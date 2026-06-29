mod acl;
mod api;
mod config;
mod dataplane;
mod state;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use config::{LogConfig, LogFormat};

const DEFAULT_CONFIG: &str = include_str!("../deploy/examples/config.toml");

#[derive(Debug, Parser)]
#[command(author, version, about = "Random IPv6 exit proxy")]
struct Cli {
    /// Path to the v6proxy TOML config file.
    #[arg(short, long, global = true, default_value = "/etc/v6proxy/config.toml")]
    config: PathBuf,

    /// Validate the config file and exit without binding listeners.
    #[arg(long)]
    check_config: bool,

    /// Log output format (overrides `[log].format` in the config).
    #[arg(long, global = true, value_enum)]
    log_format: Option<LogFormat>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a starter config file.
    Init {
        /// Overwrite the config file if it already exists.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // The `init` subcommand creates a config, so there is none to read logging
    // settings from yet — use defaults (still honoring --log-format / RUST_LOG).
    if let Some(Command::Init { force }) = cli.command {
        init_logging(cli.log_format, &LogConfig::default());
        init_config(&cli.config, force)?;
        info!(config = %cli.config.display(), "config initialized");
        return Ok(());
    }

    // Load the config first so logging can honor its [log] section, then bring
    // logging up before the validation phase so its logs are captured.
    let config = config::Config::load(&cli.config).context("failed to load config")?;
    init_logging(cli.log_format, &config.log);

    if cli.check_config {
        validate_config(config)?;
        info!(config = %cli.config.display(), "config ok");
        return Ok(());
    }

    info!(config = %cli.config.display(), "starting v6proxy");

    let loaded = validate_config(config)?;
    let config = loaded.config;
    let pools = Arc::new(loaded.pools);
    let tokens = loaded.tokens;
    state::init_default_binding(config.policy.default, config.policy.default_seed);

    // Phase 4: Load or initialize policies state
    let state_path = PathBuf::from(&config.paths.state);
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state directory: {}", parent.display()))?;
    }
    let policies =
        state::load_policies(&state_path).context("failed to load policies (file corrupt?)")?;
    info!(
        version = policies.version,
        bindings = policies.bindings.len(),
        "loaded policies"
    );

    state::init_state_path(state_path);
    state::POLICIES.store(Arc::new(policies));

    // Build the domain ACL from the [domain] base + persisted overlay, ready
    // for the data plane to read.
    acl::init_domain_filter(config.domain.allow.clone(), config.domain.deny.clone());
    acl::init_egress_filter(config.egress.allow.clone(), config.egress.deny.clone());

    // Phase 5: Bind all listeners BEFORE spawning serve loops.
    // This ensures bind errors fail startup immediately.

    let admin_bind = loaded.admin_bind;
    let admin_router = api::router(tokens);
    let admin_listener = tokio::net::TcpListener::bind(admin_bind)
        .await
        .with_context(|| format!("failed to bind admin API on {}", admin_bind))?;
    info!(addr = %admin_bind, "admin API bound");

    let mut tcp_listeners = Vec::new();
    for bind_addr in &config.data.tcp_binds {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind TCP on {}", bind_addr))?;
        info!(addr = %bind_addr, "TCP listener bound");
        tcp_listeners.push((bind_addr.clone(), listener));
    }

    let mut udp_sockets = Vec::new();
    for bind_addr in &config.data.udp_binds {
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind UDP on {}", bind_addr))?;
        info!(addr = %bind_addr, "UDP listener bound");
        udp_sockets.push((bind_addr.clone(), socket));
    }

    // Phase 6: All binds succeeded — now spawn serve loops.

    let admin_handle = tokio::spawn(async move {
        info!(addr = %admin_bind, "starting admin API");
        if let Err(e) = axum::serve(
            admin_listener,
            admin_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            error!(error = %e, "admin API exited with error");
        }
    });

    for (addr, listener) in tcp_listeners {
        let pools = Arc::clone(&pools);
        tokio::spawn(async move {
            if let Err(e) = dataplane::tcp::run_tcp_listener_on(listener, &addr, pools).await {
                error!(addr = %addr, error = %e, "TCP listener failed");
            }
        });
    }

    for (addr, socket) in udp_sockets {
        let pools = Arc::clone(&pools);
        tokio::spawn(async move {
            if let Err(e) = dataplane::quic::run_quic_listener_on(socket, &addr, pools).await {
                error!(addr = %addr, error = %e, "QUIC listener failed");
            }
        });
    }

    info!("v6proxy started successfully — all listeners active");

    // Wait for admin to exit or SIGINT
    tokio::select! {
        r = admin_handle => {
            error!("admin API exited unexpectedly: {:?}", r);
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
    }

    Ok(())
}

fn init_logging(cli_format: Option<LogFormat>, log: &LogConfig) {
    // RUST_LOG (if set) wins over the configured level; otherwise use [log].level.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log.level.as_str()));
    // --log-format (if passed) wins over the configured format.
    let format = cli_format.unwrap_or(log.format);
    match format {
        LogFormat::Text => fmt().with_env_filter(filter).init(),
        LogFormat::Json => fmt().with_env_filter(filter).json().init(),
    }
}

struct LoadedConfig {
    config: config::Config,
    pools: Vec<config::V6Pool>,
    tokens: config::ParsedTokensConfig,
    admin_bind: SocketAddr,
}

fn init_config(config_path: &Path, force: bool) -> Result<()> {
    if config_path.exists() && !force {
        anyhow::bail!(
            "config already exists: {} (use --force to overwrite)",
            config_path.display()
        );
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory: {}", parent.display()))?;
    }

    std::fs::write(config_path, DEFAULT_CONFIG)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    Ok(())
}

fn validate_config(config: config::Config) -> Result<LoadedConfig> {
    // Parse IPv6 pools
    let pools = config.parse_pools().context("failed to parse v6 pools")?;
    anyhow::ensure!(!pools.is_empty(), "machine.v6_pools must not be empty");
    info!(pools = pools.len(), "loaded v6 pools");

    // Validate the [egress] base now so bad CIDRs fail --check-config / startup;
    // the live filter is built later from base + persisted overlay.
    config
        .egress
        .build_filter()
        .context("failed to parse egress filter")?;

    // Validate the [domain] base rules so bad rules fail --check-config / startup.
    config
        .domain
        .validate()
        .context("failed to parse [domain] rules")?;

    // Phase 3: Parse admin auth config
    let tokens = config
        .admin
        .parse_allowlist()
        .context("failed to parse admin allowlist")?;
    info!(
        allowlist_entries = tokens.admin_allowlist.len(),
        "loaded admin tokens"
    );

    let admin_bind: SocketAddr = config
        .admin
        .bind
        .parse()
        .context("invalid admin bind address")?;

    for bind_addr in &config.data.tcp_binds {
        bind_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid TCP bind address: {}", bind_addr))?;
    }

    for bind_addr in &config.data.udp_binds {
        bind_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid UDP bind address: {}", bind_addr))?;
    }

    Ok(LoadedConfig {
        config,
        pools,
        tokens,
        admin_bind,
    })
}
