mod api;
mod config;
mod dataplane;
mod state;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

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

    /// Log output format.
    #[arg(long, global = true, value_enum, default_value = "text")]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
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

    init_logging(cli.log_format);

    if let Some(Command::Init { force }) = cli.command {
        init_config(&cli.config, force)?;
        info!(config = %cli.config.display(), "config initialized");
        return Ok(());
    }

    if cli.check_config {
        check_config(&cli.config)?;
        info!(config = %cli.config.display(), "config ok");
        return Ok(());
    }

    info!(config = %cli.config.display(), "starting v6proxy");

    let loaded = load_and_validate_config(&cli.config)?;
    let config = loaded.config;
    let pools = Arc::new(loaded.pools);
    let egress = Arc::new(loaded.egress);
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
        let egress = Arc::clone(&egress);
        tokio::spawn(async move {
            if let Err(e) = dataplane::tcp::run_tcp_listener_on(listener, &addr, pools, egress).await
            {
                error!(addr = %addr, error = %e, "TCP listener failed");
            }
        });
    }

    for (addr, socket) in udp_sockets {
        let pools = Arc::clone(&pools);
        let egress = Arc::clone(&egress);
        tokio::spawn(async move {
            if let Err(e) =
                dataplane::quic::run_quic_listener_on(socket, &addr, pools, egress).await
            {
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

fn init_logging(log_format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match log_format {
        LogFormat::Text => fmt().with_env_filter(filter).init(),
        LogFormat::Json => fmt().with_env_filter(filter).json().init(),
    }
}

struct LoadedConfig {
    config: config::Config,
    pools: Vec<config::V6Pool>,
    egress: config::EgressFilter,
    tokens: config::ParsedTokensConfig,
    admin_bind: SocketAddr,
}

fn check_config(config_path: &Path) -> Result<()> {
    load_and_validate_config(config_path).map(|_| ())
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

fn load_and_validate_config(config_path: &Path) -> Result<LoadedConfig> {
    // Phase 1: Load config
    let config = config::Config::load(config_path).context("failed to load config")?;

    // Phase 2: Parse IPv6 pools
    let pools = config.parse_pools().context("failed to parse v6 pools")?;
    anyhow::ensure!(!pools.is_empty(), "machine.v6_pools must not be empty");
    info!(pools = pools.len(), "loaded v6 pools");

    // Parse egress destination filter (allow/deny + built-in special-use ranges)
    let egress = config
        .egress
        .build_filter()
        .context("failed to parse egress filter")?;

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
        egress,
        tokens,
        admin_bind,
    })
}
