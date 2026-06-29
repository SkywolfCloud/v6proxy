use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn, Instrument};

use super::forward;
use super::hash;
use super::sni;
use crate::config::V6Pool;
use crate::state::{self, POLICIES};

#[allow(dead_code)]
pub async fn run_tcp_listener(bind_addr: String, pools: Arc<Vec<V6Pool>>) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind TCP on {}", bind_addr))?;
    run_tcp_listener_on(listener, &bind_addr, pools).await
}

/// Run the TCP listener accept loop on a pre-bound TcpListener.
pub async fn run_tcp_listener_on(
    listener: TcpListener,
    bind_addr: &str,
    pools: Arc<Vec<V6Pool>>,
) -> Result<()> {
    let local_addr = listener.local_addr()?;
    let local_port = local_addr.port();
    info!(addr = %bind_addr, "TCP listener started");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let pools = Arc::clone(&pools);
                let span = tracing::info_span!("tcp_conn", peer = %peer, port = local_port);
                tokio::spawn(
                    async move {
                        debug!(peer = %peer, port = local_port, "TCP connection accepted");
                        if let Err(e) = handle_tcp(stream, peer, local_port, &pools).await {
                            debug!(error = %e, "connection error");
                        }
                    }
                    .instrument(span),
                );
            }
            Err(e) => {
                error!(error = %e, "accept error");
            }
        }
    }
}

async fn handle_tcp(
    mut client: TcpStream,
    peer: SocketAddr,
    local_port: u16,
    pools: &[V6Pool],
) -> Result<()> {
    // 1. Look up binding by srcip
    let policies = POLICIES.load();
    let binding = match policies.bindings.get(&peer.ip()) {
        Some(b) => b.clone(),
        None => {
            debug!(
                peer = %peer,
                policy = %state::default_hash_policy(),
                seed = state::default_binding_seed(),
                "no binding for peer, using default binding"
            );
            state::default_binding()
        }
    };

    // 2. Peek SNI/Host
    let (_peeked, hostname) = sni::peek_sni_or_host(&client, local_port).await?;

    let dst_host = match hostname {
        Some(h) => h,
        None => {
            warn!(peer = %peer, "no SNI/Host found, dropping");
            return Ok(());
        }
    };

    // 2b. Domain ACL: drop before any DNS resolution if the host is blocked.
    if !crate::acl::DOMAIN_FILTER.load().is_allowed(&dst_host) {
        crate::acl::note_domain_blocked();
        info!(peer = %peer, sni = %dst_host, "blocked by domain ACL, dropping");
        return Ok(());
    }

    // 3. Resolve destination (subject to the egress filter)
    let dst_port = local_port;
    let dst_addr = forward::resolve_dst(&dst_host, dst_port).await?;

    // 4. Compute outgoing v6 address
    let src_v6 = match hash::pick_outgoing(
        pools,
        &binding,
        peer.ip(),
        dst_addr.ip(),
        peer.port(),
        dst_port,
    ) {
        Some(v6) => v6,
        None => {
            warn!("no v6 pool available");
            return Ok(());
        }
    };

    info!(
        peer = %peer,
        dst = %dst_addr,
        src_v6 = %src_v6,
        sni = %dst_host,
        "forwarding connection"
    );

    // 5. Connect upstream via the selected v6 source
    let mut upstream = forward::bind_and_connect(src_v6, dst_addr).await?;

    // 6. Bidirectional copy (peek data is still in the socket buffer, not consumed)
    let (c2u, u2c) = forward::copy_bidirectional(&mut client, &mut upstream).await?;

    debug!(c2u, u2c, "connection closed");
    Ok(())
}
