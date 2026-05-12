use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use anyhow::{Context, Result};
use tokio::io;
use tokio::net::TcpStream;

use crate::config::EgressFilter;

/// Bind to a specific IPv6 source address (with IP_FREEBIND) and connect to destination.
/// `dst_addr` must be an IPv6 address; IPv4-only destinations are rejected before this call.
pub async fn bind_and_connect(src_v6: Ipv6Addr, dst_addr: SocketAddr) -> Result<TcpStream> {
    let src_sock = SocketAddrV6::new(src_v6, 0, 0, 0);

    let dst_addr = match dst_addr {
        SocketAddr::V4(_) => anyhow::bail!("IPv4-only destination rejected"),
        v6 @ SocketAddr::V6(_) => v6,
    };

    let socket = tokio::net::TcpSocket::new_v6().context("failed to create TCP socket")?;

    // Set IP_FREEBIND so we can bind to addresses not yet assigned to an interface
    set_freebind(&socket)?;

    socket
        .bind(SocketAddr::V6(src_sock))
        .with_context(|| format!("failed to bind to [{}]", src_v6))?;

    let stream = socket
        .connect(dst_addr)
        .await
        .with_context(|| format!("failed to connect to {}", dst_addr))?;

    Ok(stream)
}

fn set_freebind(socket: &tokio::net::TcpSocket) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let optval: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_FREEBIND,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        anyhow::bail!(
            "setsockopt IPV6_FREEBIND failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Bidirectional copy between two TCP streams.
pub async fn copy_bidirectional(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
) -> Result<(u64, u64)> {
    let (c2u, u2c) = io::copy_bidirectional(client, upstream)
        .await
        .context("bidirectional copy failed")?;
    Ok((c2u, u2c))
}

/// Resolve a hostname to a SocketAddr, IPv6 only, subject to the egress filter.
/// Returns an error if the host has no AAAA record, or if every resolved IPv6
/// address is blocked by the egress policy.
pub async fn resolve_dst(host: &str, port: u16, filter: &EgressFilter) -> Result<SocketAddr> {
    use tokio::net::lookup_host;

    let addrs: Vec<SocketAddr> = lookup_host(format!("{}:{}", host, port))
        .await
        .with_context(|| format!("DNS resolution failed for {}", host))?
        .collect();

    let v6_addrs: Vec<&SocketAddr> = addrs.iter().filter(|a| a.is_ipv6()).collect();
    if v6_addrs.is_empty() {
        anyhow::bail!(
            "no AAAA record for {}, IPv4-only destinations are not supported",
            host
        );
    }

    // Only accept IPv6 destinations the egress policy permits.
    if let Some(v6) = v6_addrs.iter().find(|a| filter.is_allowed(a.ip())) {
        return Ok(**v6);
    }

    anyhow::bail!(
        "all IPv6 destinations for {} are blocked by the egress policy",
        host
    )
}
