use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use super::hash;
use crate::config::V6Pool;
use crate::state::{self, POLICIES};

const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_UDP_PACKET: usize = 65535;

/// A QUIC session entry tracking the upstream socket and last activity.
struct QuicSession {
    upstream: Arc<UdpSocket>,
    dst_addr: SocketAddr,
    #[allow(dead_code)]
    src_v6: Ipv6Addr,
    last_active: Instant,
}

type SessionKey = (IpAddr, u16); // (client_ip, client_port)

#[allow(dead_code)]
pub async fn run_quic_listener(bind_addr: String, pools: Arc<Vec<V6Pool>>) -> Result<()> {
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP on {}", bind_addr))?;
    run_quic_listener_on(socket, &bind_addr, pools).await
}

/// Run the QUIC/UDP listener on a pre-bound UdpSocket.
pub async fn run_quic_listener_on(
    socket: UdpSocket,
    bind_addr: &str,
    pools: Arc<Vec<V6Pool>>,
) -> Result<()> {
    let socket = Arc::new(socket);

    info!(addr = %bind_addr, "QUIC/UDP listener started");

    let sessions: Arc<DashMap<SessionKey, QuicSession>> = Arc::new(DashMap::new());

    // Spawn cleanup task
    {
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLEANUP_INTERVAL).await;
                sessions.retain(|_k, v| v.last_active.elapsed() < SESSION_IDLE_TIMEOUT);
            }
        });
    }

    let mut buf = vec![0u8; MAX_UDP_PACKET];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let data = buf[..len].to_vec();
                let sessions = Arc::clone(&sessions);
                let socket = Arc::clone(&socket);
                let pools = Arc::clone(&pools);

                tokio::spawn(async move {
                    if let Err(e) =
                        handle_quic_packet(&socket, peer, &data, &sessions, &pools).await
                    {
                        debug!(error = %e, peer = %peer, "QUIC packet handling error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "UDP recv error");
            }
        }
    }
}

async fn handle_quic_packet(
    listener: &Arc<UdpSocket>,
    peer: SocketAddr,
    data: &[u8],
    sessions: &Arc<DashMap<SessionKey, QuicSession>>,
    pools: &[V6Pool],
) -> Result<()> {
    let key = (peer.ip(), peer.port());

    // Check if we have an existing session
    if let Some(mut session) = sessions.get_mut(&key) {
        session.last_active = Instant::now();
        // Forward to upstream
        session.upstream.send_to(data, session.dst_addr).await?;
        return Ok(());
    }

    // New connection — need to parse QUIC Initial to get SNI
    debug!(peer = %peer, "QUIC session accepted");

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

    // Extract SNI from QUIC Initial packet
    let sni = match extract_quic_sni(data) {
        Some(s) => s,
        None => {
            debug!(peer = %peer, "no SNI in QUIC Initial, dropping");
            return Ok(());
        }
    };

    // Domain ACL: drop blocked SNIs before resolving upstream.
    if !crate::acl::DOMAIN_FILTER.load().is_allowed(&sni) {
        crate::acl::note_domain_blocked();
        info!(peer = %peer, sni = %sni, "blocked by domain ACL, dropping");
        return Ok(());
    }

    // Resolve destination (subject to the egress filter)
    let dst_addr = crate::dataplane::forward::resolve_dst(&sni, 443).await?;

    // Pick outgoing v6
    let src_v6 =
        match hash::pick_outgoing(pools, &binding, peer.ip(), dst_addr.ip(), peer.port(), 443) {
            Some(v6) => v6,
            None => {
                warn!("no v6 pool available for QUIC");
                return Ok(());
            }
        };

    // Create upstream UDP socket bound to the selected v6 address. The socket is
    // intentionally left unconnected (this is a stateless datagram forwarder, and
    // a connected UDP socket would surface transient ICMP errors as fatal recv
    // errors). The reverse relay below instead drops any datagram whose source is
    // not the resolved upstream, which blocks off-path injection without tying the
    // session's fate to ICMP.
    let upstream_socket = create_v6_udp_socket(src_v6).await?;
    let upstream_socket = Arc::new(upstream_socket);

    info!(
        peer = %peer,
        dst = %dst_addr,
        src_v6 = %src_v6,
        sni = %sni,
        "forwarding new QUIC session"
    );

    // Forward the initial packet
    upstream_socket.send_to(data, dst_addr).await?;

    // Store session
    sessions.insert(
        key,
        QuicSession {
            upstream: Arc::clone(&upstream_socket),
            dst_addr,
            src_v6,
            last_active: Instant::now(),
        },
    );

    // Spawn reverse relay: upstream → client via the shared listener socket
    {
        let upstream = Arc::clone(&upstream_socket);
        let sessions_ref = sessions.clone();
        let listener = Arc::clone(listener);
        let peer = peer;
        let dst_addr = dst_addr;
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PACKET];
            loop {
                match tokio::time::timeout(SESSION_IDLE_TIMEOUT, upstream.recv_from(&mut buf)).await
                {
                    Ok(Ok((len, from))) => {
                        // Drop datagrams that did not come from the resolved
                        // upstream — blocks off-path injection into the session.
                        if from != dst_addr {
                            debug!(%from, %dst_addr, "dropping QUIC reply from unexpected source");
                            continue;
                        }
                        if let Err(e) = listener.send_to(&buf[..len], peer).await {
                            debug!(error = %e, "failed to relay upstream → client");
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(error = %e, "upstream recv error");
                        break;
                    }
                    Err(_) => {
                        sessions_ref.remove(&(peer.ip(), peer.port()));
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

/// Read a QUIC variable-length integer (RFC 9000 Section 16).
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let prefix = data[0] >> 6;
    let len = 1 << prefix;
    if data.len() < len {
        return None;
    }
    let mut val = (data[0] & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | data[i] as u64;
    }
    Some((val, len))
}

/// Extract SNI from a QUIC Initial packet.
/// Implements RFC 9001 Initial packet decryption:
/// 1. Parse long header to extract DCID
/// 2. Derive Initial keys from DCID (deterministic, no secrets needed)
/// 3. Remove header protection (AES-ECB)
/// 4. Decrypt payload (AES-128-GCM)
/// 5. Parse CRYPTO frame to find TLS ClientHello
/// 6. Extract SNI from ClientHello
fn extract_quic_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let first = data[0];

    // Long header: bit 7 set
    if first & 0x80 == 0 {
        return None;
    }

    // Packet type (bits 4-5 for QUIC v1): Initial = 0b00
    let packet_type = (first & 0x30) >> 4;
    if packet_type != 0x00 {
        return None;
    }

    // Version (4 bytes)
    if data.len() < 5 {
        return None;
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    // Determine salt based on QUIC version
    let salt = match version {
        0x00000001 => &QUIC_V1_SALT, // QUIC v1 (RFC 9001)
        0x6b3343cf => &QUIC_V2_SALT, // QUIC v2 (RFC 9369)
        _ => return None,            // Unknown version
    };

    let mut pos = 5;

    // DCID length + DCID
    if pos >= data.len() {
        return None;
    }
    let dcid_len = data[pos] as usize;
    pos += 1;
    if pos + dcid_len > data.len() {
        return None;
    }
    let dcid = &data[pos..pos + dcid_len];
    pos += dcid_len;

    // SCID length + SCID
    if pos >= data.len() {
        return None;
    }
    let scid_len = data[pos] as usize;
    pos += 1 + scid_len;

    // Token length (variable-length integer)
    if pos >= data.len() {
        return None;
    }
    let (token_len, consumed) = read_varint(&data[pos..])?;
    pos += consumed + token_len as usize;

    // Payload length (variable-length integer)
    if pos >= data.len() {
        return None;
    }
    let (payload_len, consumed) = read_varint(&data[pos..])?;
    pos += consumed;

    let payload_len = payload_len as usize;
    if pos + payload_len > data.len() {
        return None;
    }

    // Derive Initial keys from DCID
    let keys = derive_initial_keys(dcid, salt)?;

    // The packet number starts at `pos`.
    // Header protection sample is 4 bytes starting at pos + 4.
    let pn_offset = pos;
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > data.len() {
        return None;
    }
    let sample = &data[sample_offset..sample_offset + 16];

    // Compute header protection mask
    let mask = compute_hp_mask(&keys.hp, sample)?;

    // Remove header protection from first byte
    let mut header = data[..pos + payload_len].to_vec();
    header[0] ^= mask[0] & 0x0f; // Long header: lower 4 bits

    // Packet number length (lower 2 bits of first byte + 1)
    let pn_len = ((header[0] & 0x03) + 1) as usize;
    if pn_offset + pn_len > header.len() {
        return None;
    }

    // Remove header protection from packet number bytes
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
    }

    // Reconstruct packet number
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }

    // Compute nonce = IV XOR padded packet number
    let mut nonce = keys.iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[12 - 8 + i] ^= pn_bytes[i];
    }

    // AAD = the header bytes (with protection removed) up to and including packet number
    let aad = &header[..pn_offset + pn_len];

    // Ciphertext = everything after the packet number
    let ciphertext_start = pn_offset + pn_len;
    let ciphertext_end = pos + payload_len;
    if ciphertext_start >= ciphertext_end {
        return None;
    }
    let ciphertext = &data[ciphertext_start..ciphertext_end];

    // Decrypt with AES-128-GCM
    let plaintext = decrypt_payload(&keys.key, &nonce, aad, ciphertext)?;

    // Parse CRYPTO frames from decrypted payload to extract ClientHello
    let client_hello = extract_crypto_data(&plaintext)?;

    // Reuse TLS SNI parser on the ClientHello
    crate::dataplane::sni::extract_tls_sni_from_handshake(&client_hello)
}

// QUIC v1 salt (RFC 9001 Section 5.2)
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// QUIC v2 salt (RFC 9369 Section 5.2)
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

struct InitialKeys {
    key: [u8; 16], // AES-128-GCM key
    iv: [u8; 12],  // AES-128-GCM IV/nonce
    hp: [u8; 16],  // Header protection key
}

fn derive_initial_keys(dcid: &[u8], salt: &[u8; 20]) -> Option<InitialKeys> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // initial_secret = HKDF-Extract(salt, dcid)
    let hk = Hkdf::<Sha256>::new(Some(salt), dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let mut client_secret = [0u8; 32];
    let client_label = hkdf_label(b"client in", b"", 32);
    hk.expand(&client_label, &mut client_secret).ok()?;

    let client_hk = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;

    // key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
    let mut key = [0u8; 16];
    let key_label = hkdf_label(b"quic key", b"", 16);
    client_hk.expand(&key_label, &mut key).ok()?;

    // iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
    let mut iv = [0u8; 12];
    let iv_label = hkdf_label(b"quic iv", b"", 12);
    client_hk.expand(&iv_label, &mut iv).ok()?;

    // hp = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
    let mut hp = [0u8; 16];
    let hp_label = hkdf_label(b"quic hp", b"", 16);
    client_hk.expand(&hp_label, &mut hp).ok()?;

    Some(InitialKeys { key, iv, hp })
}

/// Build HKDF-Expand-Label info parameter per RFC 8446 Section 7.1:
/// struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel;
/// The label is prefixed with "tls13 ".
fn hkdf_label(label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    let full_label_len = 6 + label.len(); // "tls13 " prefix
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

/// Compute AES-ECB header protection mask from a 16-byte sample.
fn compute_hp_mask(hp_key: &[u8; 16], sample: &[u8]) -> Option<[u8; 5]> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;

    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(&sample[..16]);
    cipher.encrypt_block(&mut block);

    let mut mask = [0u8; 5];
    mask.copy_from_slice(&block[..5]);
    Some(mask)
}

/// Decrypt AES-128-GCM payload.
fn decrypt_payload(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(nonce);

    // Construct payload with AAD
    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher.decrypt(nonce, payload).ok()
}

/// Extract CRYPTO frame data from a decrypted QUIC Initial payload.
/// CRYPTO frame type = 0x06, followed by offset (varint), length (varint), data.
fn extract_crypto_data(payload: &[u8]) -> Option<Vec<u8>> {
    let mut crypto_data = Vec::new();
    let mut pos = 0;

    while pos < payload.len() {
        let frame_type = payload[pos];
        pos += 1;

        match frame_type {
            0x00 => {
                // PADDING frame — skip
                continue;
            }
            0x01 => {
                // PING frame — skip
                continue;
            }
            0x06 => {
                // CRYPTO frame
                if pos >= payload.len() {
                    break;
                }
                let (_offset, consumed) = read_varint(&payload[pos..])?;
                pos += consumed;
                if pos >= payload.len() {
                    break;
                }
                let (length, consumed) = read_varint(&payload[pos..])?;
                pos += consumed;
                let length = length as usize;
                if pos + length > payload.len() {
                    break;
                }
                crypto_data.extend_from_slice(&payload[pos..pos + length]);
                pos += length;
            }
            0x02 | 0x03 => {
                // ACK frame — has complex structure, skip rest
                break;
            }
            _ => {
                // Unknown frame type — stop parsing
                break;
            }
        }
    }

    if crypto_data.is_empty() {
        None
    } else {
        Some(crypto_data)
    }
}

async fn create_v6_udp_socket(src_v6: Ipv6Addr) -> Result<UdpSocket> {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        anyhow::bail!(
            "failed to create UDP socket: {}",
            std::io::Error::last_os_error()
        );
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_udp_freebind(owned_fd.as_raw_fd())?;

    let src = SocketAddrV6::new(src_v6, 0, 0, 0);
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: src.port().to_be(),
        sin6_flowinfo: src.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: src.ip().octets(),
        },
        sin6_scope_id: src.scope_id(),
    };

    let ret = unsafe {
        libc::bind(
            owned_fd.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        anyhow::bail!(
            "failed to bind UDP to [{}]: {}",
            src_v6,
            std::io::Error::last_os_error()
        );
    }

    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(owned_fd.into_raw_fd()) };
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket).context("failed to convert to tokio UdpSocket")
}

fn set_udp_freebind(fd: std::os::fd::RawFd) -> Result<()> {
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
            "setsockopt IPV6_FREEBIND failed for UDP socket: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint_1byte() {
        assert_eq!(read_varint(&[0x25]), Some((37, 1)));
    }

    #[test]
    fn test_read_varint_2byte() {
        assert_eq!(read_varint(&[0x7b, 0xbd]), Some((15293, 2)));
    }

    #[test]
    fn test_read_varint_empty() {
        assert_eq!(read_varint(&[]), None);
    }
}
