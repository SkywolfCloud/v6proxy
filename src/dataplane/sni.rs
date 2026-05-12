use anyhow::{Context, Result};
use std::time::Duration;
use tokio::net::TcpStream;

const PEEK_BUF_SIZE: usize = 16384;
const PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Peek at the beginning of a TCP stream to extract SNI (TLS) or Host (HTTP).
/// Returns the peeked bytes and the extracted hostname (if any).
pub async fn peek_sni_or_host(
    stream: &TcpStream,
    local_port: u16,
) -> Result<(Vec<u8>, Option<String>)> {
    let mut buf = vec![0u8; PEEK_BUF_SIZE];

    let n = tokio::time::timeout(PEEK_TIMEOUT, stream.peek(&mut buf))
        .await
        .context("peek timeout")?
        .context("peek failed")?;

    let data = &buf[..n];

    if local_port == 443 {
        // Try TLS ClientHello SNI extraction
        let sni = extract_tls_sni(data);
        Ok((data.to_vec(), sni))
    } else {
        // Try HTTP Host header extraction
        let host = extract_http_host(data);
        Ok((data.to_vec(), host))
    }
}

/// Extract SNI from TLS ClientHello.
/// Minimal parser — just enough to find the SNI extension.
fn extract_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if data.len() < 5 {
        return None;
    }
    // Content type 22 = Handshake
    if data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let handshake = &data[5..std::cmp::min(5 + record_len, data.len())];

    extract_tls_sni_from_handshake(handshake)
}

/// Extract SNI from a TLS Handshake message (without the TLS record header).
/// Used both for direct TLS and for QUIC CRYPTO frame data.
pub fn extract_tls_sni_from_handshake(handshake: &[u8]) -> Option<String> {
    // Handshake type 1 = ClientHello
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }
    if handshake.len() < 4 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    let ch = &handshake[4..std::cmp::min(4 + hs_len, handshake.len())];

    // ClientHello: version(2) + random(32) + session_id_len(1) + session_id + ...
    if ch.len() < 34 {
        return None;
    }
    let mut pos = 34; // skip version + random

    // Session ID
    if pos >= ch.len() {
        return None;
    }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;

    // Cipher suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods
    if pos >= ch.len() {
        return None;
    }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    // Extensions
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = std::cmp::min(pos + ext_len, ch.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(&ch[pos..std::cmp::min(pos + ext_data_len, ext_end)]);
        }
        pos += ext_data_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = std::cmp::min(2 + list_len, data.len());

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0 && pos + name_len <= end {
            return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
        }
        pos += name_len;
    }
    None
}

/// Extract Host header from HTTP/1.x request.
fn extract_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let host = strip_host_port(value.trim());
            return Some(host.to_string());
        }
    }
    None
}

/// Strip an optional `:port` suffix from a Host header value without mangling
/// IPv6 literals. `[2001:db8::1]:8080` and `[2001:db8::1]` both yield the
/// bracketed address contents; `example.com:80` yields `example.com`; a bare
/// (unbracketed) IPv6 literal is left untouched since it carries no port.
fn strip_host_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal in brackets: return what is inside the brackets.
        return match rest.find(']') {
            Some(end) => &rest[..end],
            None => host,
        };
    }

    // Only strip a port when there is exactly one colon; more than one colon
    // means a bare IPv6 literal (no port), which must be preserved as-is.
    match host.rfind(':') {
        Some(idx) if host.matches(':').count() == 1 => &host[..idx],
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_http_host() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_http_host_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_http_host_ipv6_literal_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\nConnection: close\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_http_host_ipv6_literal_no_port() {
        let data = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\nConnection: close\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_http_host_bare_ipv6_no_port_preserved() {
        let data = b"GET / HTTP/1.1\r\nHost: 2001:db8::1\r\nConnection: close\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_tls_sni_no_data() {
        assert_eq!(extract_tls_sni(&[]), None);
    }

    #[test]
    fn test_extract_tls_sni_not_tls() {
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1"), None);
    }
}
