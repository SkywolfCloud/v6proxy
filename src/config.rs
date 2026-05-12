use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use crate::state::HashPolicy;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub admin: AdminConfig,
    pub data: DataConfig,
    pub paths: PathsConfig,
    pub machine: MachineConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub egress: EgressConfig,
}

/// Egress destination filtering. An address is permitted when it is explicitly
/// allow-listed (an `allow` entry overrides everything), otherwise it is rejected
/// if it falls in `deny` or in the built-in special-use ranges; when `allow` is
/// non-empty the filter operates in whitelist mode and anything not allow-listed
/// is rejected.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct EgressConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MachineConfig {
    pub v6_pools: Vec<String>,
    // TODO: Add explicit SNI routing rules once the dataplane enforces them.
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    pub bind: String,
    pub token_hash: String,
    pub allowlist: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DataConfig {
    pub tcp_binds: Vec<String>,
    pub udp_binds: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathsConfig {
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    #[serde(default = "default_hash_policy")]
    pub default: HashPolicy,
    #[serde(default, with = "crate::state::hex_seed")]
    pub default_seed: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: default_hash_policy(),
            default_seed: 0,
        }
    }
}

fn default_hash_policy() -> HashPolicy {
    HashPolicy::SrcIp
}

#[derive(Debug, Clone)]
pub struct V6Pool {
    pub prefix: u128,
    pub prefix_len: u8,
}

impl V6Pool {
    pub fn parse(s: &str) -> Result<Self> {
        // Parse CIDR like "2001:db8:a::/64"
        let parts: Vec<&str> = s.split('/').collect();
        anyhow::ensure!(parts.len() == 2, "invalid v6 pool format: {}", s);
        let addr: Ipv6Addr = parts[0].parse().context("invalid IPv6 address")?;
        let prefix_len: u8 = parts[1].parse().context("invalid prefix length")?;
        anyhow::ensure!(prefix_len <= 128, "prefix length too large");
        let prefix = u128::from(addr);
        // Zero out host bits
        let mask = if prefix_len == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix_len)
        };
        let prefix = prefix & mask;
        Ok(V6Pool { prefix, prefix_len })
    }

    /// Map a hash value into this pool's address space.
    /// For a /64, the low 64 bits come from the hash.
    /// For a /48, the low 80 bits come from the hash (but we only have 64 bits of hash,
    /// so we fill the remaining bits deterministically).
    pub fn host_at(&self, hash: u64) -> Ipv6Addr {
        let host_bits = 128 - self.prefix_len as u32;
        let host_mask = if host_bits >= 128 {
            !0u128
        } else {
            (1u128 << host_bits) - 1
        };
        // Use the hash value as host part, extending if needed
        let host = (hash as u128) & host_mask;
        // Avoid all-zeros and all-ones host (reserved addresses)
        let host = if host == 0 {
            1
        } else if host == host_mask {
            host_mask - 1
        } else {
            host
        };
        Ipv6Addr::from(self.prefix | host)
    }
}

#[derive(Debug, Clone)]
pub struct ParsedTokensConfig {
    pub admin_token_hash: String,
    pub admin_allowlist: Vec<IpNet>,
}

/// Parse a list of "ip" or "cidr" strings into networks (a bare IP becomes a
/// host route). Shared by the admin allowlist and the egress filter.
fn parse_net_list(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| {
            if entry.contains('/') {
                entry
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid CIDR: {}", entry))
            } else {
                let ip: IpAddr = entry
                    .parse()
                    .with_context(|| format!("invalid IP: {}", entry))?;
                Ok(IpNet::from(ip))
            }
        })
        .collect()
}

impl AdminConfig {
    pub fn parse_allowlist(&self) -> Result<ParsedTokensConfig> {
        Ok(ParsedTokensConfig {
            admin_token_hash: self.token_hash.clone(),
            admin_allowlist: parse_net_list(&self.allowlist)?,
        })
    }
}

/// Special-use IPv6 ranges that are always denied unless an explicit `allow`
/// entry overrides them. Keeps a customer from steering the proxy at the host's
/// own loopback/link-local/internal services via SNI/Host.
fn builtin_blocked_nets() -> Vec<IpNet> {
    [
        "::1/128",       // loopback
        "::/128",        // unspecified
        "::/96",         // deprecated IPv4-compatible (embeds an IPv4 address)
        "fe80::/10",     // link-local
        "fc00::/7",      // unique local (ULA)
        "ff00::/8",      // multicast
        "::ffff:0:0/96", // IPv4-mapped
        "64:ff9b::/96",  // NAT64 (embeds an IPv4 address)
        "2002::/16",     // 6to4 (embeds an IPv4 address)
        "2001:db8::/32", // documentation
    ]
    .iter()
    .map(|s| s.parse().expect("valid builtin CIDR"))
    .collect()
}

/// Resolved egress destination filter.
#[derive(Debug, Clone)]
pub struct EgressFilter {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl EgressFilter {
    /// Returns true if the proxy may connect outbound to `ip`.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // An explicit allow entry overrides every deny rule.
        if self.allow.iter().any(|n| n.contains(&ip)) {
            return true;
        }
        if self.deny.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        // Whitelist mode: with a non-empty allow list, anything not matched above
        // is rejected. With an empty allow list, default-allow.
        self.allow.is_empty()
    }
}

impl EgressConfig {
    pub fn build_filter(&self) -> Result<EgressFilter> {
        let allow = parse_net_list(&self.allow).context("invalid egress allow entry")?;
        let mut deny = parse_net_list(&self.deny).context("invalid egress deny entry")?;
        deny.extend(builtin_blocked_nets());
        Ok(EgressFilter { allow, deny })
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn parse_pools(&self) -> Result<Vec<V6Pool>> {
        self.machine
            .v6_pools
            .iter()
            .map(|s| V6Pool::parse(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(extra: &str) -> String {
        format!(
            r#"
[admin]
bind = "127.0.0.1:8787"
token_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$placeholder"
allowlist = ["127.0.0.1"]

[data]
tcp_binds = ["127.0.0.1:8080"]
udp_binds = ["127.0.0.1:8443"]

[paths]
state = "/tmp/v6proxy-policies.json"

[machine]
v6_pools = ["2001:db8:a::/64"]
{extra}
"#
        )
    }

    #[test]
    fn default_policy_is_src_ip_when_omitted() {
        let config: Config = toml::from_str(&minimal_config("")).unwrap();
        assert_eq!(config.policy.default, HashPolicy::SrcIp);
    }

    #[test]
    fn default_policy_can_be_configured() {
        let config: Config = toml::from_str(&minimal_config(
            r#"
[policy]
default = "five_tuple"
"#,
        ))
        .unwrap();
        assert_eq!(config.policy.default, HashPolicy::FiveTuple);
    }

    #[test]
    fn default_seed_is_zero_when_omitted() {
        let config: Config = toml::from_str(&minimal_config("")).unwrap();
        assert_eq!(config.policy.default_seed, 0);
    }

    #[test]
    fn default_seed_can_be_configured_as_integer() {
        let config: Config = toml::from_str(&minimal_config(
            r#"
[policy]
default_seed = 42
"#,
        ))
        .unwrap();
        assert_eq!(config.policy.default_seed, 42);
    }

    #[test]
    fn default_seed_can_be_configured_as_hex_string() {
        let config: Config = toml::from_str(&minimal_config(
            r#"
[policy]
default_seed = "0x2a"
"#,
        ))
        .unwrap();
        assert_eq!(config.policy.default_seed, 42);
    }

    #[test]
    fn egress_blocks_internal_ranges_by_default() {
        let filter = EgressConfig::default().build_filter().unwrap();
        // Public IPv6 is allowed.
        assert!(filter.is_allowed("2606:4700:4700::1111".parse().unwrap()));
        // Internal/special-use ranges are denied by default.
        assert!(!filter.is_allowed("::1".parse().unwrap()));
        assert!(!filter.is_allowed("fe80::1".parse().unwrap()));
        assert!(!filter.is_allowed("fd00::1".parse().unwrap()));
        assert!(!filter.is_allowed("ff02::1".parse().unwrap()));
        // IPv4-mapped, 6to4 and IPv4-compatible encodings of internal IPv4
        // addresses must also be denied (they would otherwise smuggle an
        // internal IPv4 destination past the filter).
        assert!(!filter.is_allowed("::ffff:127.0.0.1".parse().unwrap())); // IPv4-mapped loopback
        assert!(!filter.is_allowed("2002:7f00:1::1".parse().unwrap())); // 6to4 of 127.0.0.1
        assert!(!filter.is_allowed("2002:a9fe:101::1".parse().unwrap())); // 6to4 of 169.254.1.1
        assert!(!filter.is_allowed("::127.0.0.1".parse().unwrap())); // IPv4-compatible loopback
    }

    #[test]
    fn egress_deny_list_adds_ranges() {
        let cfg = EgressConfig {
            allow: vec![],
            deny: vec!["2001:4860:4860::/48".to_string()],
        };
        let filter = cfg.build_filter().unwrap();
        assert!(!filter.is_allowed("2001:4860:4860::8888".parse().unwrap()));
        assert!(filter.is_allowed("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn egress_allow_list_is_whitelist_and_overrides_deny() {
        let cfg = EgressConfig {
            // Allow a ULA range that is otherwise blocked by the built-in deny.
            allow: vec!["fd12:3456::/32".to_string()],
            deny: vec![],
        };
        let filter = cfg.build_filter().unwrap();
        // Explicit allow overrides the built-in fc00::/7 deny.
        assert!(filter.is_allowed("fd12:3456::1".parse().unwrap()));
        // Whitelist mode: a public address not in `allow` is rejected.
        assert!(!filter.is_allowed("2606:4700:4700::1111".parse().unwrap()));
    }
}
