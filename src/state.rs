use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

pub static POLICIES: Lazy<ArcSwap<Policies>> =
    Lazy::new(|| ArcSwap::from_pointee(Policies::default()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashPolicy {
    SrcIp,
    SrcDst,
    FiveTuple,
}

impl std::fmt::Display for HashPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashPolicy::SrcIp => write!(f, "src_ip"),
            HashPolicy::SrcDst => write!(f, "src_dst"),
            HashPolicy::FiveTuple => write!(f, "five_tuple"),
        }
    }
}

impl std::str::FromStr for HashPolicy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "src_ip" => Ok(HashPolicy::SrcIp),
            "src_dst" => Ok(HashPolicy::SrcDst),
            "five_tuple" => Ok(HashPolicy::FiveTuple),
            _ => anyhow::bail!("invalid hash policy: {}", s),
        }
    }
}

/// Parse a seed value the same way everywhere: a `0x`-prefixed string is hex,
/// otherwise it is decimal. Shared by the config deserializer and the API.
pub fn parse_seed(value: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    }
}

pub(crate) mod hex_seed {
    use std::fmt;

    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:016x}", value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SeedVisitor;

        impl<'de> serde::de::Visitor<'de> for SeedVisitor {
            type Value = u64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a u64 seed as an integer, decimal string, or 0x-prefixed hex string",
                )
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u64::try_from(value).map_err(E::custom)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                super::parse_seed(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(SeedVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub policy: HashPolicy,
    #[serde(with = "hex_seed")]
    pub seed: u64,
    pub updated_at: DateTime<Utc>,
}

/// Use string keys for IpAddr in JSON since JSON keys must be strings.
mod ip_map {
    use super::Binding;
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::collections::HashMap;
    use std::net::IpAddr;

    pub fn serialize<S>(map: &HashMap<IpAddr, Binding>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(&k.to_string(), v)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<IpAddr, Binding>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map: HashMap<String, Binding> = HashMap::deserialize(deserializer)?;
        let mut map = HashMap::new();
        for (k, v) in string_map {
            let ip: IpAddr = k.parse().map_err(serde::de::Error::custom)?;
            map.insert(ip, v);
        }
        Ok(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policies {
    pub version: u64,
    pub updated_at: DateTime<Utc>,
    #[serde(with = "ip_map")]
    pub bindings: HashMap<IpAddr, Binding>,
    /// Runtime overlay for the domain (SNI/Host) ACL, over the `[domain]` base.
    #[serde(default)]
    pub domain_acl: AclDelta,
    /// Runtime overlay for the IP egress ACL, over the `[egress]` base.
    #[serde(default)]
    pub egress_acl: AclDelta,
}

impl Default for Policies {
    fn default() -> Self {
        Policies {
            version: 0,
            updated_at: Utc::now(),
            bindings: HashMap::new(),
            domain_acl: AclDelta::default(),
            egress_acl: AclDelta::default(),
        }
    }
}

pub fn load_policies(path: &Path) -> Result<Policies> {
    if !path.exists() {
        return Ok(Policies::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse policies from {}", path.display()))
}

pub fn save_policies(path: &Path, policies: &Policies) -> Result<()> {
    let tmp_path = path.with_extension("json.tmp");

    let content = serde_json::to_string_pretty(policies).context("failed to serialize policies")?;

    // Write to temp file
    std::fs::write(&tmp_path, content.as_bytes())
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;

    // fsync the temp file
    let f = std::fs::File::open(&tmp_path)
        .with_context(|| format!("failed to open {} for fsync", tmp_path.display()))?;
    f.sync_all()
        .with_context(|| format!("failed to fsync {}", tmp_path.display()))?;

    // Atomic rename
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    // fsync parent directory
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// State file path, set once during startup.
static STATE_PATH: once_cell::sync::OnceCell<PathBuf> = once_cell::sync::OnceCell::new();

static DEFAULT_HASH_POLICY: once_cell::sync::OnceCell<HashPolicy> =
    once_cell::sync::OnceCell::new();
static DEFAULT_BINDING_SEED: once_cell::sync::OnceCell<u64> = once_cell::sync::OnceCell::new();

pub fn init_state_path(path: PathBuf) {
    STATE_PATH.set(path).expect("state path already set");
}

pub fn state_path() -> &'static Path {
    STATE_PATH.get().expect("state path not initialized")
}

pub fn init_default_binding(policy: HashPolicy, seed: u64) {
    DEFAULT_HASH_POLICY
        .set(policy)
        .expect("default hash policy already set");
    DEFAULT_BINDING_SEED
        .set(seed)
        .expect("default binding seed already set");
}

pub fn default_hash_policy() -> HashPolicy {
    *DEFAULT_HASH_POLICY.get_or_init(|| HashPolicy::SrcIp)
}

pub fn default_binding_seed() -> u64 {
    *DEFAULT_BINDING_SEED.get_or_init(|| 0)
}

pub fn default_binding() -> Binding {
    Binding {
        policy: default_hash_policy(),
        seed: default_binding_seed(),
        updated_at: Utc::now(),
    }
}

/// Apply a mutation to the current policies, save to disk, and update ArcSwap.
/// The mutator receives a mutable reference to a cloned Policies.
/// Returns the new Policies after mutation.
pub fn apply_and_save<F>(mutator: F) -> Result<Arc<Policies>>
where
    F: FnOnce(&mut Policies),
{
    // Use a global lock to serialize writes
    use parking_lot::Mutex;
    static WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
    let _guard = WRITE_LOCK.lock();

    let current = POLICIES.load();
    let mut new_policies = (**current).clone();
    mutator(&mut new_policies);
    new_policies.version += 1;
    new_policies.updated_at = Utc::now();

    save_policies(state_path(), &new_policies)?;

    let new_arc = Arc::new(new_policies);
    POLICIES.store(Arc::clone(&new_arc));
    Ok(new_arc)
}

/// Runtime overlay over a config base list, persisted in `policies.json`.
///
/// The effective list is `(base ∪ *_add) − *_del`. Storing additions and
/// deletions separately lets the admin API both add new rules and suppress
/// rules that came from the (read-only) config base, without ever rewriting
/// `config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclDelta {
    #[serde(default)]
    pub allow_add: Vec<String>,
    #[serde(default)]
    pub allow_del: Vec<String>,
    #[serde(default)]
    pub deny_add: Vec<String>,
    #[serde(default)]
    pub deny_del: Vec<String>,
}

/// Effective list = `(base ∪ add) − del`, deduped, base entries first.
fn merge_acl(base: &[String], add: &[String], del: &[String]) -> Vec<String> {
    let del_set: std::collections::HashSet<&str> = del.iter().map(String::as_str).collect();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for s in base.iter().chain(add.iter()) {
        if del_set.contains(s.as_str()) {
            continue;
        }
        if seen.insert(s.as_str()) {
            out.push(s.clone());
        }
    }
    out
}

/// Add `rule`: cancel any prior suppression; record in `add` only if it is not
/// already part of the config base.
fn apply_add(base: &[String], add: &mut Vec<String>, del: &mut Vec<String>, rule: &str) {
    del.retain(|r| r != rule);
    let in_base = base.iter().any(|b| b == rule);
    let in_add = add.iter().any(|a| a == rule);
    if !in_base && !in_add {
        add.push(rule.to_string());
    }
}

/// Remove `rule`: drop it from `add`; if it came from the config base, record a
/// suppression in `del`.
fn apply_del(base: &[String], add: &mut Vec<String>, del: &mut Vec<String>, rule: &str) {
    add.retain(|r| r != rule);
    let in_base = base.iter().any(|b| b == rule);
    let in_del = del.iter().any(|d| d == rule);
    if in_base && !in_del {
        del.push(rule.to_string());
    }
}

impl AclDelta {
    /// Effective allow list = `(base ∪ allow_add) − allow_del`.
    pub fn effective_allow(&self, base: &[String]) -> Vec<String> {
        merge_acl(base, &self.allow_add, &self.allow_del)
    }

    /// Effective deny list = `(base ∪ deny_add) − deny_del`.
    pub fn effective_deny(&self, base: &[String]) -> Vec<String> {
        merge_acl(base, &self.deny_add, &self.deny_del)
    }

    pub fn add_allow(&mut self, base: &[String], rule: &str) {
        apply_add(base, &mut self.allow_add, &mut self.allow_del, rule);
    }

    pub fn del_allow(&mut self, base: &[String], rule: &str) {
        apply_del(base, &mut self.allow_add, &mut self.allow_del, rule);
    }

    pub fn add_deny(&mut self, base: &[String], rule: &str) {
        apply_add(base, &mut self.deny_add, &mut self.deny_del, rule);
    }

    pub fn del_deny(&mut self, base: &[String], rule: &str) {
        apply_del(base, &mut self.deny_add, &mut self.deny_del, rule);
    }
}

#[cfg(test)]
mod acl_delta_tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn effective_is_base_union_add_minus_del() {
        let d = AclDelta {
            allow_add: v(&["b"]),
            allow_del: v(&["x"]),
            ..Default::default()
        };
        let base = v(&["a", "x"]);
        // x removed by del, b appended after base, a kept.
        assert_eq!(d.effective_allow(&base), v(&["a", "b"]));
    }

    #[test]
    fn add_is_idempotent() {
        let base = v(&["a"]);
        let mut d = AclDelta::default();
        d.add_allow(&base, "b");
        d.add_allow(&base, "b");
        assert_eq!(d.allow_add, v(&["b"]));
        assert_eq!(d.effective_allow(&base), v(&["a", "b"]));
    }

    #[test]
    fn add_existing_base_rule_is_noop() {
        let base = v(&["a"]);
        let mut d = AclDelta::default();
        d.add_allow(&base, "a");
        assert!(d.allow_add.is_empty());
        assert_eq!(d.effective_allow(&base), v(&["a"]));
    }

    #[test]
    fn del_dynamic_add_just_removes_it() {
        let base: Vec<String> = vec![];
        let mut d = AclDelta::default();
        d.add_allow(&base, "b");
        d.del_allow(&base, "b");
        assert!(d.allow_add.is_empty());
        assert!(d.allow_del.is_empty()); // b not in base -> no suppression needed
        assert!(d.effective_allow(&base).is_empty());
    }

    #[test]
    fn del_base_rule_suppresses_it() {
        let base = v(&["a"]);
        let mut d = AclDelta::default();
        d.del_allow(&base, "a");
        assert_eq!(d.allow_del, v(&["a"]));
        assert!(d.effective_allow(&base).is_empty());
    }

    #[test]
    fn add_cancels_prior_del_of_base_rule() {
        let base = v(&["a"]);
        let mut d = AclDelta::default();
        d.del_allow(&base, "a");
        d.add_allow(&base, "a");
        assert!(d.allow_del.is_empty());
        assert!(d.allow_add.is_empty());
        assert_eq!(d.effective_allow(&base), v(&["a"]));
    }

    #[test]
    fn deny_side_mirrors_allow_side() {
        let base = v(&["d1"]);
        let mut d = AclDelta::default();
        d.add_deny(&base, "d2");
        d.del_deny(&base, "d1");
        assert_eq!(d.effective_deny(&base), v(&["d2"]));
    }

    #[test]
    fn policies_without_acl_fields_deserialize_to_defaults() {
        // Old state files predate the ACL overlays — they must still load.
        let json = r#"{"version":1,"updated_at":"2020-01-01T00:00:00Z","bindings":{}}"#;
        let p: Policies = serde_json::from_str(json).unwrap();
        assert!(p.domain_acl.allow_add.is_empty());
        assert!(p.egress_acl.deny_add.is_empty());
    }
}
