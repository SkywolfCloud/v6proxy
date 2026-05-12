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
}

impl Default for Policies {
    fn default() -> Self {
        Policies {
            version: 0,
            updated_at: Utc::now(),
            bindings: HashMap::new(),
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
