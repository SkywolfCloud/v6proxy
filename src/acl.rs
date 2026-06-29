//! Shared access-control primitives for the IP (egress) and domain filters.
//!
//! Both filters resolve allow/deny conflicts with the same "most-specific-wins"
//! rule (model B): among the rules that match a target, the one with the highest
//! specificity decides; a tie goes to deny (fail-closed); when nothing matches, a
//! non-empty allow list means whitelist mode (block), otherwise default-allow.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use arc_swap::ArcSwap;
use once_cell::sync::{Lazy, OnceCell};

use crate::config::EgressFilter;
use crate::state::{AclDelta, POLICIES};

/// Resolve an allow/deny decision from the most-specific match found in each
/// list.
///
/// * `best_allow` / `best_deny` — the highest specificity that matched in the
///   allow / deny list, or `None` if that list matched nothing.
/// * `allow_is_empty` — whether the effective allow list has no entries at all.
///
/// Returns `true` to permit, `false` to block.
pub fn decide<S: Ord>(best_allow: Option<S>, best_deny: Option<S>, allow_is_empty: bool) -> bool {
    match (best_allow, best_deny) {
        // Nothing matched: whitelist mode (non-empty allow) blocks, else allow.
        (None, None) => allow_is_empty,
        // Only one side matched: that side decides.
        (Some(_), None) => true,
        (None, Some(_)) => false,
        // Both matched: the more specific wins; a tie (a == d) goes to deny.
        (Some(a), Some(d)) => a > d,
    }
}

// ---------------------------------------------------------------------------
// Domain rules (mosdns-style): full / domain / keyword.
// ---------------------------------------------------------------------------

/// A parsed domain rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Exact match: `full:example.com` matches only `example.com`.
    Full(String),
    /// Zone match: `domain:example.com` matches `example.com` and any subdomain.
    Domain(String),
    /// Substring match: `keyword:ads` matches any host containing `ads`.
    Keyword(String),
}

/// Normalize a hostname or domain value: trim, drop trailing dot(s), lowercase.
fn normalize(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse a single mosdns-style rule string. A bare entry (no known prefix) is
/// treated as `domain:`. `regexp:` is intentionally unsupported.
pub fn parse_rule(s: &str) -> Result<Rule> {
    let s = s.trim();

    if let Some(v) = s.strip_prefix("keyword:") {
        let v = v.trim().to_ascii_lowercase();
        if v.is_empty() {
            bail!("empty keyword rule: {:?}", s);
        }
        return Ok(Rule::Keyword(v));
    }

    let (is_full, raw) = if let Some(v) = s.strip_prefix("full:") {
        (true, v)
    } else if let Some(v) = s.strip_prefix("domain:") {
        (false, v)
    } else {
        (false, s)
    };

    let v = normalize(raw);
    if v.is_empty() {
        bail!("empty domain rule: {:?}", s);
    }
    // A leftover ':' / '/' / whitespace means an unknown or unsupported prefix
    // (e.g. regexp:) or a malformed entry — reject rather than silently treating
    // it as a literal domain.
    if v.contains(':') || v.contains('/') || v.contains(char::is_whitespace) {
        bail!(
            "invalid domain rule {:?} (unsupported prefix or bad characters)",
            s
        );
    }

    if is_full {
        Ok(Rule::Full(v))
    } else {
        Ok(Rule::Domain(v))
    }
}

/// Parse a rule and re-render it in canonical `kind:value` form, so dynamic
/// add/del entries compare equal to the config base regardless of how they were
/// written. Returns an error for invalid/unsupported rules.
pub fn canonicalize_rule(s: &str) -> Result<String> {
    Ok(match parse_rule(s)? {
        Rule::Full(v) => format!("full:{v}"),
        Rule::Domain(v) => format!("domain:{v}"),
        Rule::Keyword(v) => format!("keyword:{v}"),
    })
}

/// A compiled set of domain rules supporting an O(labels) best-match query.
#[derive(Debug, Default, Clone)]
struct DomainMatcher {
    full: HashSet<String>,
    domain: HashSet<String>,
    keyword: Vec<String>,
}

impl DomainMatcher {
    fn from_rules(rules: impl IntoIterator<Item = Rule>) -> Self {
        let mut m = DomainMatcher::default();
        for r in rules {
            match r {
                Rule::Full(s) => {
                    m.full.insert(s);
                }
                Rule::Domain(s) => {
                    m.domain.insert(s);
                }
                Rule::Keyword(s) => m.keyword.push(s),
            }
        }
        m
    }

    fn is_empty(&self) -> bool {
        self.full.is_empty() && self.domain.is_empty() && self.keyword.is_empty()
    }

    /// Specificity `(tier, detail)` of the most specific matching rule, or
    /// `None`. tier: full=3 > domain=2 > keyword=1; detail for `domain` = the
    /// matched zone's label count (a longer zone is more specific).
    fn best_match(&self, host: &str) -> Option<(u8, u16)> {
        if self.full.contains(host) {
            return Some((3, 0));
        }
        // Walk suffixes longest -> shortest; the first hit is the longest zone.
        let mut suffix = Some(host);
        while let Some(s) = suffix {
            if self.domain.contains(s) {
                let labels = s.split('.').count() as u16;
                return Some((2, labels));
            }
            suffix = s.split_once('.').map(|(_, rest)| rest);
        }
        if self.keyword.iter().any(|k| host.contains(k.as_str())) {
            return Some((1, 0));
        }
        None
    }
}

/// Allow/deny domain filter resolved with model B (most-specific-wins).
#[derive(Debug, Default, Clone)]
pub struct DomainFilter {
    allow: DomainMatcher,
    deny: DomainMatcher,
}

impl DomainFilter {
    /// Build from raw rule strings (config base merged with the dynamic
    /// overlay). Invalid rules are an error.
    pub fn build(allow: &[String], deny: &[String]) -> Result<Self> {
        let allow_rules = allow
            .iter()
            .map(|s| parse_rule(s))
            .collect::<Result<Vec<_>>>()?;
        let deny_rules = deny
            .iter()
            .map(|s| parse_rule(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(DomainFilter {
            allow: DomainMatcher::from_rules(allow_rules),
            deny: DomainMatcher::from_rules(deny_rules),
        })
    }

    /// Returns true if `host` (a SNI/Host value) is permitted.
    pub fn is_allowed(&self, host: &str) -> bool {
        let host = normalize(host);
        decide(
            self.allow.best_match(&host),
            self.deny.best_match(&host),
            self.allow.is_empty(),
        )
    }
}

// ---------------------------------------------------------------------------
// Build the effective filter from config base + runtime overlay.
// ---------------------------------------------------------------------------

/// Parse rules, dropping any that fail to parse (returned, formatted, for
/// logging) so a hand-edited state file cannot break startup.
fn filter_valid_rules(rules: &[String]) -> (Vec<String>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for r in rules {
        match parse_rule(r) {
            Ok(_) => ok.push(r.clone()),
            Err(e) => bad.push(format!("{}: {}", r, e)),
        }
    }
    (ok, bad)
}

/// Build the effective domain filter from the config base + dynamic overlay.
/// Invalid persisted rules are dropped and returned for logging.
pub fn build_domain_filter(
    base_allow: &[String],
    base_deny: &[String],
    delta: &AclDelta,
) -> (DomainFilter, Vec<String>) {
    let (allow, mut bad) = filter_valid_rules(&delta.effective_allow(base_allow));
    let (deny, bad_deny) = filter_valid_rules(&delta.effective_deny(base_deny));
    bad.extend(bad_deny);
    // Every remaining rule parses, so build cannot actually fail.
    let filter = DomainFilter::build(&allow, &deny).unwrap_or_default();
    (filter, bad)
}

// ---------------------------------------------------------------------------
// Hot-swappable global filter + drop counter, rebuilt on every mutation.
// ---------------------------------------------------------------------------

/// Config `[domain]` base (allow, deny), recorded once at startup.
static DOMAIN_BASE: OnceCell<(Vec<String>, Vec<String>)> = OnceCell::new();

/// The compiled, hot-swappable domain filter read by the data plane.
pub static DOMAIN_FILTER: Lazy<ArcSwap<DomainFilter>> =
    Lazy::new(|| ArcSwap::from_pointee(DomainFilter::default()));

/// Number of connections dropped by the domain ACL (exported via /v1/metrics).
pub static DOMAIN_BLOCKED: AtomicU64 = AtomicU64::new(0);

/// Record the config base and build the initial domain filter from base + the
/// persisted overlay. Call once at startup, after policies are loaded.
pub fn init_domain_filter(base_allow: Vec<String>, base_deny: Vec<String>) {
    // Canonicalize the base so that an API `del` of a base rule compares equal
    // regardless of how the rule was written in config.toml.
    let ba = base_allow
        .iter()
        .filter_map(|r| canonicalize_rule(r).ok())
        .collect();
    let bd = base_deny
        .iter()
        .filter_map(|r| canonicalize_rule(r).ok())
        .collect();
    let _ = DOMAIN_BASE.set((ba, bd));
    rebuild_domain_filter();
}

/// Rebuild the domain filter from the config base + current `POLICIES.domain_acl`
/// and hot-swap it in. Call after every domain ACL mutation.
pub fn rebuild_domain_filter() {
    let (base_allow, base_deny) = DOMAIN_BASE.get().expect("domain base not initialized");
    let policies = POLICIES.load();
    let (filter, bad) = build_domain_filter(base_allow, base_deny, &policies.domain_acl);
    for b in &bad {
        tracing::warn!(rule = %b, "skipping invalid domain rule from state");
    }
    DOMAIN_FILTER.store(Arc::new(filter));
}

/// Increment the domain-ACL drop counter.
pub fn note_domain_blocked() {
    DOMAIN_BLOCKED.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of the config `[domain]` base `(allow, deny)` for the admin API.
pub fn domain_base() -> (Vec<String>, Vec<String>) {
    DOMAIN_BASE.get().cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Egress (IP) filter: same two-layer + hot-swap machinery as the domain side.
// ---------------------------------------------------------------------------

/// Config `[egress]` base (allow, deny), recorded once at startup.
static EGRESS_BASE: OnceCell<(Vec<String>, Vec<String>)> = OnceCell::new();

/// The compiled, hot-swappable egress filter read by `resolve_dst`.
pub static EGRESS_FILTER: Lazy<ArcSwap<EgressFilter>> =
    Lazy::new(|| ArcSwap::from_pointee(EgressFilter::default()));

/// Number of upstream connections dropped by the egress filter.
pub static EGRESS_BLOCKED: AtomicU64 = AtomicU64::new(0);

/// Keep only entries that parse as an IP/CIDR; return the dropped ones.
fn filter_valid_nets(entries: &[String]) -> (Vec<String>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for e in entries {
        if crate::config::parse_net(e).is_ok() {
            ok.push(e.clone());
        } else {
            bad.push(e.clone());
        }
    }
    (ok, bad)
}

/// Build the effective egress filter from the config base + dynamic overlay.
/// Invalid persisted entries are dropped and returned for logging.
pub fn build_egress_filter(
    base_allow: &[String],
    base_deny: &[String],
    delta: &AclDelta,
) -> (EgressFilter, Vec<String>) {
    let (allow, mut bad) = filter_valid_nets(&delta.effective_allow(base_allow));
    let (deny, bad_deny) = filter_valid_nets(&delta.effective_deny(base_deny));
    bad.extend(bad_deny);
    // Every remaining entry parses, so build cannot actually fail.
    let filter = EgressFilter::build(&allow, &deny).unwrap_or_default();
    (filter, bad)
}

/// Record the canonicalized config base and build the initial egress filter.
pub fn init_egress_filter(base_allow: Vec<String>, base_deny: Vec<String>) {
    let ba = base_allow
        .iter()
        .filter_map(|e| crate::config::canonicalize_net(e).ok())
        .collect();
    let bd = base_deny
        .iter()
        .filter_map(|e| crate::config::canonicalize_net(e).ok())
        .collect();
    let _ = EGRESS_BASE.set((ba, bd));
    rebuild_egress_filter();
}

/// Rebuild the egress filter from base + `POLICIES.egress_acl` and hot-swap it.
pub fn rebuild_egress_filter() {
    let (base_allow, base_deny) = EGRESS_BASE.get().expect("egress base not initialized");
    let policies = POLICIES.load();
    let (filter, bad) = build_egress_filter(base_allow, base_deny, &policies.egress_acl);
    for b in &bad {
        tracing::warn!(entry = %b, "skipping invalid egress entry from state");
    }
    EGRESS_FILTER.store(Arc::new(filter));
}

/// Increment the egress drop counter.
pub fn note_egress_blocked() {
    EGRESS_BLOCKED.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of the config `[egress]` base `(allow, deny)` for the admin API.
pub fn egress_base() -> (Vec<String>, Vec<String>) {
    EGRESS_BASE.get().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_match_default_allows_when_allow_empty() {
        // Pure blacklist mode: nothing matched and there is no allow list at all
        // -> permit.
        assert!(decide::<u8>(None, None, true));
    }

    #[test]
    fn no_match_blocks_in_whitelist_mode() {
        // Whitelist mode: allow list is non-empty but nothing matched -> block.
        assert!(!decide::<u8>(None, None, false));
    }

    #[test]
    fn allow_only_permits() {
        assert!(decide(Some(10u8), None, false));
    }

    #[test]
    fn deny_only_blocks() {
        assert!(!decide(None, Some(10u8), true));
    }

    #[test]
    fn more_specific_allow_wins() {
        // e.g. allow /32 vs deny /7 -> allow is more specific.
        assert!(decide(Some(32u8), Some(7u8), false));
    }

    #[test]
    fn more_specific_deny_wins() {
        // e.g. allow domain(2 labels) vs deny full -> deny is more specific.
        assert!(!decide(Some(2u8), Some(128u8), false));
    }

    #[test]
    fn tie_goes_to_deny() {
        assert!(!decide(Some(64u8), Some(64u8), false));
    }
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    #[test]
    fn parse_bare_is_domain_normalized() {
        assert_eq!(
            parse_rule("Example.COM.").unwrap(),
            Rule::Domain("example.com".into())
        );
    }

    #[test]
    fn parse_known_prefixes() {
        assert_eq!(
            parse_rule("full:a.com").unwrap(),
            Rule::Full("a.com".into())
        );
        assert_eq!(
            parse_rule("domain:a.com").unwrap(),
            Rule::Domain("a.com".into())
        );
        assert_eq!(
            parse_rule("keyword:Ads").unwrap(),
            Rule::Keyword("ads".into())
        );
    }

    #[test]
    fn parse_rejects_empty_and_unsupported() {
        assert!(parse_rule("domain:").is_err());
        assert!(parse_rule("").is_err());
        // regexp: is not supported; it must not silently become a domain rule.
        assert!(parse_rule("regexp:.+\\.cn$").is_err());
    }

    #[test]
    fn full_matches_exact_only() {
        let f = DomainFilter::build(&[], &["full:example.com".into()]).unwrap();
        assert!(!f.is_allowed("example.com")); // deny matched
        assert!(f.is_allowed("www.example.com")); // full does not cover subdomain
    }

    #[test]
    fn domain_matches_subdomains() {
        let f = DomainFilter::build(&[], &["domain:example.com".into()]).unwrap();
        assert!(!f.is_allowed("example.com"));
        assert!(!f.is_allowed("www.example.com"));
        assert!(!f.is_allowed("a.b.example.com"));
        assert!(f.is_allowed("notexample.com")); // suffix boundary respected
        assert!(f.is_allowed("example.com.evil.com"));
    }

    #[test]
    fn keyword_matches_substring_case_insensitive() {
        let f = DomainFilter::build(&[], &["keyword:ads".into()]).unwrap();
        assert!(!f.is_allowed("ads.example.com"));
        assert!(!f.is_allowed("x.ADS-server.net"));
        assert!(f.is_allowed("example.com"));
    }

    #[test]
    fn host_normalization_uppercase_and_trailing_dot() {
        let f = DomainFilter::build(&[], &["domain:example.com".into()]).unwrap();
        assert!(!f.is_allowed("WWW.Example.COM."));
    }

    #[test]
    fn block_zone_but_allow_one_host() {
        let f = DomainFilter::build(
            &["full:safe.example.com".into()],
            &["domain:example.com".into()],
        )
        .unwrap();
        assert!(f.is_allowed("safe.example.com")); // full (3) beats domain (2)
        assert!(!f.is_allowed("evil.example.com"));
        assert!(!f.is_allowed("example.com"));
    }

    #[test]
    fn allow_zone_but_block_one_host() {
        let f = DomainFilter::build(
            &["domain:example.com".into()],
            &["full:ads.example.com".into()],
        )
        .unwrap();
        assert!(!f.is_allowed("ads.example.com")); // full (3) beats domain (2)
        assert!(f.is_allowed("www.example.com"));
        // whitelist mode: allow non-empty -> unrelated host blocked
        assert!(!f.is_allowed("other.org"));
    }

    #[test]
    fn pure_blacklist_allows_unrelated() {
        let f = DomainFilter::build(&[], &["domain:bad.com".into()]).unwrap();
        assert!(f.is_allowed("good.com"));
        assert!(!f.is_allowed("bad.com"));
    }

    #[test]
    fn longer_zone_is_more_specific() {
        let f = DomainFilter::build(
            &["domain:example.com".into()],
            &["domain:ads.example.com".into()],
        )
        .unwrap();
        assert!(!f.is_allowed("x.ads.example.com")); // deny (2,3) beats allow (2,2)
        assert!(f.is_allowed("x.example.com")); // only allow matches
    }

    #[test]
    fn canonicalize_renders_normalized_prefixed_form() {
        assert_eq!(
            canonicalize_rule("Example.COM.").unwrap(),
            "domain:example.com"
        );
        assert_eq!(canonicalize_rule("full:A.com").unwrap(), "full:a.com");
        assert_eq!(canonicalize_rule("keyword:Ads").unwrap(), "keyword:ads");
        assert!(canonicalize_rule("regexp:x").is_err());
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn build_applies_base_and_overlay() {
        let base_deny = vec!["domain:example.com".to_string()];
        let mut delta = AclDelta::default();
        delta.add_allow(&[], "full:safe.example.com");
        let (f, bad) = build_domain_filter(&[], &base_deny, &delta);
        assert!(bad.is_empty());
        assert!(!f.is_allowed("evil.example.com")); // base deny
        assert!(f.is_allowed("safe.example.com")); // overlay allow, full beats domain
    }

    #[test]
    fn build_drops_invalid_overlay_rule() {
        let mut delta = AclDelta::default();
        delta.deny_add.push("regexp:bad".to_string());
        delta.deny_add.push("domain:bad.com".to_string());
        let (f, bad) = build_domain_filter(&[], &[], &delta);
        assert_eq!(bad.len(), 1);
        assert!(!f.is_allowed("bad.com"));
        assert!(f.is_allowed("ok.com"));
    }
}
