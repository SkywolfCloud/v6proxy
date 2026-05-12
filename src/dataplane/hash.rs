use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};

use siphasher::sip::SipHasher24;

use crate::config::V6Pool;
use crate::state::{Binding, HashPolicy};

/// Pick an outgoing IPv6 address based on the binding's hash policy and seed.
pub fn pick_outgoing(
    pools: &[V6Pool],
    binding: &Binding,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> Option<Ipv6Addr> {
    if pools.is_empty() {
        return None;
    }

    let k0 = binding.seed;
    let k1 = binding.seed.rotate_left(17);
    let mut hasher = SipHasher24::new_with_keys(k0, k1);

    match binding.policy {
        HashPolicy::SrcIp => {
            src_ip.hash(&mut hasher);
        }
        HashPolicy::SrcDst => {
            src_ip.hash(&mut hasher);
            dst_ip.hash(&mut hasher);
        }
        HashPolicy::FiveTuple => {
            src_ip.hash(&mut hasher);
            dst_ip.hash(&mut hasher);
            src_port.hash(&mut hasher);
            dst_port.hash(&mut hasher);
        }
    }

    let hash = hasher.finish();

    // Select pool by hash, then map host bits within that pool
    let pool_index = (hash as usize) % pools.len();
    let pool = &pools[pool_index];
    Some(pool.host_at(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::HashPolicy;
    use chrono::Utc;

    fn test_binding(policy: HashPolicy, seed: u64) -> Binding {
        Binding {
            policy,
            seed,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_same_src_same_output() {
        let pool = V6Pool::parse("2001:db8:a::/64").unwrap();
        let binding = test_binding(HashPolicy::SrcIp, 0x1234567890abcdef);
        let src: IpAddr = "203.0.113.10".parse().unwrap();
        let dst: IpAddr = "93.184.216.34".parse().unwrap();

        let v6_1 = pick_outgoing(&[pool.clone()], &binding, src, dst, 12345, 443);
        let v6_2 = pick_outgoing(
            &[pool.clone()],
            &binding,
            src,
            "1.2.3.4".parse().unwrap(),
            54321,
            80,
        );

        // SrcIp policy: same src → same output regardless of dst
        assert_eq!(v6_1, v6_2);
    }

    #[test]
    fn test_different_src_different_output() {
        let pool = V6Pool::parse("2001:db8:a::/64").unwrap();
        let binding = test_binding(HashPolicy::SrcIp, 0x1234567890abcdef);
        let dst: IpAddr = "93.184.216.34".parse().unwrap();

        let v6_1 = pick_outgoing(
            &[pool.clone()],
            &binding,
            "203.0.113.10".parse().unwrap(),
            dst,
            1,
            443,
        );
        let v6_2 = pick_outgoing(
            &[pool.clone()],
            &binding,
            "203.0.113.11".parse().unwrap(),
            dst,
            1,
            443,
        );

        assert_ne!(v6_1, v6_2);
    }

    #[test]
    fn test_src_dst_policy() {
        let pool = V6Pool::parse("2001:db8:a::/64").unwrap();
        let binding = test_binding(HashPolicy::SrcDst, 0xdeadbeefcafebabe);
        let src: IpAddr = "10.0.0.1".parse().unwrap();

        let v6_1 = pick_outgoing(
            &[pool.clone()],
            &binding,
            src,
            "1.1.1.1".parse().unwrap(),
            1,
            443,
        );
        let v6_2 = pick_outgoing(
            &[pool.clone()],
            &binding,
            src,
            "8.8.8.8".parse().unwrap(),
            1,
            443,
        );

        // Different dst → different output
        assert_ne!(v6_1, v6_2);
    }

    #[test]
    fn test_output_in_pool() {
        let pool = V6Pool::parse("2001:db8:a::/64").unwrap();
        let binding = test_binding(HashPolicy::SrcIp, 0x1111111111111111);
        let v6 = pick_outgoing(
            &[pool],
            &binding,
            "10.0.0.1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            1,
            443,
        )
        .unwrap();

        let v6_u128 = u128::from(v6);
        // Top 64 bits should match the pool prefix
        let prefix = u128::from("2001:0db8:000a:0000::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6_u128 & (!0u128 << 64), prefix & (!0u128 << 64));
    }

    #[test]
    fn test_reseed_changes_output() {
        let pool = V6Pool::parse("2001:db8:a::/64").unwrap();
        let b1 = test_binding(HashPolicy::SrcIp, 0xaaaa);
        let b2 = test_binding(HashPolicy::SrcIp, 0xbbbb);
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();

        let v6_1 = pick_outgoing(&[pool.clone()], &b1, src, dst, 1, 443);
        let v6_2 = pick_outgoing(&[pool], &b2, src, dst, 1, 443);

        assert_ne!(v6_1, v6_2);
    }
}
