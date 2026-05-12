# v6proxy

Single-binary Rust proxy for random IPv6 exit routing. It listens on TCP 80,
TCP 443, and UDP 443, sniffs HTTP Host / TLS SNI / QUIC SNI, and forwards
customer traffic through deterministic random IPv6 source addresses.

## What It Does

- Admin API on a management address, protected by source IP allowlist and
  bearer token for binding changes.
- TCP data plane for HTTP and HTTPS SNI forwarding.
- UDP data plane for QUIC Initial SNI forwarding.
- Per-customer source IP bindings persisted to `policies.json`.
- Hash policies that determine how stable or random the selected IPv6 exit is.
- Outbound IPv6 source binding with `IPV6_FREEBIND`.

IPv4-only upstream targets are intentionally unsupported. Upstream hosts must
resolve to IPv6, or the deployment must provide NAT64/DNS64 and expose the
target through a real IPv6 address.

## Files

Recommended production layout:

```text
/etc/v6proxy/
└── config.toml     # Listeners, auth, state path, IPv6 pools

/var/lib/v6proxy/
└── policies.json   # Runtime binding state, managed by v6proxy
```

Example configs live in `deploy/examples/`.

## config.toml

`config.toml` replaces the old separate `global.toml` and `machine.toml`.

```toml
[admin]
bind = "127.0.0.1:8787"
# Generate with: echo -n "your-secret-token" | argon2 $(openssl rand -base64 16) -id -e
token_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
allowlist = [
  "127.0.0.1",
  "10.0.1.0/24",
]

[data]
tcp_binds = ["0.0.0.0:80", "0.0.0.0:443", "[::]:80", "[::]:443"]
udp_binds = ["0.0.0.0:443", "[::]:443"]

[paths]
state = "/var/lib/v6proxy/policies.json"

[policy]
# Default policy for traffic without a matching binding, and for new bindings
# when the API request omits "policy".
# Options: "src_ip", "src_dst", "five_tuple".
default = "src_ip"
# Default seed for traffic without a matching binding, and for new bindings
# when the API request omits "seed".
default_seed = 0

[machine]
v6_pools = ["2001:db8:a::/64", "2001:db8:b::/48"]
# TODO: Add SNI routing rules here once the dataplane supports them.
```

Notes:

- `admin.bind` should normally stay on `127.0.0.1` or a private management
  address.
- `admin.token_hash` is the argon2id hash of the admin bearer token.
- `admin.allowlist` controls which source IPs may call admin endpoints.
- `data.tcp_binds` controls HTTP/HTTPS TCP listeners.
- `data.udp_binds` controls QUIC listeners.
- `paths.state` points to the runtime policies file. The parent directory is
  created automatically.
- `policy.default` controls the hash policy for traffic without a matching
  binding, and for new bindings when the API request omits `policy`. Valid
  values are `src_ip`, `src_dst`, and `five_tuple`.
- `policy.default_seed` controls the hash seed for traffic without a matching
  binding, and for new bindings when the API request omits `seed`. Use `0` for
  a stable deterministic fallback.
- `machine.v6_pools` must contain routed IPv6 prefixes that the host is allowed
  to use.

Generate an admin token hash with an argon2id-compatible tool, then put only
the hash in `admin.token_hash`. API clients send the plaintext token as:

```text
Authorization: Bearer <token>
```

## Hash Policies

| Policy | Behavior |
| ------ | -------- |
| `src_ip` | Same customer source IP always selects the same IPv6 exit. |
| `src_dst` | Source IP plus destination IP selects the IPv6 exit. |
| `five_tuple` | Source IP, destination IP, source port, and destination port select the IPv6 exit. |

Use `src_ip` when stability matters most. Use `five_tuple` when you want more
rotation across concurrent flows.

## Admin API

`/v1/healthz` has no auth. `/v1/metrics` requires the caller source IP to be in
`admin.allowlist`. Binding endpoints require both allowlist and bearer token.

```text
GET    /v1/healthz
GET    /v1/metrics
GET    /v1/bindings
GET    /v1/bindings/:srcip
PUT    /v1/bindings/:srcip
PATCH  /v1/bindings/:srcip/hash_policy
POST   /v1/bindings/:srcip/reseed
DELETE /v1/bindings/:srcip
```

`GET /v1/bindings/:srcip` always returns `200` for a valid source IP. When a
dedicated binding exists, `exists` is `true`. When no dedicated binding exists,
the response contains the default effective hash policy and seed with `exists`
set to `false`.

Create or replace a binding:

```bash
curl -X PUT http://127.0.0.1:8787/v1/bindings/203.0.113.10 \
  -H 'Authorization: Bearer your-secret-token' \
  -H 'Content-Type: application/json' \
  -d '{"policy":"src_ip","seed":"0x1111111111111111"}'
```

Change policy:

```bash
curl -X PATCH http://127.0.0.1:8787/v1/bindings/203.0.113.10/hash_policy \
  -H 'Authorization: Bearer your-secret-token' \
  -H 'Content-Type: application/json' \
  -d '{"policy":"five_tuple"}'
```

Reseed:

```bash
curl -X POST http://127.0.0.1:8787/v1/bindings/203.0.113.10/reseed \
  -H 'Authorization: Bearer your-secret-token'
```

## Build

```bash
cargo build --release
install -m 0755 target/release/v6proxy /usr/local/bin/v6proxy
```

## Host Prerequisites

The host must be able to emit packets using addresses from each configured
`v6_pools` prefix.

Typical Linux setup:

```bash
sysctl -w net.ipv6.ip_nonlocal_bind=1
ip -6 route add local 2001:db8:a::/64 dev lo
ip -6 route add local 2001:db8:b::/48 dev lo
```

Persist these settings through your normal system configuration management.
The exact route commands depend on the prefixes assigned to the machine.

For public service ports 80 and 443, run with either root privileges or the
needed Linux capabilities. The provided systemd service grants:

```text
CAP_NET_BIND_SERVICE CAP_NET_RAW
```

## Run Manually

```bash
RUST_LOG=info /usr/local/bin/v6proxy --config /etc/v6proxy/config.toml
```

Logs default to text output. Use JSON for structured log collection:

```bash
RUST_LOG=info /usr/local/bin/v6proxy --config /etc/v6proxy/config.toml --log-format json
```

Create a starter config:

```bash
/usr/local/bin/v6proxy --config /etc/v6proxy/config.toml init
```

Validate the config without binding listeners or touching state:

```bash
/usr/local/bin/v6proxy --config /etc/v6proxy/config.toml --check-config
```

If `--config` is not passed, v6proxy defaults to:

```text
/etc/v6proxy/config.toml
```

## systemd

Install the service:

```bash
cp deploy/systemd/v6proxy.service /etc/systemd/system/v6proxy.service
systemctl daemon-reload
systemctl enable --now v6proxy
systemctl status v6proxy
```

The service uses `Type=simple`. Startup fails before the "started successfully"
log line if any configured listener cannot bind.

## Smoke Test

1. Start the service.
2. Check health:

```bash
curl http://127.0.0.1:8787/v1/healthz
```

3. Create a binding for a test client source IP.
4. Send TCP traffic with an HTTP `Host` header or TLS SNI to the data listener.
5. Run with `RUST_LOG=debug` during validation and confirm logs show:

```text
forwarding connection ... dst=... src_v6=... sni=...
```

For QUIC validation, use a client with HTTP/3 support, for example:

```bash
curl --http3-only https://example.com/
```

Expected debug log:

```text
forwarding new QUIC session ... dst=... src_v6=... sni=...
```

## Operational Notes

- `policies.json` is written atomically and should be on persistent storage.
- If a source IP has no binding, data-plane traffic is silently dropped.
- If a request has no usable Host/SNI, data-plane traffic is dropped.
- Multiple IPv6 pools are selected by hash, then the host bits are derived from
  the same hash.
- QUIC support depends on parsing Initial packets. Keep UDP 443 disabled if
  your deployment has not validated HTTP/3 traffic end to end.

## License

Apache License 2.0
