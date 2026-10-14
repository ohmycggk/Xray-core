# Nowhere outbound

Protocol name: `nowhere`. This is the Nowhere client. Fields sit at the top level of `settings`, not inside a nested object.

`alpn` selects the protocol stack, on both client and server — there is no separate version field:

| `alpn` | Stack |
| --- | --- |
| Omitted or `"nw3"` | Nowhere 3 (`nw3`) — the default |
| `"nw2"`, or any other single value | Nowhere 2.2.1 (`nw2`) — the legacy stack |

The two stacks share no handshake: a single outbound runs exactly one stack, and the fields of the other stack are rejected. Nowhere 3 is the default, so a configuration that sets no `alpn` runs nw3. Nowhere 2 is kept for compatibility with pre-nw3 peers: set `alpn` to `"nw2"` (or a custom value) to keep it. This page leads with Nowhere 3. The legacy stack is at the end.

The protocol performs its own TLS 1.3. `streamSettings` may be omitted. If set, `network` must be `tcp` and `security` must be `none`. The dial uses the Xray outbound dialer, so `sockopt` and this outbound's `sendThrough` apply to the connection toward the Portal.

On the Portal, write `listen` as an IP. A non-IP or omitted `listen` makes QUIC bind `0.0.0.0`, and the QUIC `port` must not be `0`. See the [inbound](../inbound/nowhere.md).

## Nowhere 3

Nowhere 3 negotiates ALPN `nw3` only. Each outbound uses exactly one transport. The session is created on first use, and later flows share it. An omitted `net`, or `"tcp"`, is TLS over TCP, and UDP targets are carried as UoT. `"udp"` is QUIC: TCP uses streams and UDP uses DATAGRAMs. `up` / `down` are neither required nor accepted.

The key must match the Portal and be exactly 32 lowercase hexadecimal characters (`[0-9a-f]{32}`). Those characters are the raw key text. They are not hex-decoded again.

`morph` is not negotiated in band. When omitted, Nowhere 3 turns it on. It must match the Portal.

```json
{
  "tag": "nw3-out",
  "protocol": "nowhere",
  "settings": {
    "address": "203.0.113.10",
    "port": 443,
    "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "allowInsecure": true
  }
}
```

When the Portal uses a trusted certificate, drop `allowInsecure` and set `serverName` to the name on that certificate. For QUIC, set `net` to `"udp"` and have the Portal listen on UDP.

### Fields

| Field | Required | Description |
| --- | --- | --- |
| `address` | Yes | Portal address, an IP or a domain |
| `port` | Yes | Portal port |
| `password` | Yes | Exactly 32 lowercase hexadecimal characters |
| `net` | No | `tcp` or `udp`. Omitted means `tcp`. Any other value fails startup |
| `morph` | No | Key transform. Omitted means `true`. Must match the Portal |
| `serverName` | No | TLS verification name. If omitted and `address` is a domain, `address` is used. An IP `address` is not copied in |
| `pin` | No | SHA-256 of the leaf certificate, 64 lowercase hex characters. `none` or omitted disables pinning. When set, the pin overrides certificate-chain and name checks |
| `allowInsecure` | No | Skip certificate-chain and name checks. Required for a self-signed certificate when `pin` is not set |
| `userLevel` | No | Policy level used for this outbound's connection timeouts. Default `0` |

Nowhere 3 rejects `up`, `down`, `mux`, `pool`, `dial4`, and `dial6`. ALPN is fixed to `nw3`.

When the Portal has no `certificates`, each start replaces the in-memory self-signed certificate (ECDSA P-256, DNS `nowhere.local`). A Nowhere 3 Portal prints `nowhere TLS certificate SHA-256 fingerprint:` at log level `info`. Put that value in `pin`. For an existing certificate file:

```bash
openssl x509 -in server.crt -outform DER | sha256sum
```

Uppercase hex is rejected.

## Nowhere 2

Setting `alpn` to `"nw2"`, or to any other single non-nw3 value, selects the legacy Nowhere 2 stack. It cannot interoperate with Nowhere 3. `password`, `morph`, and `alpn` must match the Portal. Omitted `up` / `down` are both `tcp`.

```json
{
  "tag": "nw2-out",
  "protocol": "nowhere",
  "settings": {
    "address": "203.0.113.10",
    "port": 443,
    "password": "shared-secret",
    "alpn": "nw2",
    "up": "tcp",
    "down": "tcp",
    "pool": 5,
    "allowInsecure": true
  }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `address` | Yes | Portal address, an IP or a domain |
| `port` | Yes | Portal port |
| `password` | Yes | 1–255 bytes. The Portal inbound's 32–64 lowercase-hex rule does not apply |
| `alpn` | No | The stack selector. Default `nw2` when omitted, length 1–255 bytes. Must match the Portal |
| `up` / `down` | No | `tcp` or `udp`. Omitted means `tcp`. If either direction is `udp`, the Portal must enable that transport |
| `mux` | No | `true` enables TLS Mux. It matters only when TCP can be used; `udp` / `udp` is canonicalized to off |
| `morph` | No | Omitted means `false`. Must match the Portal |
| `serverName` | No | Same as Nowhere 3 |
| `pin` | No | Same as Nowhere 3 |
| `allowInsecure` | No | Same as Nowhere 3 |
| `pool` | No | Effective only for dedicated `tcp` / `tcp` with `mux` false. Range 0–256. Omitted or `0` does not prewarm; dials happen on demand |
| `userLevel` | No | Policy level used for connection timeouts. Default `0` |

If `mux` is true, or either `up` or `down` is `udp`, `pool` must be `0` or omitted. Otherwise startup fails.

| `up` ↓ / `down` → | `tcp` | `udp` |
| --- | --- | --- |
| `tcp` | TLS / TLS | TLS / QUIC |
| `udp` | QUIC / TLS | QUIC / QUIC |

`dial4` / `dial6` on a normal outbound fail startup. To bind the source of the dial toward the Portal, set `sendThrough` on this outbound. Those two fields work only on an inbound `next` hop. To bind the source of a later direct connection leaving this host, set `sendThrough` on the freedom outbound.

Nowhere 2 does not use `net` or `egress`. Setting either of them does not select Nowhere 3 — only `alpn: "nw3"` does, and on the nw2 stack both are rejected at startup.
