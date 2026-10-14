# Nowhere inbound

Protocol name: `nowhere`. This is the Nowhere Portal. It accepts clients and either dispatches decrypted flows into Xray routing, or, in exit mode, hands them to the single registered Egress.

`alpn` selects the protocol stack, on both client and server — there is no separate version field:

| `alpn` | Stack |
| --- | --- |
| Omitted or `"nw3"` | Nowhere 3 (`nw3`) — the default |
| `"nw2"`, or any other single value | Nowhere 2.2.1 (`nw2`) — the legacy stack |

The two stacks share no handshake: a single inbound runs exactly one stack, and the fields of the other stack are rejected. Nowhere 3 is the default, so a configuration that sets no `alpn` runs nw3. Nowhere 2 is kept for compatibility with pre-nw3 peers: set `alpn` to `"nw2"` (or a custom value) to keep it. This page leads with Nowhere 3. The legacy stack is at the end.

The protocol performs its own TLS 1.3. `streamSettings` may be omitted. If set, `network` must be `tcp` and `security` must be `none`. `sockopt` applies to the QUIC listener, and also to the system dial used by a Nowhere 2 `next` hop.

## Nowhere 3

Nowhere 3 serves ALPN `nw3` only. Each inbound uses exactly one transport. An omitted `net`, or `"tcp"`, is TLS over TCP, and UDP flows are carried as UoT. `"udp"` is QUIC: one connection carries streams and DATAGRAMs.

The key must match the client and be exactly 32 lowercase hexadecimal characters (`[0-9a-f]{32}`). Those characters are the raw key text. They are not hex-decoded again. `openssl rand -hex 16` produces one.

`morph` is not negotiated in band. When omitted, Nowhere 3 turns it on. If one side enables it and the other does not, the handshake cannot complete.

TCP:

```json
{
  "tag": "nw3-in",
  "listen": "0.0.0.0",
  "port": 443,
  "protocol": "nowhere",
  "settings": {
    "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"]
  }
}
```

QUIC. The firewall must allow UDP on this port. `networks` may be omitted; if set, it must be `["udp"]`.

```json
{
  "tag": "nw3-in",
  "listen": "0.0.0.0",
  "port": 443,
  "protocol": "nowhere",
  "settings": {
    "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "net": "udp"
  }
}
```

With `egress` left off, decrypted TCP and UDP enter Xray routing, and inbound `sniffing` still applies. `userLevel` is the policy level of that flow. The default is `0`.

### Fields

| Field | Required | Description |
| --- | --- | --- |
| `password` | Yes | Exactly 32 lowercase hexadecimal characters |
| `net` | No | `tcp` or `udp`. Omitted means `tcp`. Any other value fails startup |
| `morph` | No | Key transform. Omitted means `true` |
| `networks` | No | Must match `net`, or be omitted. `tcp` allows only `["tcp"]`; `udp` allows only `["udp"]` |
| `certificates` | No | PEM certificate and private key, as a pair. Omitted generates an in-memory self-signed certificate on every start |
| `egress` | No | `true` turns this Portal into an exit bridge and requires `net: "udp"`. See [Egress](nowhere-egress.md) |
| `userLevel` | No | Policy level of routed flows. Default `0`. Unused when `egress` is `true` |

Nowhere 3 rejects `alpn` and `next`. ALPN is fixed to `nw3`, and Nowhere 3 has no Portal chain.

When `egress` is `true`, this inbound does not dispatch flows to the local router. It accepts one Egress registration and forwards every authenticated flow there. A second Egress is told the exit is busy and retries on its own; it does not preempt the current owner. After the connection drops, a waiting Egress can take over. `sniffing` on this inbound does not apply to those flows.

### Listen address

With `net: "tcp"`, Xray accepts the TCP listener. `listen` and `port` behave like any other inbound.

With `net: "udp"`, Nowhere listens for QUIC on that same address. `streamSettings.network` must not be `udp`. `port` must not be `0`. Write `listen` as an IP. If `listen` is omitted, or set to a non-IP such as `localhost`, QUIC binds `0.0.0.0` on the same port. Any other domain is rejected while the inbound config is built.

## Certificates and pin

Without `certificates`, every process start generates an in-memory self-signed certificate: ECDSA P-256, DNS `nowhere.local`, plus `127.0.0.1` and `::1`, valid for about 365 days. A restart replaces it.

A Nowhere 3 Portal prints this at log level `info`:

```text
nowhere TLS certificate SHA-256 fingerprint: <64 lowercase hex characters>
```

Put that value in the client `pin`. For an existing certificate file:

```bash
openssl x509 -in server.crt -outform DER | sha256sum
```

The digest must be lowercase. Uppercase is rejected. `pin` is 64 lowercase hex characters; `none` or omitted disables pinning. When set, the pin overrides certificate-chain and name checks.

`certificates` uses the Xray certificate object. The certificate and key may be files or arrays of PEM lines:

```json
"certificates": [
  {
    "certificateFile": "/etc/xray/server.crt",
    "keyFile": "/etc/xray/server.key"
  }
]
```

## Nowhere 2

Setting `alpn` to `"nw2"`, or to any other single non-nw3 value, selects the legacy Nowhere 2 stack. It cannot interoperate with Nowhere 3. `password`, `morph`, and `alpn` must match on the server and the client.

```json
{
  "tag": "nw2-in",
  "listen": "0.0.0.0",
  "port": 443,
  "protocol": "nowhere",
  "settings": {
    "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "alpn": "nw2",
    "networks": ["tcp", "udp"]
  }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `password` | Yes | 32–64 lowercase hexadecimal characters. Odd lengths are allowed. The text is used raw: no percent-decoding and no hex decoding |
| `alpn` | No | The stack selector. Default `nw2` when omitted, length 1–255 bytes. Both ends must match |
| `networks` | No | `tcp`, `udp`, or both. Omitted enables both. Duplicates or other values fail startup. Case-insensitive |
| `morph` | No | Omitted means `false`. Not negotiated; the peer must match |
| `certificates` | No | Same as Nowhere 3. When omitted, each start still generates an in-memory self-signed certificate |
| `userLevel` | No | Policy level of routed flows. Default `0` |
| `next` | No | Next Portal. When set, this inbound no longer uses routing |

When `networks` includes `udp`, the QUIC listen rules above apply: `port` must not be `0`, `listen` should be an IP, and an omitted or non-IP listen binds `0.0.0.0`. A UDP-only inbound still must not set `streamSettings.network` to `udp`. At log level `info` the line `nowhere QUIC listening on ...` appears.

Without `next`, decrypted flows enter routing and `sniffing` applies. With `next`, every flow from this inbound is forwarded to the next Nowhere 2 Portal. There is no fallback, and neither `sniffing` nor routing rules apply. `next` uses a system dial and does not pass through another outbound. If `next.alpn` is omitted, it inherits this inbound's ALPN.

`next` uses the same fields as a Nowhere 2 [outbound](../outbound/nowhere.md), and this is where `dial4` / `dial6` bind the dial source. `auto` or omitted lets the kernel choose; otherwise they must be an IPv4 and an IPv6 literal respectively. `next.password` must also be 32–64 lowercase hexadecimal characters.

```json
"next": {
  "address": "origin.example",
  "port": 443,
  "password": "0123456789abcdef0123456789abcdef",
  "alpn": "nw2",
  "up": "tcp",
  "down": "tcp",
  "serverName": "origin.example"
}
```

Nowhere 2 does not use `net` or `egress`. Setting either of them does not select Nowhere 3 — only `alpn: "nw3"` does, and on the nw2 stack both are rejected at startup.
