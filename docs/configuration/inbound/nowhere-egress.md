# Nowhere Egress inbound

Protocol name: `nowhere-egress`. This is the Nowhere 3 exit bridge. It does not listen for Nowhere traffic. It dials a Portal that is in exit mode over QUIC, registers as that Portal's single exit, and serves the flows the Portal opens through local Xray routing.

On the Portal, use an inbound `nowhere` with `net: "udp"` and `egress: true`. The Portal accepts one registration at a time. See the [Nowhere inbound](nowhere.md).

```json
{
  "tag": "nw3-egress",
  "listen": "127.0.0.1",
  "port": 1,
  "protocol": "nowhere-egress",
  "settings": {
    "address": "203.0.113.10",
    "port": 443,
    "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "allowInsecure": true
  }
}
```

The Xray inbound object still requires `listen` and `port`. This protocol declares no listen network, so that address is not bound and any value is fine. The Portal address and port belong in `settings`.

## Fields

| Field | Required | Description |
| --- | --- | --- |
| `address` | Yes | Portal address, an IP or a domain |
| `port` | Yes | Portal port |
| `password` | Yes | Exactly 32 lowercase hexadecimal characters (`[0-9a-f]{32}`), used as raw text. Must match the Portal |
| `morph` | No | Key transform under QUIC. Omitted means `true`. Not negotiated; must match the Portal |
| `serverName` | No | TLS verification name. If omitted and `address` is a domain, `address` is used. An IP `address` is not copied in |
| `pin` | No | SHA-256 of the leaf certificate, 64 lowercase hex characters. `none` or omitted disables pinning. When set, the pin overrides certificate-chain and name checks |
| `allowInsecure` | No | Skip certificate-chain and name checks. Required for a self-signed certificate when `pin` is not set |

There is no `net` or `alpn`. This inbound implements only the Nowhere 3 QUIC exit registration. ALPN is fixed to `nw3`, and the protocol performs its own TLS 1.3.

## Registration and routing

If the Portal already has an exit, this side is told the exit is busy, waits 3 seconds, and retries. It does not preempt the current owner. After the registration drops, it waits 3 seconds and dials again, so a restarted Portal or a departed exit is picked up without operator action.

Registered flows enter local routing. This inbound has no `userLevel`; the flow policy level is `0`. `sniffing` on this inbound is not read.

The QUIC connection to the Portal is a system dial. The kernel chooses the source address. `streamSettings.sockopt` and `sendThrough` on this inbound do not apply to that connection. `streamSettings` may be omitted. If set, keep `network` at `tcp` and `security` at `none`.

On the Portal, write `listen` as an IP. An omitted or non-IP `listen` makes QUIC bind `0.0.0.0`, and the Portal `port` must not be `0`.

When the Portal has no `certificates`, each start replaces the in-memory self-signed certificate (ECDSA P-256, DNS `nowhere.local`). At log level `info` the Portal prints `nowhere TLS certificate SHA-256 fingerprint:`. Put that value in `pin`. For an existing certificate file:

```bash
openssl x509 -in server.crt -outform DER | sha256sum
```

Uppercase hex is rejected.
