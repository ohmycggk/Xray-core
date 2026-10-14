# Nowhere 出站

协议名 `nowhere`。这是 Nowhere 客户端，字段写在 `settings` 顶层，不是嵌套对象。

`alpn` 选择协议栈，客户端与服务端规则一致——没有单独的 version 字段：

| `alpn` | 协议栈 |
| --- | --- |
| 省略或 `"nw3"` | Nowhere 3（`nw3`）—— 默认 |
| `"nw2"`，或其它任意单个值 | Nowhere 2.2.1（`nw2`）—— 遗留栈 |

两套协议栈没有共同握手：单个出站只跑一套协议栈，另一套的字段会被拒绝。Nowhere 3 是默认栈，因此不写 `alpn` 就跑 nw3。Nowhere 2 为兼容 nw3 之前的对端而保留：把 `alpn` 设为 `"nw2"`（或自定义值）即可继续使用。本文以 Nowhere 3 为主，旧版见文末。

TLS 1.3 由协议自己完成。`streamSettings` 可以省略。如果写了，`network` 只能是 `tcp`，`security` 只能是 `none`。拨号走 Xray 出站 dialer，因此 `sockopt` 和该出站的 `sendThrough` 会作用到通往 Portal 的连接。

对端 Portal 的 `listen` 请写 IP。写成非 IP 或省略时，QUIC 绑到 `0.0.0.0`，且 QUIC 的 `port` 不能为 `0`。见 [入站](../inbound/nowhere.zh.md)。

## Nowhere 3

Nowhere 3 只协商 ALPN `nw3`。每个出站恰好一个传输，第一次使用时建立会话，之后的 flow 复用这条会话。`net` 省略或 `"tcp"` 时是 TLS over TCP，UDP 目标以 UoT 承载。`"udp"` 时是 QUIC，TCP 走 stream，UDP 走 DATAGRAM。不需要也不接受 `up` / `down`。

密钥必须与 Portal 一致，且恰好是 32 个小写十六进制字符（`[0-9a-f]{32}`）。这 32 个字符按原始文本使用，不会再做十六进制解码。

`morph` 不在带内协商。未写时 Nowhere 3 为开启，必须与 Portal 一致。

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

Portal 使用受信任证书时，去掉 `allowInsecure`，并设置与证书一致的 `serverName`。QUIC 时把 `net` 设为 `"udp"`，且 Portal 必须监听 UDP。

### 字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `address` | 是 | Portal 地址，IP 或域名 |
| `port` | 是 | Portal 端口 |
| `password` | 是 | 恰好 32 个小写十六进制字符 |
| `net` | 否 | `tcp` 或 `udp`。省略为 `tcp`。其它值会启动失败 |
| `morph` | 否 | 密钥变换。省略为 `true`。必须与 Portal 一致 |
| `serverName` | 否 | TLS 校验名。省略且 `address` 为域名时，用 `address`。`address` 为 IP 时不会自动填入 |
| `pin` | 否 | 叶子证书 SHA-256，64 位小写十六进制。`none` 或省略表示不固定。设置后优先于证书链和域名校验 |
| `allowInsecure` | 否 | 跳过证书链与域名校验。自签且未使用 `pin` 时需要 `true` |
| `userLevel` | 否 | 该出站连接超时使用的 policy 等级，默认 `0` |

Nowhere 3 会拒绝 `up`、`down`、`mux`、`pool`、`dial4`、`dial6`。ALPN 固定为 `nw3`。

Portal 未配置 `certificates` 时，每次启动更换内存自签证书（ECDSA P-256，DNS `nowhere.local`）。Nowhere 3 的 Portal 在日志级别 `info` 下打印 `nowhere TLS certificate SHA-256 fingerprint:`，把该值写入 `pin`。已有证书文件时：

```bash
openssl x509 -in server.crt -outform DER | sha256sum
```

大写十六进制会被拒绝。

## Nowhere 2

把 `alpn` 设为 `"nw2"` 或其它任意非 nw3 的单个值时，选择遗留的 Nowhere 2 栈。它不能与 Nowhere 3 互通。`password`、`morph`、`alpn` 必须与 Portal 一致。`up` / `down` 省略时都是 `tcp`。

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

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `address` | 是 | Portal 地址，IP 或域名 |
| `port` | 是 | Portal 端口 |
| `password` | 是 | 1–255 字节。不套用 Portal 入站的 32–64 小写十六进制规则 |
| `alpn` | 否 | 协议栈选择器。省略时默认 `nw2`，长度 1–255 字节，必须与 Portal 相同 |
| `up` / `down` | 否 | `tcp` 或 `udp`。省略为 `tcp`。任一方向为 `udp` 时，Portal 必须开启对应传输 |
| `mux` | 否 | `true` 启用 TLS Mux。只在会使用 TCP 时有意义；`udp` / `udp` 会规范为关闭 |
| `morph` | 否 | 省略为 `false`。必须与 Portal 一致 |
| `serverName` | 否 | 与 Nowhere 3 相同 |
| `pin` | 否 | 与 Nowhere 3 相同 |
| `allowInsecure` | 否 | 与 Nowhere 3 相同 |
| `pool` | 否 | 仅 `tcp` / `tcp` 且 `mux` 为 false 时有效，范围 0–256。省略或 `0` 表示不预热，按需拨号 |
| `userLevel` | 否 | 连接超时使用的 policy 等级，默认 `0` |

`mux` 为 true，或 `up` / `down` 任一为 `udp` 时，`pool` 必须为 `0` 或省略，否则启动失败。

| `up` ↓ / `down` → | `tcp` | `udp` |
| --- | --- | --- |
| `tcp` | TLS / TLS | TLS / QUIC |
| `udp` | QUIC / TLS | QUIC / QUIC |

普通出站上的 `dial4` / `dial6` 会启动失败。绑定通往 Portal 的拨号源地址，使用本出站的 `sendThrough`。这两个字段只在入站 `next` 上生效。绑定从本机再向外直连的源地址时，使用 freedom 出站的 `sendThrough`。

Nowhere 2 不使用 `net` 和 `egress`。填写它们不会选择 Nowhere 3——只有 `alpn: "nw3"` 会；在 nw2 栈上这两个字段会直接启动失败。
