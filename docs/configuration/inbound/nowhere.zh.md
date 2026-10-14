# Nowhere 入站

协议名 `nowhere`。这是 Nowhere Portal：接受客户端，把解密后的 flow 送进 Xray 路由，或在出口模式下交给唯一已注册的 Egress。

`alpn` 选择协议栈，客户端与服务端规则一致——没有单独的 version 字段：

| `alpn` | 协议栈 |
| --- | --- |
| 省略或 `"nw3"` | Nowhere 3（`nw3`）—— 默认 |
| `"nw2"`，或其它任意单个值 | Nowhere 2.2.1（`nw2`）—— 遗留栈 |

两套协议栈没有共同握手：单个入站只跑一套协议栈，另一套的字段会被拒绝。Nowhere 3 是默认栈，因此不写 `alpn` 就跑 nw3。Nowhere 2 为兼容 nw3 之前的对端而保留：把 `alpn` 设为 `"nw2"`（或自定义值）即可继续使用。本文以 Nowhere 3 为主，旧版见文末。

TLS 1.3 由协议自己完成。`streamSettings` 可以省略。如果写了，`network` 只能是 `tcp`，`security` 只能是 `none`。其中的 `sockopt` 会用于 QUIC 监听；Nowhere 2 的 `next` 系统拨号也会用到它。

## Nowhere 3

Nowhere 3 只服务 ALPN `nw3`，每个入站恰好一个传输。`net` 省略或 `"tcp"` 时是 TLS over TCP，UDP 流量以 UoT 承载。`"udp"` 时是 QUIC，同一条连接承载 stream 与 DATAGRAM。

密钥必须与客户端一致，且恰好是 32 个小写十六进制字符（`[0-9a-f]{32}`）。这 32 个字符按原始文本使用，不会再做十六进制解码。例如 `openssl rand -hex 16`。

`morph` 不在带内协商。未写时 Nowhere 3 为开启。一端开、另一端不开时握手无法完成。

TCP：

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

QUIC。防火墙必须放通该端口的 UDP。`networks` 可以省略；如果写了，只能是 `["udp"]`。

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

`egress` 留空时，解密后的 TCP 与 UDP 进入 Xray 路由，入站 `sniffing` 依旧生效。`userLevel` 是该 flow 的 policy 等级，默认 `0`。

### 字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `password` | 是 | 恰好 32 个小写十六进制字符 |
| `net` | 否 | `tcp` 或 `udp`。省略为 `tcp`。其它值会启动失败 |
| `morph` | 否 | 密钥变换。省略为 `true` |
| `networks` | 否 | 必须与 `net` 一致，或省略。`tcp` 只允许 `["tcp"]`；`udp` 只允许 `["udp"]` |
| `certificates` | 否 | PEM 证书与私钥，成对提供。省略时每次启动生成内存自签证书 |
| `egress` | 否 | `true` 把该 Portal 变成出口桥，并要求 `net: "udp"`。见 [Egress](nowhere-egress.zh.md) |
| `userLevel` | 否 | 进入路由的 flow 的 policy 等级，默认 `0`。`egress` 为 `true` 时不使用 |

Nowhere 3 会拒绝 `alpn` 和 `next`。ALPN 固定为 `nw3`，且 Nowhere 3 没有 Portal 链。

`egress` 为 `true` 时，该入站不再把 flow 送给本地路由，而是接受一个 Egress 注册，把每个通过认证的 flow 转发过去。第二个 Egress 会被告知出口忙并自行重试，不会抢占当前归属者。连接断开后，等待中的 Egress 可以接管。该入站上的 `sniffing` 对这些 flow 不生效。

### 监听地址

`net: "tcp"` 时由 Xray 接受 TCP 监听，`listen` 与 `port` 与其它入站一致。

`net: "udp"` 时由 Nowhere 在同一地址上监听 QUIC。`streamSettings.network` 不能是 `udp`，`port` 不能为 `0`。`listen` 请写 IP。省略或写成 `localhost` 这类非 IP 时，QUIC 在同一端口绑到 `0.0.0.0`；写成其它域名会在构建入站配置时报错。

## 证书与 pin

未配置 `certificates` 时，每次进程启动都会生成内存自签证书：ECDSA P-256，DNS `nowhere.local`，外加 `127.0.0.1` 与 `::1`，有效期约 365 天。重启即更换。

Nowhere 3 的 Portal 在日志级别 `info` 下打印：

```text
nowhere TLS certificate SHA-256 fingerprint: <64 位小写十六进制>
```

把该值写入客户端的 `pin`。已有证书文件时：

```bash
openssl x509 -in server.crt -outform DER | sha256sum
```

摘要必须小写，大写会被拒绝。`pin` 是 64 位小写十六进制；`none` 或省略表示不固定。设置后优先于证书链和域名校验。

`certificates` 使用 Xray 的证书对象，证书与私钥可以是文件，也可以是 PEM 行数组：

```json
"certificates": [
  {
    "certificateFile": "/etc/xray/server.crt",
    "keyFile": "/etc/xray/server.key"
  }
]
```

## Nowhere 2

把 `alpn` 设为 `"nw2"` 或其它任意非 nw3 的单个值时，选择遗留的 Nowhere 2 栈。它不能与 Nowhere 3 互通。`password`、`morph`、`alpn` 必须在服务端与客户端一致。

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

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `password` | 是 | 32–64 位小写十六进制字符，允许奇数长度。文本按原样使用：不做百分号解码，也不做十六进制解码 |
| `alpn` | 否 | 协议栈选择器。省略时默认 `nw2`，单个字符串，长度 1–255 字节，两端必须一致 |
| `networks` | 否 | `tcp`、`udp` 或两者。省略时两者都开。重复或其它值会启动失败。大小写不敏感 |
| `morph` | 否 | 省略为 `false`。不协商；对端必须一致 |
| `certificates` | 否 | 与 Nowhere 3 相同。省略时每次启动同样生成内存自签证书 |
| `userLevel` | 否 | 进入路由的 flow 的 policy 等级，默认 `0` |
| `next` | 否 | 下一个 Portal。设置后该入站不再走路由 |

`networks` 含 `udp` 时，同样适用上面的 QUIC 监听规则：`port` 不能为 `0`，`listen` 建议写 IP，省略或非 IP 时绑 `0.0.0.0`。只开 UDP 的入站依然不能把 `streamSettings.network` 设成 `udp`。日志级别 `info` 下会出现 `nowhere QUIC listening on ...`。

没有 `next` 时，解密后的 flow 进入路由并应用 `sniffing`。有 `next` 时，该入站的每个 flow 都转发给下一个 Nowhere 2 Portal。没有回退，`sniffing` 与路由规则都不生效。`next` 使用系统拨号，不经过其它出站。`next.alpn` 省略时继承该入站的 ALPN。

`next` 使用的字段与 Nowhere 2 [出站](../outbound/nowhere.zh.md) 相同，`dial4` / `dial6` 也在这里绑定拨号源地址。`auto` 或省略由内核选择；否则必须分别是 IPv4 与 IPv6 字面量。`next.password` 同样必须是 32–64 位小写十六进制字符。

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

Nowhere 2 不使用 `net` 和 `egress`。填写它们不会选择 Nowhere 3——只有 `alpn: "nw3"` 会；在 nw2 栈上这两个字段会直接启动失败。
