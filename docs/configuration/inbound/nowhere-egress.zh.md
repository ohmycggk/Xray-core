# Nowhere Egress 入站

协议名 `nowhere-egress`。这是 Nowhere 3 出口桥。它不监听 Nowhere 流量：通过 QUIC 拨号一个处于出口模式的 Portal，注册成为该 Portal 的唯一出口，再经本机 Xray 路由转发 Portal 送来的 flow。

Portal 侧使用入站 `nowhere`，并设置 `net: "udp"`、`egress: true`。同一时刻只接受一个注册。见 [Nowhere 入站](nowhere.zh.md)。

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

Xray 的入站对象仍然要求 `listen` 与 `port`。本协议不声明监听网络，这个地址不会被绑定，可以改成任意值。Portal 的地址和端口写在 `settings` 里。

## 字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `address` | 是 | Portal 地址，IP 或域名 |
| `port` | 是 | Portal 端口 |
| `password` | 是 | 恰好 32 个小写十六进制字符（`[0-9a-f]{32}`），按原始文本使用，必须与 Portal 一致 |
| `morph` | 否 | 在 QUIC 之下做密钥变换。省略为 `true`。不协商，必须与 Portal 一致 |
| `serverName` | 否 | TLS 校验名。省略且 `address` 为域名时，用 `address`。`address` 为 IP 时不会自动填入 |
| `pin` | 否 | 叶子证书 SHA-256，64 位小写十六进制。`none` 或省略表示不固定。设置后优先于证书链和域名校验 |
| `allowInsecure` | 否 | 跳过证书链与域名校验。自签且未使用 `pin` 时需要 `true` |

没有 `net`、`alpn`。这条入站只实现 Nowhere 3 的 QUIC 出口注册，ALPN 固定为 `nw3`，TLS 1.3 由协议自己完成。

## 注册与路由

Portal 已有出口时，本端会被告知繁忙，等待 3 秒后重试，不会抢占当前所有者。注册连接断开后，同样等待 3 秒再拨号，因此 Portal 重启或原出口离开后可以自动接管。

已注册的 flow 进入本机路由。本入站没有 `userLevel`，flow 的 policy 等级为 `0`。本入站上的 `sniffing` 不会被读取。

通往 Portal 的 QUIC 使用系统拨号，源地址由内核选择。本入站的 `streamSettings.sockopt` 和 `sendThrough` 都不作用到这条连接。`streamSettings` 可以省略。如果写了，`network` 保持 `tcp`，`security` 保持 `none`。

Portal 的 `listen` 请写 IP。省略或写成非 IP 时，QUIC 绑到 `0.0.0.0`，且 Portal 的 `port` 不能为 `0`。

Portal 未配置 `certificates` 时，每次启动更换内存自签证书（ECDSA P-256，DNS `nowhere.local`）。日志级别为 `info` 时，Portal 打印 `nowhere TLS certificate SHA-256 fingerprint:`，把该值写入 `pin`。已有证书文件时：

```bash
openssl x509 -in server.crt -outform DER | sha256sum
```

大写十六进制会被拒绝。
