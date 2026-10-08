# WAES-256 cipher + AES-256 cascade

> [!WARNING]
> **Non-standard build addition, for study only.** The cipher methods here are
> **not** wire-compatible with stock Shadowsocks / VLESS / VMess / Trojan — use
> this build on **both** ends. WAES-256 is an experimental, unvetted, non-constant-time
> wide-block AES variant (256-bit block/key); do not use it to protect real
> traffic. For production use a standard cipher.

## What this package is

A pure-Go port of WAES-256 — AES's 4×4 state with every cell widened from 8 to
16 bits, giving a 256-bit block and 256-bit key, 14 rounds, AES key schedule.
It exposes:

- `NewCipher` — the WAES-256 block cipher (`crypto/cipher.Block`).
- `NewAEAD` — a `cipher.AEAD` built as WAES-256-CTR + HMAC-SHA256
  (encrypt-then-MAC), since GCM requires a 128-bit block and WAES-256's is
  256-bit.
- `NewCascadeAEAD` — the **AES-256-CTR → WAES-256 cascade** `cipher.AEAD`
  (described below); this is what the proxy integrations use.

Reference vector `E(0²⁵⁶, 0²⁵⁶)`:

```
43e012f37fcfa47852c843208a39e873f99d617ec43660f217aefed7dad9ed53
```

## The AES-256 + WAES-256 cascade (`NewCascadeAEAD`)

Each record/chunk is encrypted in **two layers**:

```
plaintext ──AES-256-CTR──▶ ──WAES-256 (CTR + HMAC-SHA256)──▶ wire
            (inner)            (outer, authenticates)
```

So the bytes on the wire are `WAES-256(AES-256-CTR(data))`. The inner AES-256
layer provides confidentiality; the outer WAES-256 AEAD adds a second cipher
layer and the single authentication tag (encrypt-then-MAC). Two independent
subkeys are derived from the session key, so the layers never share key
material. The cascade keeps a **12-byte nonce and 16-byte tag** (overhead 16),
so it is a drop-in `cipher.AEAD` wherever AES-256-GCM is used — the surrounding
framing is unchanged.

Four integrations consume `NewCascadeAEAD` — Shadowsocks, VLESS Encryption,
VMess, and Trojan:

### Shadowsocks

`proxy/shadowsocks` adds it as the AEAD cipher method `waes-256-gcm`
(alias `aead_waes_256_gcm`). Use the **same `method` and `password` on both
ends**. Both TCP and UDP are supported.

**Server** (`server.json`):

```json
{
  "inbounds": [{
    "protocol": "shadowsocks",
    "listen": "0.0.0.0",
    "port": 8388,
    "settings": {
      "method": "waes-256-gcm",
      "password": "MyStrongPassword123",
      "network": "tcp,udp"
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

**Client** (`client.json`) — exposes a local SOCKS proxy on `127.0.0.1:1080`:

```json
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "settings": { "udp": true }
  }],
  "outbounds": [{
    "protocol": "shadowsocks",
    "settings": {
      "servers": [{
        "address": "SERVER_IP",
        "port": 8388,
        "method": "waes-256-gcm",
        "password": "MyStrongPassword123"
      }]
    }
  }]
}
```

**Run:**

```sh
xray run -c server.json -test   # validate config
xray run -c server.json         # on the server
xray run -c client.json         # on the client

curl -x socks5h://127.0.0.1:1080 https://example.com/   # send traffic through it
```

### VLESS Encryption

`proxy/vless/encryption`'s `NewAEAD` builds the cascade, so VLESS-Encryption
records — both the handshake framing and the data records — are sealed with
`WAES-256(AES-256-CTR(...))`. The 32-byte BLAKE3-derived key, 12-byte
incrementing nonce, 16-byte tag, key ratcheting, and TLS-record-style framing
are all unchanged; only the underlying AEAD differs. This makes VLESS
Encryption in this build incompatible with stock builds — run it on both ends.

#### Using VLESS + REALITY + the WAES-256 cascade

REALITY (transport security) and VLESS Encryption (proxy-layer) are independent
config dimensions, so they compose: enabling the `encryption`/`decryption`
fields engages the WAES-256 cascade *inside*, while REALITY wraps it *outside*.
Data is then `REALITY-TLS( WAES-256( AES-256-CTR(data) ) )`.

Generate the keys:

```sh
xray vlessenc   # prints a matching "decryption" (server) + "encryption" (client) pair
xray x25519     # REALITY: PrivateKey (server) + Password/PublicKey (client)
xray uuid       # a client UUID
```

**Server** — VLESS inbound, REALITY, and `decryption`:

```json
{
  "inbounds": [{
    "protocol": "vless",
    "listen": "0.0.0.0",
    "port": 443,
    "settings": {
      "clients": [{ "id": "YOUR-UUID" }],
      "decryption": "mlkem768x25519plus.native.600s.<server-key-from-vlessenc>"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "target": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "privateKey": "<reality-private-key>",
        "shortIds": [""]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

**Client** — VLESS outbound with the matching `encryption` and REALITY:

```json
{
  "inbounds": [{ "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings": { "udp": true } }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "SERVER_IP",
        "port": 443,
        "users": [{
          "id": "YOUR-UUID",
          "encryption": "mlkem768x25519plus.native.0rtt.<client-key-from-vlessenc>"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "www.microsoft.com",
        "publicKey": "<reality-public-key>",
        "shortId": "",
        "fingerprint": "chrome"
      }
    }
  }]
}
```

Notes:
- Leave `flow` empty — `xtls-rprx-vision` splices the raw TLS stream and
  conflicts with the encryption wrapper.
- `decryption`/`encryption` must be one matching pair from a single
  `xray vlessenc` run; the REALITY keypair is separate (`xray x25519`).
- Use port 443 in production (REALITY warns about other ports / the GFW).

### VMess

VMess selects its body cipher with the `security` field; set it to
`waes-256` on the **client** outbound user (the server accepts whatever the
client negotiates). Same UUID on both ends.

**Server** (`server.json`):

```json
{
  "inbounds": [{
    "protocol": "vmess",
    "listen": "0.0.0.0",
    "port": 8500,
    "settings": { "clients": [{ "id": "YOUR-UUID" }] }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

**Client** (`client.json`) — `security: "waes-256"` engages the cascade:

```json
{
  "inbounds": [{ "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings": { "udp": true } }],
  "outbounds": [{
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "SERVER_IP",
        "port": 8500,
        "users": [{ "id": "YOUR-UUID", "security": "waes-256" }]
      }]
    }
  }]
}
```

Generate a UUID with `xray uuid`. Run with `xray run -c server.json` /
`xray run -c client.json`, then send traffic to the client's SOCKS proxy.

### Trojan

Trojan is TLS-only and has no native cipher, so the cascade is an **opt-in
inner layer** enabled by the `encryption` account field (default off). Set
`"encryption": "waes-256"` on **both** ends; same password. Production Trojan
also needs a TLS/REALITY transport — omitted here for a minimal example.
(Encryption does not combine with Trojan `fallbacks`.) Client and server
clocks must agree within 90 seconds: the client's first record carries its
time, and the server rejects stale or replayed connections.

**Server** (`server.json`):

```json
{
  "inbounds": [{
    "protocol": "trojan",
    "listen": "0.0.0.0",
    "port": 8600,
    "settings": { "clients": [{ "password": "MyStrongPassword123", "encryption": "waes-256" }] }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

**Client** (`client.json`):

```json
{
  "inbounds": [{ "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings": { "udp": true } }],
  "outbounds": [{
    "protocol": "trojan",
    "settings": {
      "servers": [{
        "address": "SERVER_IP",
        "port": 8600,
        "password": "MyStrongPassword123",
        "encryption": "waes-256"
      }]
    }
  }]
}
```

## How to build

This package uses only the Go standard library. Building the full `xray`
binary requires the Go version pinned in the repo's `go.mod` (Go 1.26+).

```sh
# from the repository root
go build -o xray ./main

# test just this package (reference vector, S-box, AEAD, cascade)
go test ./common/crypto/waes256/

# test the integrations
go test ./proxy/shadowsocks/ ./proxy/vless/encryption/ ./proxy/vmess/... ./proxy/trojan/
```

## Source layout

| File | Contents |
|------|----------|
| `waes256.go` | WAES-256 block cipher (`cipher.Block`) — S-box, ShiftRows, table-free MixColumns, key schedule. |
| `aead.go` | `NewAEAD` — WAES-256-CTR + HMAC-SHA256 `cipher.AEAD`. |
| `cascade.go` | `NewCascadeAEAD` — AES-256-CTR + WAES-256 cascade `cipher.AEAD`. |
| `waes256_test.go` | Reference vector, round-trip, S-box and AEAD tests. |
| `reference_test.go` | The original 4×4-state implementation, kept as an oracle; the optimized cipher is checked against it. Benchmarks. |

Consumers of `NewCascadeAEAD`:
- `proxy/shadowsocks/cascade.go` — the `waes-256-gcm` method.
- `proxy/vless/encryption/common.go` — `NewAEAD` (VLESS records).
- `proxy/vmess/encoding/{client,server}.go` — the `waes-256` VMess `security`.
- `proxy/trojan/encryption.go` — the opt-in `encryption: "waes-256"` layer.
