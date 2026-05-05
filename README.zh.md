# ceres_wallet_frost_mpc

面向 Solana MPC 钱包的 FROST-Ed25519 2-of-2 门限签名库。

纯密码学原语 — 不含 session 管理、异步运行时和网络层。集成层由上层应用负责。

本库是 [dkls23](https://github.com/silence-laboratories/dkls23) 的 Ed25519/Solana 等价实现：功能完全对齐，算法不同。

[English](README.md)

## 功能

| 功能 | 描述 |
|------|------|
| **Keygen** | 3 轮分布式密钥生成（FROST DKG） |
| **Sign** | 2 轮门限签名（FROST Schnorr 签名） |
| **Recovery** | 3 轮密钥刷新 — 轮换 share，验证密钥不变 |
| **Export** | Lagrange 2-of-2 标量重建，还原原始 Ed25519 私钥 |
| **Backup** | AES-256-GCM + HKDF-SHA256 加密 keyshare，用于安全备份 |

## 协议设计

2-of-2 门限方案，所有操作都需要双方参与。

- 客户端：`Identifier(1)`
- 服务端：`Identifier(2)`

所有轮函数都是纯函数 — 接受输入，返回输出，session 状态由调用方管理。

## 使用方式

在 `Cargo.toml` 中添加：

```toml
[dependencies]
ceres_wallet_frost_mpc = { git = "https://github.com/SauceWu/ceres_wallet_frost_mpc.git" }
```

### 密钥生成（3 轮）

```rust
use ceres_wallet_frost_mpc::{keygen_part1, keygen_part2, keygen_part3};

// 服务端第 1 轮 — 无需客户端输入
let (state, srv_r1_encoded) = keygen_part1(&mut rng)?;

// 服务端第 2 轮 — 接收客户端第 1 轮消息
let (state, srv_r2_encoded) = keygen_part2(state, &client_r1_encoded)?;

// 服务端第 3 轮 — 接收客户端第 2 轮消息，生成密钥包
let (key_package, public_key_package) = keygen_part3(state, &client_r2_encoded)?;
```

### 签名（2 轮）

```rust
use ceres_wallet_frost_mpc::{sign_part1, sign_part2};

// 服务端第 1 轮 — 生成 nonce commitment
let (state, srv_r1_encoded) = sign_part1(&key_package, message_hash, &mut rng)?;

// 服务端第 2 轮 — 接收客户端 commitment，返回 signing_package + sig_share
let srv_r2_encoded = sign_part2(state, &client_r1_encoded, &key_package)?;
// 客户端聚合双方 sig_share，产出最终 Schnorr 签名
```

### 密钥恢复 / Share 轮换（3 轮）

```rust
use ceres_wallet_frost_mpc::{recovery_part1, recovery_part2, recovery_part3};

let (state, srv_r1_encoded) = recovery_part1(key_package, public_key_package, &mut rng)?;
let (state, srv_r2_encoded) = recovery_part2(state, &client_r1_encoded)?;
let (new_key_package, new_public_key_package) = recovery_part3(state, &client_r2_encoded)?;
// 验证密钥不变，只有 share 发生变化
```

### 私钥导出

通过 Lagrange 插值，从两份 share 中重建原始 Ed25519 私钥标量。

```rust
use ceres_wallet_frost_mpc::{build_share_envelope, export_private_key};

let local_share = build_share_envelope(&client_key_package, &public_key_package)?;
let server_share = build_share_envelope(&server_key_package, &public_key_package)?;

let result = export_private_key(&local_share, &server_share)?;
// result.private_key — 64 字符十六进制字符串（32 字节 Ed25519 标量）
// result.exported    — true
```

### 备份与恢复

```rust
use ceres_wallet_frost_mpc::{derive_backup_envelope, decrypt_backup_share};

let backup = derive_backup_envelope(&share_envelope, "用户备份密码", "2026-01-01")?;
let recovered = decrypt_backup_share(&backup, "用户备份密码")?;
```

## Wire 格式

轮函数之间通过不透明的 `base64(json({...}))` 字符串传递消息，字段名协议稳定：

| 轮次 | 字段 |
|------|------|
| keygen r1 | `round1_pkg`（hex） |
| keygen r2 | `round2_pkg`（hex） |
| recovery r1 | `refresh_round1_pkg`（hex） |
| recovery r2 | `refresh_round2_pkg`（hex） |
| sign r1 | `commitments`（hex） |
| sign r2 | `signing_pkg`（hex），`sig_share`（hex） |

ShareEnvelope v2 格式：
```
base64( json({ "v": 2, "curve": "ed25519", "share": base64( json({ "kp": base64(...), "pkp": base64(...) }) ) }) )
```

## 安全说明

- `export_private_key` 会进行防御性校验：`scalar × G == verifying_key`，不匹配则返回错误。
- 备份每次使用随机 12 字节 nonce，对同一 share 多次加密会产生不同密文。
- HKDF info 字符串：`ceres-mpc-backup-v1`。
- 本库不内置"只导出一次"的策略锁，调用方需自行实现该逻辑。

## 依赖

| Crate | 用途 |
|-------|------|
| `frost-ed25519` v3 | FROST 门限签名协议 |
| `curve25519-dalek` v4 | 私钥导出所需的 Ed25519 标量运算 |
| `aes-gcm` | AES-256-GCM 备份加密 |
| `hkdf` + `sha2` | 备份密钥派生 |
| `serde` + `serde_json` | 消息序列化 |
| `base64` + `hex` | Wire 编码 |
| `rand` | Nonce 与随机数 |

## 许可证

MIT
