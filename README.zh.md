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

- 参与方 1（客户端）：`Identifier(1)`
- 参与方 2（服务端）：`Identifier(2)`

所有轮函数**与参与方无关** — 双方调用相同的函数，传入各自的 `party_id`。函数为纯函数：接受输入，返回输出，session 状态由调用方管理。

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
# 锁定 tag（生产环境推荐）
ceres_wallet_frost_mpc = { git = "https://github.com/SauceWu/ceres_wallet_frost_mpc", tag = "v0.1.0" }

# 或跟踪分支
ceres_wallet_frost_mpc = { git = "https://github.com/SauceWu/ceres_wallet_frost_mpc", branch = "main" }

# 或锁定特定 commit
ceres_wallet_frost_mpc = { git = "https://github.com/SauceWu/ceres_wallet_frost_mpc", rev = "abc1234" }
```

## 使用方式

### 密钥生成（3 轮）

双方使用各自的 `party_id`（1 或 2）调用相同的函数，每轮结束后交换消息。

```rust
use ceres_wallet_frost_mpc::{keygen_part1, keygen_part2, keygen_part3};

// 第 1 轮：各方生成自己的 DKG 包
let (state, my_r1_encoded) = keygen_part1(party_id, &mut rng)?;

// 与对方交换 r1_encoded，然后：

// 第 2 轮：各方处理对方的 r1，生成自己的 r2
let (state, my_r2_encoded) = keygen_part2(state, &other_r1_encoded)?;

// 与对方交换 r2_encoded，然后：

// 第 3 轮：完成密钥生成，返回 (KeyPackage, PublicKeyPackage)
let (key_package, public_key_package) = keygen_part3(state, &other_r2_encoded)?;
```

### 签名（2 轮）

客户端（参与方 1）负责聚合，服务端（参与方 2）在第 2 轮充当协调者。

```rust
use ceres_wallet_frost_mpc::{sign_part1, sign_part2};

// 第 1 轮：各方生成 nonce commitment
let (state, my_r1_encoded) = sign_part1(&key_package, message_hash, &mut rng)?;

// 交换 r1_encoded，然后服务端执行第 2 轮：

// 第 2 轮（协调者）：构建 signing_package，生成自己的 sig_share
let srv_r2_encoded = sign_part2(state, &client_r1_encoded, &key_package)?;

// 客户端收到 srv_r2_encoded，解析 signing_package 和服务端 sig_share，
// 生成自己的 sig_share，聚合双方结果 → 最终 64 字节 Schnorr 签名。
```

`message_hash` 类型为 `[u8; 32]`，即待签名的 32 字节消息摘要（例如对 Solana 序列化交易消息取 SHA-256）。

### 密钥恢复 / Share 轮换（3 轮）

结构与 keygen 相同。验证密钥不变，只有 share 发生变化。

```rust
use ceres_wallet_frost_mpc::{recovery_part1, recovery_part2, recovery_part3};

// 第 1 轮：基于现有密钥包启动 refresh
let (state, my_r1_encoded) = recovery_part1(key_package, public_key_package, &mut rng)?;

// 交换 r1_encoded，然后：

// 第 2 轮
let (state, my_r2_encoded) = recovery_part2(state, &other_r1_encoded)?;

// 交换 r2_encoded，然后：

// 第 3 轮：完成 — 新 share，验证密钥不变
let (new_key_package, new_public_key_package) = recovery_part3(state, &other_r2_encoded)?;
```

### 私钥导出

通过 Lagrange 插值，从两份 share 中重建原始 Ed25519 私钥标量。

```rust
use ceres_wallet_frost_mpc::{build_share_envelope, export_private_key};

let local_share = build_share_envelope(&client_key_package, &public_key_package)?;
let server_share = build_share_envelope(&server_key_package, &public_key_package)?;

let result = export_private_key(&local_share, &server_share)?;
// result.private_key — 64 字符十六进制（32 字节 Ed25519 标量）
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
