<div align="center">

```
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
          ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
```

**用 Rust 编写的门限 MPC 钱包研究原型**

[![CI](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml)

[English](README.md) | [中文](README.zh-CN.md)

</div>

> [!CAUTION]
> 未经审计的 Pre-Alpha 研究软件 · 仅限测试网 · 请勿用于真实资金。已知的严重限制（按类别）：(1) 受影响的签名方案类别 — 自行实现的门限 ECDSA 引擎不安全（unsound），且 Sr25519/BLS 签名并非门限签名；(2) 密钥生成期间的传输机密性；(3) 控制平面消息的新鲜性；(4) 签名策略未被强制执行 — 签名节点不会独立验证其所签署的内容；(5) 不安全的充值地址：代码裁剪（pre-cut）之前的版本为尚未实现的链导出的地址，以及为 FROST-TR 钱包显示的 P2WPKH 地址，可能无法花费；请勿向这些地址转入资金。
>
> 本警示以 [README.md](README.md) 中的英文原文为准。

---

## Vaultex 是什么？

Vaultex 是一个 Rust 工作区，用于探索可自托管的门限多方计算（MPC）钱包。每个签名节点持有一个密钥份额，网关通过 NATS 协调各节点，链相关的 crate 负责构建和编码交易。

设计目标是任何一方都不持有完整私钥。**当前 HEAD 的代码并非对所有签名方案都达到这一目标，也无法安全地托管资产。** 使用本仓库中的任何内容之前，请先阅读上方警示和下方的支持矩阵。

- **可用的部分：** 链交易编码器。对于六条链，编码结果在有官方参考实现的情况下与官方 SDK 输出逐字节一致，并已在公共测试网上产生经确认的交易。
- **不可用的部分：** 整体托管系统。其已知限制已在上方警示中按类别列出。本项目尚未经过任何独立安全审计或外部评审。
- **后续方向：** 参见 [docs/ROADMAP.md](docs/ROADMAP.md)（提议稿，等待所有者决策）和 [docs/TASKS.md](docs/TASKS.md)。提议中的首个支持范围是：基于一个经采用并锁定版本的门限 ECDSA 库的 TRON（TRX + TRC-20）签名器，其中每个节点都会验证自己所签署的内容。只有当路线图中的某个里程碑凭公开证据完成时，上方警示才会更改。

---

## 支持矩阵

本矩阵描述的是 HEAD 中的代码。

| 状态 | 含义 |
|---|---|
| **已支持（Supported）** | 在已发布的支持政策下可用于真实资金。**目前没有任何内容处于已支持状态。** |
| **预备（Staged）** | 已实现，并已在公共测试网上端到端运行过。仅限测试网。待影响它的限制修复后，可作为支持候选。 |
| **实验性（Experimental）** | 代码中存在，但未经验证、不安全或不完整。请勿依赖，也不要向它显示的任何地址转入资金。 |

### 链

任何链的主网均不受支持。

| 链 | 测试网络 | 资产 | 编码器证据 | 该证据所用的签名方案 | 状态 |
|---|---|---|---|---|---|
| TRON | Shasta 测试网 | TRX、TRC-20 | tronweb 参考向量；已确认的测试网交易 | 自行实现的 ECDSA（实验性，限制 1） | 预备 |
| Ethereum | Sepolia 测试网 | ETH、ERC-20 | viem 参考向量；已确认的测试网交易 | 自行实现的 ECDSA（实验性，限制 1） | 预备 |
| Bitcoin | 测试网，P2WPKH | BTC | 已确认的测试网交易 | 自行实现的 ECDSA（实验性，限制 1） | 预备。⚠ 不安全的充值地址（5）：为 FROST-TR 钱包显示的 P2WPKH 地址可能无法花费；请勿向这些地址转入资金 |
| Solana | Devnet | SOL、SPL 代币 | `@solana/spl-token` 参考向量；已确认的 devnet 交易 | FROST Ed25519 | 预备 |
| Sui | 测试网 | SUI、`Coin<T>` | `@mysten/sui` 参考向量；已确认的测试网交易 | FROST Ed25519 | 预备 |
| Aptos | 测试网 | APT、Coin、Fungible Asset | `@aptos-labs/ts-sdk` 参考向量；已确认的测试网交易 | FROST Ed25519 | 预备 |

代码中还列出了另外 44 条链，它们都没有端到端证据。

| 链 | 状态 |
|---|---|
| Ethereum 以外的 EVM 网络（25 条）：Polygon、BSC、Arbitrum、Optimism、Base、Avalanche、Linea、zkSync Era、Scroll、Mantle、Blast、Zora、Fantom、Gnosis、Cronos、Celo、Moonbeam、Ronin、opBNB、Immutable、Manta Pacific、Hyperliquid、Berachain、MegaETH、Monad | 实验性。⚠ 不安全的充值地址（5）：为这些链导出的地址可能无法花费；请勿向这些地址转入资金 |
| Bitcoin 主网、Litecoin、Dogecoin、Zcash | 实验性。⚠ 不安全的充值地址（5）：为这些链导出的地址可能无法花费；请勿向这些地址转入资金 |
| Polkadot、Kusama、Astar、Acala、Phala、Interlay | 实验性。⚠ 不安全的充值地址（5）：为这些链导出的地址可能无法花费；请勿向这些地址转入资金 |
| Cosmos Hub、Osmosis、Celestia、Injective、Sei | 实验性。⚠ 不安全的充值地址（5）：为这些链导出的地址可能无法花费；请勿向这些地址转入资金 |
| Movement、TON、Monero、Starknet | 实验性。⚠ 不安全的充值地址（5）：为这些链导出的地址可能无法花费；请勿向这些地址转入资金 |

### 签名方案

| 方案 | 来源 | 状态 | 说明 |
|---|---|---|---|
| GG20 门限 ECDSA（secp256k1） | 本仓库自行实现 | 实验性 | 不安全（限制 1）。将被删除或隔离（[ROADMAP §3.5](docs/ROADMAP.md#35-scope-cuts)） |
| CGGMP21 门限 ECDSA（secp256k1） | 本仓库自行实现 | 实验性 | 不安全（限制 1）。将被删除或隔离 |
| Stark 曲线门限 ECDSA | 本仓库自行实现 | 实验性 | 不安全（限制 1）。将被删除或隔离 |
| Sr25519 | 使用 `schnorrkel` | 实验性 | **并非门限签名**（限制 1）。将被删除或隔离 |
| BLS12-381 | 使用 `blst` | 实验性 | **并非门限签名**（限制 1）。将被删除或隔离 |
| FROST Ed25519 | 封装 ZF 的 `frost-ed25519` crate | 预备 | 受限制 2–4 影响 |
| FROST secp256k1 Taproot | 封装 ZF 的 `frost-secp256k1-tr` crate | 实验性 | ⚠ 不安全的充值地址（5）：为 FROST-TR 钱包显示的 P2WPKH 地址可能无法花费；请勿向这些地址转入资金 |
| `cggmp24`（LFDT-Lockness，锁定版本） | 上游库 | 尚未集成 | 提议用于替换自行实现的 ECDSA 引擎；决策待定（ROADMAP ADR-07） |

### 组件

| 组件 | 状态 | 说明 |
|---|---|---|
| 链交易编码器（上述六条预备链） | 预备 | 证据见链表格 |
| MPC 节点与网关（`services/`） | 实验性 | 受限制 2–4 影响。没有可用的多主机部署；网关的钱包注册表仅保存在内存中 |
| 策略引擎、审批、限速、RBAC/ABAC/MFA、审计账本 | 实验性（仅库代码） | 签名节点并不执行这些检查（限制 4） |
| 网关认证（密钥交换握手、会话 JWT、经 TLS 终止器的 mTLS、Bearer JWT） | 实验性 | 正在评估替换方案（ROADMAP ADR-09） |
| 加密密钥存储（Argon2id + AES-256-GCM） | 实验性 | 尚无备份或恢复工具 |
| 密钥刷新与重分享 | 实验性 | 基于自行实现的引擎（限制 1） |
| KMS、HSM、SGX/TEE | 未实现 | 仅有接口、桩代码和一个模拟实现 |
| 交易模拟与风险评分 | 实验性 | — |
| CLI（`mpc-wallet-cli`） | 实验性 | 单进程演示，所有参与方都在同一进程中运行。切勿用于真实资金 |
| 部署：Docker Compose、Kubernetes 清单、Helm、Terraform | 实验性 | 均无法启动可用的多主机集群 |

---

## 快速开始（仅限开发与测试网）

```bash
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

# 单元测试与集成测试（单进程，无需基础设施）
cargo test --workspace --features local-transport

# 单主机开发环境：Vault、Redis、NATS、三个 MPC 节点和网关
./scripts/local-infra.sh up
./scripts/local-infra.sh test    # 通过 NATS 进行端到端密钥生成与签名
./scripts/local-infra.sh down

# 单进程 CLI 演示
./scripts/demo.sh
```

测试使用的是测试规模的密码学参数。测试通过并不表明任何功能能在生产参数下或跨主机正常工作。

---

## 文档

| 文档 | 内容 |
|---|---|
| [路线图](docs/ROADMAP.md) | 生产路线图（提议稿），以及对当前状态的如实说明 |
| [任务清单](docs/TASKS.md) | 执行路线图的任务 |
| [安全政策](SECURITY.md) | 如何报告漏洞 |
| [CLI 指南](docs/CLI_GUIDE.md) | 单进程演示 CLI 的命令 |
| [API 参考](docs/API_REFERENCE.md) | 网关 REST API（实验性） |
| [架构](specs/ARCHITECTURE.md) | 架构说明。早于路线图编写，可能夸大成熟度 |
| [认证规范](specs/AUTH_SPEC.md) | 网关密钥交换握手（实验性） |
| [标准](specs/STANDARDS.md) | 代码引用的标准与参考文献 |
| [贡献指南](docs/CONTRIBUTING.md) | 贡献说明 |
| [更新日志](CHANGELOG.md) | 变更历史 |

较早的文档早于路线图，其中包括 [docs/SECURITY_FINDINGS.md](docs/SECURITY_FINDINGS.md) 和 [docs/SECURITY_AUDIT_AUTH.md](docs/SECURITY_AUDIT_AUTH.md) 中的内部安全记录，以及 [specs/CHAIN_ROADMAP.md](specs/CHAIN_ROADMAP.md) 中的链计划。这些安全记录由 AI Agent 在开发过程中编写，并非独立审计，其中的“已解决”状态并不涵盖上方警示中的限制。过时文档正在归档（ROADMAP M5 #10）。

---

## 项目结构

```
crates/
  mpc-wallet-core/     ← MPC 协议、传输层、密钥存储、策略、身份认证、RPC 消息
  mpc-wallet-chains/   ← 链提供器与交易编码器（见支持矩阵）
  mpc-wallet-cli/      ← 单进程演示 CLI
services/
  api-gateway/         ← REST 网关与协调器（不持有密钥份额）
  mpc-node/            ← 独立 MPC 节点（一个参与方，一个份额）
infra/                 ← Docker、本地开发环境、Kubernetes、Helm、Terraform（实验性）
scripts/               ← local-infra.sh、demo.sh 及辅助脚本
specs/、docs/、retro/  ← 规范、文档、决策记录与经验教训
```

---

## 安全

请按照 [SECURITY.md](SECURITY.md) 中的说明私下报告漏洞。请勿为安全问题创建公开 issue。

---

## 许可证

本仓库目前尚未包含许可证文件，因此本 README 不授予任何许可。许可证正在确定中（ROADMAP M5 #2）。Cargo 清单中的 `license` 字段早于此说明，将与许可证文件一并更正。

---

<p align="center">
  <sub>
    由 <a href="https://claude.com/claude-code">Claude Code</a> AI Agent 团队构建。
  </sub>
</p>
