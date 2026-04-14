# PQC TLS/HTTP3 Benchmark Framework

测试真实网络环境下抗量子密码算法（PQC）对 TLS 1.3 和 HTTP/3 协议性能的影响。

测量指标包括：RTT 延迟、各阶段握手时间、通信数据量、丢包率、吞吐量。

**GitHub**: https://github.com/flydolpin/pqc-application-test

---

## 功能特性

- **模块化算法架构** — 签名算法和密钥交换算法可独立替换，无需修改 TLS 或 benchmark 代码
- **TLS 1.3 Benchmark** — 测量使用 PQC 算法的 TLS 1.3 握手性能（开发中）
- **HTTP/3 (QUIC) Benchmark** — 测量 QUIC 协议下的 PQC 性能（Phase 2）
- **算法微基准** — 纯算法级别的 keygen/sign/verify/encaps/decaps 性能测试
- **多格式输出** — JSON、CSV、Console 三种结果输出格式
- **Docker 集成** — 一键构建含 liboqs + oqs-provider 的完整测试环境
- **42 种 KEM + 64 种签名算法** — 覆盖所有 liboqs 支持的算法

---

## 架构

```
┌──────────────────────────────────────────────────────────┐
│                   Benchmark Framework                     │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Benchmark   │  │   Metrics    │  │   Reporter     │  │
│  │  Orchestrator│  │  Collector   │  │ JSON/CSV/CLI   │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────────┘  │
│         │                 │                                │
├─────────┼─────────────────┼────────────────────────────────┤
│         │    Protocol Layer│                                │
│  ┌──────┴──────────────────┴───────────────────────────┐  │
│  │         TLS 1.3 / QUIC Client+Server               │  │
│  │  ┌────────────────┐  ┌────────────────────────────┐ │  │
│  │  │ Handshake Phase │  │  Byte Counter / BIO Filter │ │  │
│  │  │   Tracker       │  │  (msg_callback)           │ │  │
│  │  └────────────────┘  └────────────────────────────┘ │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         │                                  │
├─────────────────────────┼──────────────────────────────────┤
│            Crypto Abstraction Layer (vtable)               │
│  ┌──────────────────────┴──────────────────────────────┐  │
│  │              Crypto Factory                          │  │
│  │   pqc_factory_create_kem("ML-KEM-768")              │  │
│  │   pqc_factory_create_sig("ML-DSA-65")               │  │
│  └────────┬──────────┬──────────┬──────────┬───────────┘  │
│           │          │          │          │                │
│  ┌────────┴──┐ ┌─────┴────┐ ┌──┴───────┐ ┌┴────────────┐ │
│  │  liboqs   │ │  liboqs  │ │  OpenSSL │ │  Custom     │ │
│  │  KEM      │ │  SIG     │ │  Classic │ │  Backend    │ │
│  │  Backend  │ │  Backend │ │  Backend │ │  (pluggable)│ │
│  └───────────┘ └──────────┘ └──────────┘ └─────────────┘ │
└──────────────────────────────────────────────────────────┘
```

**设计原则**: 上层代码（TLS/Benchmark）通过 vtable 接口调用密码学操作，不直接依赖任何具体库。添加新后端只需实现 vtable 并注册到工厂。

---

## 目录结构

```
pqc/
├── include/pqc/              # 公共头文件
│   ├── pqc_types.h           # 基础类型、枚举、错误码
│   ├── pqc_kem.h             # KEM 抽象接口 (vtable)
│   ├── pqc_sig.h             # 签名抽象接口 (vtable)
│   ├── pqc_crypto_factory.h  # 算法工厂
│   ├── pqc_tls_client.h      # TLS 1.3 客户端
│   ├── pqc_tls_server.h      # TLS 1.3 服务端
│   ├── pqc_tls_handshake.h   # 握手阶段追踪
│   ├── pqc_benchmark.h       # Benchmark 编排器
│   ├── pqc_metrics.h         # 指标数据结构
│   ├── pqc_reporter.h        # 输出格式化
│   ├── pqc_config.h          # 配置文件解析
│   └── pqc_timer.h           # 高精度计时器
├── src/
│   ├── crypto/               # 密码学抽象层
│   │   ├── pqc_crypto_factory.c
│   │   └── backends/
│   │       ├── oqs_kem.c     # liboqs KEM 封装
│   │       ├── oqs_sig.c     # liboqs SIG 封装
│   │       ├── oqs_provider.c
│   │       └── classic.c     # RSA/ECDSA (占位)
│   ├── tls/                  # TLS 1.3 实现
│   ├── quic/                 # QUIC/HTTP3 (Phase 2)
│   ├── benchmark/            # Benchmark 核心逻辑
│   └── util/                 # 配置解析
├── tools/                    # CLI 工具
│   ├── pqc_list_algs.c       # 列出可用算法
│   ├── pqc_bench_algo.c      # 算法微基准测试
│   └── pqc_bench_tls.c       # TLS benchmark
├── configs/                  # 配置文件
│   ├── benchmark_tls.toml
│   └── profiles/             # NIST Level 预设
├── docker/                   # Docker 集成
│   ├── Dockerfile.base
│   ├── docker-compose.tls.yml
│   └── scripts/
├── tests/                    # 单元测试
└── CMakeLists.txt
```

---

## 支持的算法

### KEM（密钥交换）

| NIST Level | 算法 | 公钥大小 | 密文大小 |
|-----------|------|---------|---------|
| 1 | ML-KEM-512, Kyber512, BIKE-L1, FrodoKEM-640 | 800 - 9616 B | 768 - 9752 B |
| 2 | sntrup761 | 1158 B | 1039 B |
| 3 | **ML-KEM-768**, Kyber768, BIKE-L3, FrodoKEM-976, NTRU-HRSS-701 | 1138 - 15632 B | 1088 - 15792 B |
| 5 | ML-KEM-1024, Kyber1024, Classic-McEliece, FrodoKEM-1344 | 1568 - 1357824 B | 1568 - 21696 B |

### 签名算法

| NIST Level | 算法 | 公钥大小 | 最大签名 |
|-----------|------|---------|---------|
| 1 | Falcon-512, MAYO-1/2 | 897 - 4912 B | 186 - 752 B |
| 2 | ML-DSA-44, Dilithium2 | 1312 B | 2420 B |
| 3 | **ML-DSA-65**, Dilithium3 | 1952 B | 3309 B |
| 5 | ML-DSA-87, Falcon-1024 | 1793 - 2592 B | 1280 - 4627 B |

> 使用 `pqc_list_algs` 查看完整列表（42 KEM + 64 SIG）

---

## 快速开始

### 前置条件

- Docker Desktop（已安装并运行）
- Windows / Linux / macOS

### 1. 构建 Docker 镜像

```bash
# 拉取基础镜像（国内网络使用 daocloud 镜像）
docker pull docker.m.daocloud.io/library/ubuntu:24.04
docker tag docker.m.daocloud.io/library/ubuntu:24.04 ubuntu:24.04

# 构建项目（包含 liboqs + oqs-provider + benchmark 工具）
docker build --network host -t pqc-benchmark -f docker/Dockerfile.base .
```

构建包含三个阶段：
1. 编译 liboqs（约 2-3 分钟）
2. 编译 oqs-provider（约 30 秒）
3. 编译 benchmark 框架（约 10 秒）

### 2. 列出可用算法

```bash
docker run --rm pqc-benchmark pqc_list_algs
```

### 3. 算法微基准测试

```bash
# 测试 ML-KEM-768（NIST Level 3 KEM）
docker run --rm pqc-benchmark pqc_bench_algo kem ML-KEM-768 1000

# 测试 ML-DSA-65（NIST Level 3 签名）
docker run --rm pqc-benchmark pqc_bench_algo sig ML-DSA-65 1000

# 测试 FrodoKEM（对比性能）
docker run --rm pqc-benchmark pqc_bench_algo kem FrodoKEM-976-SHAKE 1000
```

### 4. 端到端 TLS Benchmark（开发中）

```bash
# 使用 Docker Compose 启动 server + client
cd docker
docker compose -f docker-compose.tls.yml up

# 或直接运行 benchmark 客户端
docker run --rm pqc-benchmark pqc_bench_tls \
  --kem ML-KEM-768 --sig ML-DSA-65 \
  --host pqc-server --port 4433 \
  --iterations 100 --format json \
  --output /opt/pqc/results/results.json
```

---

## 工具使用手册

### `pqc_list_algs` — 列出可用算法

列出系统中所有可用的 KEM 和签名算法及其参数大小。

```bash
docker run --rm pqc-benchmark pqc_list_algs
```

输出示例：
```
=== Available KEM Algorithms (42) ===
Name                           Backend    NIST Lvl       PK       SK       CT       SS
ML-KEM-768                     liboqs     3            1184     2400     1088       32
...

=== Available Signature Algorithms (64) ===
Name                           Backend    NIST Lvl       PK       SK   MaxSig
ML-DSA-65                      liboqs     3            1952     4032     3309
...
```

### `pqc_bench_algo` — 算法微基准测试

测量单个算法的 keygen / sign / verify / encaps / decaps 操作性能。

```bash
# 语法
pqc_bench_algo <kem|sig> <算法名称> [迭代次数]

# 示例
pqc_bench_algo kem ML-KEM-768 1000       # KEM: 测量 keygen/encaps/decaps
pqc_bench_algo sig ML-DSA-65 1000        # SIG: 测量 keygen/sign/verify
```

输出指标：
- **mean** — 平均耗时（纳秒/毫秒）
- **stdev** — 标准差

### `pqc_bench_tls` — TLS 1.3 Benchmark

对远程 TLS 服务器运行完整的握手 benchmark。

```bash
# 语法
pqc_bench_tls --kem <KEM算法> --sig <SIG算法> --host <地址> [选项]

# 选项
--config <path>       TOML 配置文件
--kem <alg>           KEM 算法名称
--sig <alg>           签名算法名称
--host <addr>         服务器地址
--port <num>          服务器端口 (默认 4433)
--iterations <num>    握手次数 (默认 100)
--format <fmt>        输出格式: json, csv, console
--output <path>       输出文件路径
```

---

## 配置文件

### `configs/benchmark_tls.toml`

```toml
[server]
host = "localhost"
port = 4433
ca_cert = "certs/CA.crt"
verify_peer = true

[benchmark]
iterations = 100
warmup = 10
throughput_test_bytes = 1048576   # 1 MB

[output]
format = "console"               # "json", "csv", "console"
path = ""                         # 空 = stdout

kem_algorithms = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
sig_algorithms = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
```

### 预设配置（`configs/profiles/`）

| 文件 | 说明 |
|------|------|
| `nist_l1.toml` | NIST Level 1 算法组合（~128-bit 安全性） |
| `nist_l3.toml` | NIST Level 3 算法组合（~192-bit 安全性） |
| `nist_l5.toml` | NIST Level 5 算法组合（~256-bit 安全性） |
| `hybrid.toml` | 经典+PQC 混合算法组合 |

---

## Benchmark 指标说明

### 握手阶段追踪

TLS 1.3 握手分为以下阶段，每阶段独立计时：

```
Client                          Server
  │                               │
  │─── ClientHello ──────────────>│  Phase 0: KEM 公钥发送
  │                               │
  │<── ServerHello ──────────────│  Phase 1: KEM 密封 (encaps)
  │<── Certificate ──────────────│  Phase 2: 证书链传输
  │<── CertificateVerify ────────│  Phase 3: SIG 签名验证
  │<── Finished ─────────────────│  Phase 4: 握手完成
  │                               │
  │─── Finished ─────────────────>│  Phase 5: Session Tickets
  │                               │
```

### 测量指标

| 指标 | 说明 | 单位 |
|------|------|------|
| `total_duration_ns` | 端到端握手总时间 | 纳秒 |
| `phase_mean_ns[7]` | 各阶段平均耗时 | 纳秒 |
| `total_bytes_sent` | 发送总字节数 | 字节 |
| `total_bytes_received` | 接收总字节数 | 字节 |
| `kem_pk_bytes` | KEM 公钥大小 | 字节 |
| `kem_ct_bytes` | KEM 密文大小 | 字节 |
| `sig_cert_bytes` | 证书链字节数 | 字节 |
| `sig_signature_bytes` | 签名字节数 | 字节 |
| `success_rate` | 握手成功率 | 百分比 |
| `packet_loss_rate` | 丢包率 | 百分比 |
| `throughput_mbps` | 握手后吞吐量 | Mbps |

### 输出格式

**JSON 输出**:
```json
{
  "kem_algorithm": "ML-KEM-768",
  "sig_algorithm": "ML-DSA-65",
  "iterations": 100,
  "success_rate": 1.00,
  "handshake_time": {
    "mean_ns": 2500000,
    "stdev_ns": 150000,
    "median_ns": 2400000
  },
  "bytes": { "avg_sent": 3200, "avg_received": 4500 },
  "packet_loss_rate": 0.001,
  "throughput_mbps": 850.5
}
```

**CSV 输出**:
```csv
kem_alg,sig_alg,iterations,success_rate,mean_ns,stdev_ns,median_ns,...
ML-KEM-768,ML-DSA-65,100,1.000,2500000,150000,2400000,...
```

---

## 开发指南

### 添加新的 PQC 后端

1. 在 `src/crypto/backends/` 下创建新文件，例如 `mybackend_kem.c`
2. 实现 `pqc_kem_vtable_t` 中所有函数指针
3. 在 `pqc_crypto_factory.c` 中注册新后端

```c
// mybackend_kem.c
static const pqc_kem_vtable_t mybackend_vtable = {
    .backend_name    = mybackend_name,
    .alg_name        = mybackend_alg_name,
    .keygen          = mybackend_keygen,
    .encaps          = mybackend_encaps,
    .decaps          = mybackend_decaps,
    // ... 其他函数
};

pqc_kem_t *pqc_mybackend_kem_create(const char *alg_name) {
    pqc_kem_t *kem = calloc(1, sizeof(pqc_kem_t));
    kem->vtable = &mybackend_vtable;
    kem->ctx = /* 你的后端状态 */;
    return kem;
}
```

### 添加新算法

新算法会随 liboqs 更新自动可用。如需手动添加：

1. 更新 `configs/algorithms.toml` 添加算法定义
2. 工厂通过 `pqc_factory_create_kem("算法名")` 自动查找可用后端

### 本地编译（需要 liboqs + OpenSSL 3）

```bash
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH=/path/to/liboqs
make -j$(nproc)
```

---

## 依赖版本

| 依赖 | 版本 | 说明 |
|------|------|------|
| liboqs | 0.15.0 | PQC 算法实现 |
| OpenSSL | 3.x | TLS 1.3, X.509 |
| oqs-provider | latest | OpenSSL 3 PQC provider |
| ngtcp2 | 1.5+ | QUIC 协议 (Phase 2) |

---

## 项目状态

| 功能 | 状态 |
|------|------|
| 密码学抽象层 (KEM/SIG vtable) | 已完成 |
| liboqs 后端 | 已完成 |
| 算法工厂 | 已完成 |
| 高精度计时器 | 已完成 |
| 指标收集与聚合 | 已完成 |
| 结果输出 (JSON/CSV/Console) | 已完成 |
| 算法微基准工具 | 已完成 |
| TOML 配置解析 | 基础完成 |
| Docker 集成 | 已完成 |
| TLS 客户端/服务端 (OpenSSL) | 开发中 |
| 握手阶段追踪 (msg_callback) | 开发中 |
| 端到端 TLS Benchmark | 开发中 |
| QUIC/HTTP3 支持 | Phase 2 |

---

## License

MIT
