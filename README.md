# SisyphusGate

> "推石上山，永不停歇" — 一款模块化蜜罐系统，实现恶意流量发现、攻击行为分析、智能路由分发、数据汇总记录的完整闭环。

## 架构

SisyphusGate 采用**"智能编排 + 成熟蜜罐"**混合架构：

- **SisyphusGate 自研层**：流量网关、攻击行为分析、蜜罐路由引擎、数据汇总 —— 负责智能编排与数据富化
- **成熟蜜罐层**：Cowrie（SSH/Telnet）、Endlessh（Tarpit）、SNARE/TANNER（HTTP）—— 负责专业协议模拟，独立 Docker 隔离运行

```
攻击者 → Gateway(外部端口) → 协议检测 → Analyzer(签名+频率+启发式)
                                              ↓
                                      Router(规则匹配)
                                              ↓
                   ┌──────────────────────────┼───────────────────────────┐
                   ↓                          ↓                           ↓
          Endlessh(Tarpit)           Cowrie(SSH/Telnet)           SNARE(HTTP)
          高频攻击消耗资源            中交互虚拟蜜罐                动态Web陷阱
                   │                          │                           │
                   └──────────────────────────┼───────────────────────────┘
                                              ↓
                              LogBridge(日志桥接→统一事件格式)
                                              ↓
                              Aggregator(JSONL/SQLite + GeoIP + 报告)
```

## 功能模块

| 模块 | 功能 | 说明 |
|------|------|------|
| **流量网关** | 多端口 TCP 监听、协议指纹识别、会话管理、TCP 代理 | 端口灵活可配 |
| **攻击行为分析** | 签名匹配、滑动窗口频率分析、启发式检测 | 输出 0-100 威胁评分 |
| **蜜罐路由** | 基于规则链的智能分发、Token Bucket 频率追踪 | 按优先级匹配，策略可配 |
| **SSH 蜜罐** | Cowrie 中交互 SSH/Telnet 蜜罐 | 完整协议栈 + SFTP + 虚拟文件系统 |
| **Tarpit** | Endlessh SSH Tarpit + 自研通用慢速消耗 | 极低资源消耗，上万并发 |
| **HTTP 蜜罐** | SNARE/TANNER AI 驱动动态响应 | 反指纹识别，可克隆真实网站 |
| **数据汇总** | 异步事件总线、JSONL/SQLite 存储、GeoIP 定位、日志桥接 | 统一事件 Schema |

## 路由策略

优先级由高到低：

1. **高频 SSH 攻击 → Endlessh Tarpit**：60秒内超过阈值次数的 SSH 连接，送入 Tarpit 消耗对方资源
2. **恶意 SSH/Telnet 流量 → Cowrie**：威胁评分 ≥ 30，送入 Cowrie 进行中交互欺骗
3. **恶意 HTTP 流量 → SNARE**：威胁评分 ≥ 30，送入 SNARE 进行动态 Web 陷阱
4. **高频恶意流量 → 通用 Tarpit**：跨协议高频攻击，通用慢速消耗
5. **IP 黑名单 → Endlessh**：手动标记的 IP 直接送入 Tarpit
6. **默认 → 仅记录**：低可疑度流量记录后断开

## 快速开始

### 方式一：使用预构建镜像（推荐，无需克隆仓库）

```bash
# 一行命令启动完整架构（amd64 / arm64 均支持）
docker compose -f https://raw.githubusercontent.com/sisyphusgate/sisyphusgate/main/docker-compose.yml up -d

# 或下载到本地后修改配置
curl -O https://raw.githubusercontent.com/sisyphusgate/sisyphusgate/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/sisyphusgate/sisyphusgate/main/.env
docker compose up -d
```

### 方式二：Docker Compose 一键部署（本地构建）

```bash
git clone https://github.com/sisyphusgate/sisyphusgate.git
cd sisyphusgate

# 一键启动整个服务架构（SisyphusGate + Cowrie + Endlessh）
docker compose up -d

# 查看运行状态
docker compose ps

# 查看 SisyphusGate 日志
docker compose logs -f sisyphusgate

# 启用 HTTP 蜜罐（可选）
docker compose --profile http_honeypot up -d
```

一条命令启动后，攻击端口即对外可用：

| 端口 | 协议 | 路由目标 |
|------|------|----------|
| 2222 | SSH | 恶意 → Cowrie，高频 → Endlessh |
| 2323 | Telnet | 恶意 → Cowrie |
| 8080 | HTTP | 恶意 → SNARE（需显式启用） |

可通过 `.env` 文件修改端口：

```bash
SISYPHUSGATE_SSH_PORT=2222
SISYPHUSGATE_TELNET_PORT=2323
SISYPHUSGATE_HTTP_PORT=8080
TARPIT_DELAY_MS=10000
```

### 方式三：手动安装（开发调试）

**环境要求**

- Python 3.11+
- Docker & Docker Compose（运行外部蜜罐）
- 操作系统：Linux

```bash
git clone https://github.com/sisyphusgate/sisyphusgate.git
cd sisyphusgate

# 安装 Python 包
pip install -e ".[dev]"

# 生成 SSH 主机密钥
python -m sisyphusgate gen-key

# 启动外部蜜罐
docker compose up -d cowrie endlessh

# 启动 SisyphusGate
python -m sisyphusgate run

# 或使用自定义配置
python -m sisyphusgate run --config /path/to/custom.yaml

# 查看报告
python -m sisyphusgate report

# 运行测试
python -m pytest tests/ -v
```

## 配置

### 核心配置项

```yaml
sisyphusgate:
  gateway:
    bind_address: "0.0.0.0"       # 监听地址
    ports:
      - port: 2222                 # SSH 蜜罐端口
        protocol: ssh
      - port: 2323                 # Telnet 蜜罐端口
        protocol: telnet
      - port: 8080                 # HTTP 蜜罐端口
        protocol: http

  analyzer:
    frequency:
      window_seconds: 60           # 频率分析窗口
      threshold: 10                # 高频攻击阈值

  external_honeypots:
    cowrie:
      enabled: true                # 启用 Cowrie SSH/Telnet 蜜罐
      mode: docker
      ssh_port: 2222               # 内部端口
      telnet_port: 2223
    endlessh:
      enabled: true                # 启用 Endlessh Tarpit
      mode: docker
      internal_port: 2224
    snare:
      enabled: false               # HTTP 蜜罐（默认关闭）
      mode: docker
      internal_port: 8081
```

### 环境变量覆盖

| 变量 | 对应配置 |
|------|----------|
| `SISYPHUSGATE_CONFIG` | 配置文件路径 |
| `SISYPHUSGATE_LOG_LEVEL` | 日志级别 |
| `SISYPHUSGATE_BIND_ADDRESS` | 网关绑定地址 |
| `SISYPHUSGATE_GEOIP_DB` | GeoIP 数据库路径 |

## 数据流

```
攻击者 → TCP连接 → Gateway(协议检测) → Analyzer(签名+频率+启发式分析)
                                              ↓
                                      Router(规则链匹配)
                                              ↓
                 ┌────────────────────────────┼──────────────────────┐
                 ↓                            ↓                      ↓
           Endlessh(Tarpit)           Cowrie(SSH/Telnet)      通用Tarpit
                 │                            │                      │
                 └────────────────────────────┼──────────────────────┘
                                              ↓
                              LogBridge(Cowrie JSON→统一事件格式)
                                              ↓
                              EventCollector(asyncio.Queue 事件总线)
                                              ↓
                          ┌───────────────────┴───────────────────┐
                          ↓                                       ↓
                   JSONL 日志文件                          SQLite 数据库
                   (按日期分割)                            (按需启用)
```

## 日志格式

### 统一事件 Schema

```json
{
    "timestamp": "2026-05-21T08:00:00",
    "event_type": "auth_success|auth_failed|command|connection|tarpit_enter|tarpit_exit|...",
    "source_ip": "203.0.113.42",
    "source_port": 54321,
    "source_country": "CN",
    "source_city": "Beijing",
    "destination_port": 2222,
    "protocol": "ssh|telnet|http|raw",
    "honeypot_type": "cowrie|endlessh|tarpit|snare",
    "session_id": "uuid",
    "threat_level": "low|medium|high|critical",
    "data": {}
}
```

### Cowrie 日志桥接

Cowrie 原生 JSON 日志自动桥接为 SisyphusGate 统一格式：

| Cowrie eventid | 转换后 event_type |
|----------------|-------------------|
| `cowrie.login.success` | `auth_success` |
| `cowrie.login.failed` | `auth_failed` |
| `cowrie.command.input` | `command` |
| `cowrie.session.file_download` | `file_download` |
| `cowrie.direct-tcpip.request` | `tunnel_request` |

## 安全措施

| 措施 | 说明 |
|------|------|
| Docker 独立隔离 | 蜜罐服务（Cowrie/Endlessh）与 SisyphusGate 主进程不共享进程空间 |
| 容器网络隔离 | `internal: true` 禁止蜜罐容器出站网络访问，杜绝 SSRF 和跳板攻击 |
| 只读文件系统 | 蜜罐容器文件系统设为只读（日志目录除外） |
| 禁止提权 | `no-new-privileges:true` 防止容器内提权 |
| 端口仅回环 | 蜜罐端口仅绑定 `127.0.0.1`，由 Gateway 代理对外暴露 |
| 资源限制 | cgroup 限制 CPU/内存，防止 DoS 耗尽宿主机资源 |
| 非 root 运行 | 蜜罐容器以非 root 用户运行 |

## 目录结构

```
sisyphusgate/
├── pyproject.toml                  # 项目配置与依赖
├── docker-compose.yml              # 外部蜜罐容器编排
├── config/
│   ├── default.yaml                # 默认配置
│   ├── ssh_filesystem.json         # SSH 虚拟文件系统（Cowrie 参考）
│   └── cowrie/                     # Cowrie 配置（挂载到容器）
├── src/sisyphusgate/
│   ├── __main__.py                 # CLI 入口
│   ├── app.py                      # 应用主类
│   ├── config.py                   # Pydantic 配置模型
│   ├── gateway/                    # 流量网关（TCP监听 + 协议检测 + 会话管理 + TCP代理）
│   ├── analyzer/                   # 攻击行为分析（签名 + 频率 + 启发式）
│   ├── router/                     # 蜜罐路由（规则引擎 + 频率追踪）
│   ├── honeypots/
│   │   ├── base.py                 # 蜜罐抽象基类
│   │   ├── registry.py             # 蜜罐注册中心
│   │   ├── tarpit/                 # 自研通用 Tarpit（非 SSH 协议补充）
│   │   └── external/               # 外部蜜罐集成（管理器 + 日志桥接）
│   ├── aggregator/                 # 数据汇总（事件总线 + JSONL/SQLite + GeoIP）
│   └── utils/                      # 公共工具
├── logs/                           # 日志输出目录
├── data/                           # SSH 密钥、SQLite、GeoIP 数据库
└── tests/                          # 测试套件
```

## CLI 命令

```bash
sisyphusgate run                    # 启动蜜罐系统
sisyphusgate run -c custom.yaml     # 使用自定义配置启动
sisyphusgate report                 # 生成汇总报告
sisyphusgate gen-key                # 生成 SSH 主机密钥
sisyphusgate geoip-update           # 更新 GeoIP 数据库
```

## GitHub Packages

预构建镜像托管于 GitHub Container Registry（GHCR），支持 amd64 和 arm64 架构：

```bash
# 拉取最新镜像
docker pull ghcr.io/sisyphusgate/sisyphusgate:latest

# 拉取特定版本
docker pull ghcr.io/sisyphusgate/sisyphusgate:v0.1.0

# 指定版本（major.minor）
docker pull ghcr.io/sisyphusgate/sisyphusgate:0.1
```

镜像标签策略：

| 标签 | 说明 |
|------|------|
| `latest` | 最新稳定版本 |
| `v*` | 语义化版本（完整版本号） |
| `0.1` | 主次版本号（自动更新补丁） |
| `sha-*` | 特定 commit SHA |

## CI/CD

项目使用 GitHub Actions 实现自动化：

| 工作流 | 触发条件 | 功能 |
|--------|----------|------|
| `CI` | push/PR 到 main/develop | 测试（3.11/3.12）、Lint、类型检查、安全扫描 |
| `CD` | CI 成功后推送 main/develop/tag | Docker 多平台构建（amd64/arm64）、Trivy 漏洞扫描、SBOM 生成 |
| `Release` | 推送 `v*` tag | GitHub Release 自动创建、Docker 镜像推送 |

发布新版本：

```bash
git checkout -b release/v0.2.0
# 更新版本号后提交
git tag v0.2.0
git push origin v0.2.0
```

## 依赖项

| 包 | 用途 |
|----|------|
| `pyyaml` | YAML 配置解析 |
| `pydantic` | 类型安全配置校验 |
| `geoip2` | IP 地理定位 |
| `structlog` | 结构化日志 |
| `cryptography` | SSH 密钥生成 |

## License

MIT