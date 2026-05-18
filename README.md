<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Stable-brightgreen.svg" alt="Status">
</p>

<p align="center">
  <a href="#-english">English</a> | 
  <a href="#-简体中文">简体中文</a> | 
  <a href="#-繁體中文">繁體中文</a>
</p>

---

# 🔍 DNSWatch

## 🇬🇧 English

### 🎉 Project Introduction

**DNSWatch** is a lightweight terminal DNS query monitoring and security analysis engine. It provides real-time DNS query tracking, suspicious domain detection, performance analysis, and a beautiful TUI dashboard - all with **zero external dependencies** beyond the Python standard library.

**Why DNSWatch?**
- 🔒 **Security First**: Detect malware domains, phishing, DNS tunneling, DGA domains, and typosquatting
- ⚡ **Lightweight**: Minimal dependencies, fast startup, low resource usage
- 📊 **Rich Analytics**: Comprehensive statistics, threat summaries, and performance reports
- 🎨 **Beautiful TUI**: Real-time terminal dashboard with rich visualizations
- 🛠️ **Developer Friendly**: Clean API, extensible architecture, well-documented

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔍 **DNS Resolution** | Query A, AAAA, MX, CNAME, TXT, NS records with configurable nameservers |
| 🛡️ **Threat Detection** | 10+ threat types including malware, phishing, DGA, DNS tunneling |
| 📊 **Real-time Monitoring** | Live TUI dashboard with query tracking and alerts |
| 📈 **Performance Analysis** | Response time metrics, P50/P95/P99 percentiles |
| 📋 **Batch Processing** | Resolve multiple domains in parallel |
| 📄 **Multi-format Reports** | JSON, Markdown, and HTML report generation |
| 🎯 **Zero Dependencies** | Core functionality works without external DNS libraries |

### 🚀 Quick Start

#### Requirements
- Python 3.8 or higher
- pip package manager

#### Installation

```bash
# Install from PyPI
pip install dnswatch

# Or install from source
git clone https://github.com/gitstq/DNSWatch.git
cd DNSWatch
pip install -e .
```

#### Basic Usage

```bash
# Resolve a domain
dnswatch resolve google.com

# Resolve with specific query type
dnswatch resolve github.com --type MX

# Analyze domain for threats
dnswatch analyze suspicious-domain.com

# Batch resolve multiple domains
dnswatch batch google.com github.com example.com --analyze

# Start monitoring dashboard
dnswatch monitor -d google.com -d github.com
```

### 📖 Detailed Usage Guide

#### 1. DNS Resolution

```bash
# Basic resolution
dnswatch resolve example.com

# Specify query type
dnswatch resolve example.com --type AAAA

# Use custom nameserver
dnswatch resolve example.com --nameserver 1.1.1.1

# Output as JSON
dnswatch resolve example.com --json
```

#### 2. Security Analysis

```bash
# Analyze a domain for threats
dnswatch analyze example.com

# Check for suspicious TLDs
dnswatch analyze free-domain.tk

# JSON output for integration
dnswatch analyze example.com --json
```

#### 3. Batch Processing

```bash
# Resolve multiple domains
dnswatch batch google.com github.com example.com

# With security analysis
dnswatch batch google.com github.com --analyze

# Save results to file
dnswatch batch domains.txt --output results.json
```

#### 4. Real-time Monitoring

```bash
# Start dashboard with specific domains
dnswatch monitor -d google.com -d github.com

# Load domains from file
dnswatch monitor --file domains.txt

# Custom refresh rate
dnswatch monitor -d example.com --refresh 2.0
```

### 💡 Design Philosophy

**Self-Developed Highlights:**
- **Pure Python Implementation**: Core DNS resolution using Python's socket module
- **Heuristic-Based Detection**: Multiple threat detection algorithms without external databases
- **Modular Architecture**: Separate monitor, analyzer, and detector components
- **Extensible Rules**: Custom threat detection rules via simple API

**Technology Choices:**
- **Rich Library**: For beautiful terminal UI and progress indicators
- **Click Framework**: For intuitive CLI with subcommands
- **Pydantic**: For robust data validation and settings management

### 📦 Build & Deployment

```bash
# Build package
pip install build
python -m build

# Run tests
pip install pytest
pytest tests/

# Generate coverage report
pytest --cov=dnswatch tests/
```

### 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'feat: add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🇨🇳 简体中文

### 🎉 项目介绍

**DNSWatch** 是一款轻量级终端DNS查询监控与安全分析引擎。提供实时DNS查询追踪、可疑域名检测、性能分析以及精美的TUI仪表盘——**零外部依赖**，开箱即用。

**为什么选择 DNSWatch？**
- 🔒 **安全优先**：检测恶意域名、钓鱼网站、DNS隧道、DGA域名、域名劫持等
- ⚡ **轻量高效**：最小依赖、快速启动、低资源占用
- 📊 **丰富分析**：全面的统计数据、威胁摘要、性能报告
- 🎨 **精美界面**：实时终端仪表盘，丰富的可视化效果
- 🛠️ **开发者友好**：清晰的API、可扩展架构、完善的文档

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔍 **DNS解析** | 查询A、AAAA、MX、CNAME、TXT、NS记录，支持自定义DNS服务器 |
| 🛡️ **威胁检测** | 10+种威胁类型，包括恶意软件、钓鱼、DGA、DNS隧道 |
| 📊 **实时监控** | 实时TUI仪表盘，查询追踪与告警 |
| 📈 **性能分析** | 响应时间指标、P50/P95/P99百分位统计 |
| 📋 **批量处理** | 并行解析多个域名 |
| 📄 **多格式报告** | JSON、Markdown、HTML报告生成 |
| 🎯 **零依赖** | 核心功能无需外部DNS库即可运行 |

### 🚀 快速开始

#### 环境要求
- Python 3.8 或更高版本
- pip 包管理器

#### 安装方式

```bash
# 从 PyPI 安装
pip install dnswatch

# 或从源码安装
git clone https://github.com/gitstq/DNSWatch.git
cd DNSWatch
pip install -e .
```

#### 基本使用

```bash
# 解析域名
dnswatch resolve google.com

# 指定查询类型
dnswatch resolve github.com --type MX

# 分析域名威胁
dnswatch analyze suspicious-domain.com

# 批量解析多个域名
dnswatch batch google.com github.com example.com --analyze

# 启动监控仪表盘
dnswatch monitor -d google.com -d github.com
```

### 📖 详细使用指南

#### 1. DNS解析

```bash
# 基础解析
dnswatch resolve example.com

# 指定查询类型
dnswatch resolve example.com --type AAAA

# 使用自定义DNS服务器
dnswatch resolve example.com --nameserver 1.1.1.1

# JSON格式输出
dnswatch resolve example.com --json
```

#### 2. 安全分析

```bash
# 分析域名威胁
dnswatch analyze example.com

# 检测可疑顶级域名
dnswatch analyze free-domain.tk

# JSON输出便于集成
dnswatch analyze example.com --json
```

#### 3. 批量处理

```bash
# 解析多个域名
dnswatch batch google.com github.com example.com

# 带安全分析
dnswatch batch google.com github.com --analyze

# 保存结果到文件
dnswatch batch domains.txt --output results.json
```

#### 4. 实时监控

```bash
# 启动仪表盘监控指定域名
dnswatch monitor -d google.com -d github.com

# 从文件加载域名列表
dnswatch monitor --file domains.txt

# 自定义刷新频率
dnswatch monitor -d example.com --refresh 2.0
```

### 💡 设计思路

**自研差异化亮点：**
- **纯Python实现**：核心DNS解析使用Python标准库socket模块
- **启发式检测**：多种威胁检测算法，无需外部数据库
- **模块化架构**：监控器、分析器、检测器独立组件
- **可扩展规则**：通过简单API添加自定义威胁检测规则

**技术选型原因：**
- **Rich库**：提供精美的终端UI和进度指示器
- **Click框架**：直观的CLI子命令结构
- **Pydantic**：健壮的数据验证和设置管理

### 📦 打包与部署

```bash
# 构建包
pip install build
python -m build

# 运行测试
pip install pytest
pytest tests/

# 生成覆盖率报告
pytest --cov=dnswatch tests/
```

### 🤝 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

### 📄 开源协议

本项目采用 MIT 协议开源 - 详见 [LICENSE](LICENSE) 文件。

---

## 🇹🇼 繁體中文

### 🎉 專案介紹

**DNSWatch** 是一款輕量級終端DNS查詢監控與安全分析引擎。提供即時DNS查詢追蹤、可疑網域檢測、效能分析以及精美的TUI儀表板——**零外部依賴**，開箱即用。

**為什麼選擇 DNSWatch？**
- 🔒 **安全優先**：檢測惡意網域、釣魚網站、DNS隧道、DGA網域、網域劫持等
- ⚡ **輕量高效**：最小依賴、快速啟動、低資源佔用
- 📊 **豐富分析**：全面的統計資料、威脅摘要、效能報告
- 🎨 **精美介面**：即時終端儀表板，豐富的視覺化效果
- 🛠️ **開發者友善**：清晰的API、可擴展架構、完善的文檔

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔍 **DNS解析** | 查詢A、AAAA、MX、CNAME、TXT、NS記錄，支援自訂DNS伺服器 |
| 🛡️ **威脅檢測** | 10+種威脅類型，包括惡意軟體、釣魚、DGA、DNS隧道 |
| 📊 **即時監控** | 即時TUI儀表板，查詢追蹤與告警 |
| 📈 **效能分析** | 回應時間指標、P50/P95/P99百分位統計 |
| 📋 **批次處理** | 平行解析多個網域 |
| 📄 **多格式報告** | JSON、Markdown、HTML報告生成 |
| 🎯 **零依賴** | 核心功能無需外部DNS庫即可執行 |

### 🚀 快速開始

#### 環境要求
- Python 3.8 或更高版本
- pip 套件管理器

#### 安裝方式

```bash
# 從 PyPI 安裝
pip install dnswatch

# 或從原始碼安裝
git clone https://github.com/gitstq/DNSWatch.git
cd DNSWatch
pip install -e .
```

#### 基本使用

```bash
# 解析網域
dnswatch resolve google.com

# 指定查詢類型
dnswatch resolve github.com --type MX

# 分析網域威脅
dnswatch analyze suspicious-domain.com

# 批次解析多個網域
dnswatch batch google.com github.com example.com --analyze

# 啟動監控儀表板
dnswatch monitor -d google.com -d github.com
```

### 💡 設計思路

**自研差異化亮點：**
- **純Python實現**：核心DNS解析使用Python標準庫socket模組
- **啟發式檢測**：多種威脅檢測演算法，無需外部資料庫
- **模組化架構**：監控器、分析器、檢測器獨立元件
- **可擴展規則**：透過簡單API新增自訂威脅檢測規則

### 📦 打包與部署

```bash
# 建構套件
pip install build
python -m build

# 執行測試
pip install pytest
pytest tests/
```

### 🤝 貢獻指南

歡迎貢獻程式碼！請遵循以下步驟：

1. Fork 本儲存庫
2. 建立特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交變更 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

### 📄 開源協議

本專案採用 MIT 協議開源 - 詳見 [LICENSE](LICENSE) 檔案。

---

<p align="center">
  Made with ❤️ by SOLO Agent
</p>
