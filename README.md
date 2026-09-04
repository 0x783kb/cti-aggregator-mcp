# 🛡️ cti-aggregator-mcp

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2%2B-green)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-0x783kb%2Fcti--aggregator--mcp-black)](https://github.com/0x783kb/cti-aggregator-mcp)

基于MCP的威胁情报聚合工具。自动查询13个独立情报源模块，为IP/域名/URL/文件哈希生成专业安全画像。

## ✨ 核心特性

- 🔄 **多源聚合**：VirusTotal、FOFA、AlienVault OTX 等 13 个情报源模块
- 🤖 **双模式分析**：MCP 快速判定 + Agent 深度归因
- 🚀 **批量处理**：IP/域名混合输入，并行查询
- 💻 **IDE 集成**：Cursor / Windsurf / Trae / Claude Desktop
- 📊 **四步分析法**：解析 → 属性 → 威胁 → 资产
- 🔒 **OPSEC 优先**：被动采集为主，IOC 去毒处理

## 🔍 数据源

### 必须配置
| 模块 | 能力 |
|------|------|
| **VirusTotal** | 94+ 引擎检测、被动 DNS、关联样本 |
| **FOFA** | 端口服务、Web 指纹、SSL 证书、JARM |

### 推荐配置
| 模块 | 能力 |
|------|------|
| **AlienVault OTX** | APT 关联、MITRE ATT&CK 映射 |
| **IPInfo** | 地理位置、ASN、VPN/Proxy 检测 |
| **AbuseIPDB** | 置信度评分、攻击类型分布 |

### 免费使用（无需 API Key）
| 模块 | 能力 |
|------|------|
| **ThreatFox** | 恶意家族 IOC 匹配 |
| **ICP Filing** | 中国大陆备案查询 |
| **RDAP / LocalWhois** | 域名注册信息 |
| **crt.sh** | SSL 证书透明度、子域名 |
| **Shodan InternetDB** | 基础端口扫描 |
| **WebFingerprint** | HTTP Headers 指纹 |
| **SSL Info** | OpenSSL 证书探测 |

## 📦 快速开始

### 方式一：源码运行

```bash
git clone https://github.com/0x783kb/cti-aggregator-mcp.git
cd cti-aggregator-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # 编辑填入 API Keys
python server.py
```

### 方式二：可编辑安装（推荐，支持 `cti-aggregator-mcp` 命令启动）

```bash
git clone https://github.com/0x783kb/cti-aggregator-mcp.git
cd cti-aggregator-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -e .               # 安装 pyproject.toml + 注册 cli 入口
cp .env.example .env           # 编辑填入 API Keys
cti-aggregator-mcp             # 等价于 python server.py
```

### 环境变量

```ini
# 必须
VT_API_KEY=your_vt_api_key
FOFA_EMAIL=your_email@example.com
FOFA_API_KEY=your_fofa_api_key

# 推荐
OTX_API_KEY=your_otx_key
IPINFO_API_KEY=your_ipinfo_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# 可选
SHODAN_API_KEY=your_shodan_api_key
```

获取 API Key：[VirusTotal](https://www.virustotal.com/gui/my-apikey) · [FOFA](https://fofa.info/api) · [OTX](https://otx.alienvault.com/api) · [IPInfo](https://ipinfo.io/signup)

## 💻 IDE 集成

支持任何实现 [MCP 协议](https://modelcontextprotocol.io/) 的客户端。配置文件本质相同 —— 告诉 IDE「用什么命令启动 MCP 服务器」。

### WorkBuddy（推荐）

配置文件路径：**`~/.workbuddy/mcp.json`**（用户级，全项目复用）或 `<项目目录>/.workbuddy/mcp.json`（项目级）。

```jsonc
{
  "mcpServers": {
    "cti-aggregator": {
      "command": "/path/to/cti-aggregator-mcp/.venv/bin/cti-aggregator-mcp",
      // 或者用源码启动："command": "/path/to/cti-aggregator-mcp/.venv/bin/python",
      //                 "args": ["/path/to/cti-aggregator-mcp/server.py"]
      "cwd": "/path/to/cti-aggregator-mcp"
    }
  }
}
```

> ⚠️ WorkBuddy 读取的是 `mcp.json`（**不带点前缀**），不是 `.mcp.json`。

### Cursor / Windsurf / Trae / Claude Desktop

配置文件添加：

```json
{
  "mcpServers": {
    "cti-aggregator": {
      "command": "/path/to/cti-aggregator-mcp/.venv/bin/python",
      "args": ["/path/to/cti-aggregator-mcp/server.py"],
      "cwd": "/path/to/cti-aggregator-mcp"
    }
  }
}
```

- Cursor：`Cmd+Shift+P` → "MCP: Show Servers" → 确认 `cti-aggregator`
- Windsurf：`~/.codeium/windsurf/mcp_config.json`
- Claude Desktop：`~/Library/Application Support/Claude/claude_desktop_config.json`
- Trae：自动检测项目根目录 MCP 配置

### DeepSeek Harness (dsh)

通过官方插件 `@deepseek-ai/dsh-mcp-client` 接入（cordis.yml 或 `.dsh` 工作区配置）：

```yaml
- id: mcp-cti
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: cti-aggregator
    transport: stdio
    command: /path/to/cti-aggregator-mcp/.venv/bin/python
    args:
      - /path/to/cti-aggregator-mcp/server.py
    cwd: /path/to/cti-aggregator-mcp
```

Agent 通过 `mcp__cti-aggregator__investigate_ip` 等 `mcp__<server>__<tool>` 形式调用。

## 🗣️ 使用方式

### MCP 快速查询（直接调用）

适合快速判定，几秒内返回结构化报告：

```markdown
分析 IP 134.122.128.131
调查域名 co-journal163.com
这个哈希是否恶意：a260aa8f...
检查 URL https://evil.example.com
批量分析：1.1.1.1, example.com, 8.8.8.8
```

### Agent 深度分析（自动路由）

包含 MCP 全部能力，额外提供 MITRE ATT&CK 映射、威胁归因、攻击时间线、狩猎策略：

```markdown
深度分析域名 whm.gidosdelicacy.com
追踪这个 IP 背后的攻击者
对这批 IOC 做完整归因分析
我们可能被入侵了，帮我应急响应
```

**路由规则**：主 Agent 自动判断 — 快速判定走 MCP，深度/归因/批量走 Agent。

### Agent 配置

Agent 提示词位于 `agents/threat-intel-analyst.md`，包含完整的分析工作流、MITRE ATT&CK 映射规则和报告模板。

**WorkBuddy**：将文件复制到 `.workbuddy/agents/` 目录即可。文件末尾已附 CodeBuddy 风格 frontmatter（`model: auto` / `mcpServers: mcp-cti` 等），无需手动添加。

**其他 Agent 框架**：将 `agents/threat-intel-analyst.md` 内容作为系统提示词注入，并确保 Agent 可调用 cti-aggregator-mcp 工具。

## 🛠️ MCP 工具

| 工具 | 参数 | 说明 |
|------|------|------|
| `investigate_ip` | `ip` | IP 威胁情报报告 |
| `investigate_domain` | `domain` | 域名四步分析报告 |
| `investigate_hash` | `hash` | 文件哈希检测报告 |
| `investigate_url` | `url` | URL 威胁分析报告 |
| `investigate_batch` | `targets` | 批量混合分析 |
| `resolve_domain_ips` | `domain` | 域名 DNS 解析 |
| `health_check` | - | 系统状态与 API 配置检查 |

## 📊 报告结构

```
🚨 核心预警摘要 + 风险等级
1️⃣ 解析 — DNS / 历史 / 被动解析
2️⃣ 属性 — 地理 / ASN / Whois / 备案
3️⃣ 威胁 — VT 评分 / OTX / ThreatFox / 恶意样本
4️⃣ 资产 — 端口 / 服务 / 指纹 / SSL / JARM
📊 风险评估矩阵（5 维度打分）
🎯 综合研判
📋 处置建议（立即 / 监控 / 狩猎）
📋 IOC 清单
```

Agent 深度模式额外输出：MITRE ATT&CK 映射 · 威胁归因 · 攻击时间线 · 威胁狩猎策略

## 🔐 传输模式与安全

**默认且推荐：`stdio` 传输**（本地进程通信，不监听网络端口）

```bash
python server.py  # 自动以 stdio 启动，无端口暴露
```

`server.py` 已硬编码 `mcp.run(transport="stdio")`，防止误改 HTTP transport。

### 为什么不用 HTTP？

| 风险 | stdio | Streamable HTTP |
|------|-------|-----------------|
| 监听网络端口 | ❌ 无 | ✅ 默认 8000+ |
| 攻击面 | 仅本机进程可达 | 端口可达的任意进程/网络 |
| 鉴权 | OS 进程隔离 | 必须自己实现 token/OAuth |
| 同机进程可连 | 否 | 是 |
| CORS/CSRF | 不适用 | 必须配置 |

### 远程访问的推荐做法

如需从其他机器调用，**优先用 SSH 隧道 + stdio**，不要直接开 HTTP：

```bash
# 远端：按 stdio 启动 MCP（默认行为）
python server.py

# 本地：通过 SSH 把远端的 stdio 隧道过来
ssh -L local_port:localhost:remote_port user@remote-host
```

### 如必须 HTTP（含 loopback 风险自担）

需要自行加三层防护：

1. **绑定 `127.0.0.1`**（绝不绑 `0.0.0.0`）
2. **加 token 鉴权**（或 NetworkPolicy / 防火墙）
3. **走 TLS**（自签证书也行，至少加密 token）

任何一条缺失都等于把 API Key 暴露给本机任意进程。

## ❓ 常见问题

**Q: 端口信息少？** 未配 Shodan Key 时使用免费 InternetDB，数据有限。配 FOFA 或 Shodan 可获取更多信息。

**Q: FOFA 未启用？** 需同时配 `FOFA_EMAIL` + `FOFA_API_KEY`。

**Q: 没有网站指纹？** 默认关闭主动采集（OPSEC）。`config.py` 设置 `fingerprint.active_scan = True` 开启。

**Q: JARM 不显示？** 需安装 Salesforce 开源 [jarm](https://github.com/salesforce/jarm) 命令行工具（`git clone https://github.com/salesforce/jarm.git && cd jarm && pip install -r requirements.txt`），或配置 Shodan/FOFA API。

**Q: 域名解析为空？** 可能域名未配置 DNS / 已过期 / 查询超时。用 `resolve_domain_ips` 工具单独查看。

## 🔗 相关链接

- [MCP 官方文档](https://modelcontextprotocol.io/)
- [VirusTotal API](https://developers.virustotal.com/reference)
- [FOFA API](https://fofa.info/api)
- [AlienVault OTX](https://otx.alienvault.com/help)

## 📄 许可证

MIT License

---

⭐ 有帮助请 Star · 🐛 问题提 [Issue](https://github.com/0x783kb/cti-aggregator-mcp/issues) · 💡 建议提 [PR](https://github.com/0x783kb/cti-aggregator-mcp/pulls)
