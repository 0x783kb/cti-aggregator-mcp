# 🛡️ cti-aggregator-mcp

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2%2B-green)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-0x783kb%2Fcti--aggregator--mcp-black)](https://github.com/0x783kb/cti-aggregator-mcp)

基于[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)的威胁情报聚合工具。自动聚合12类威胁情报数据源，为IP/域名/URL/文件哈希生成专业安全画像。

## ✨ 核心特性

- 🔄 **多源聚合**：VirusTotal、FOFA、AlienVault OTX等12类数据源
- 🤖 **双模式分析**：MCP快速判定+Agent深度归因
- 🚀 **批量处理**：IP/域名混合输入，并行查询
- 💻 **IDE集成**：Cursor / Windsurf / Trae / Claude Desktop
- 📊 **四步分析法**：解析 → 属性 → 威胁 → 资产
- 🔒 **OPSEC优先**：被动采集为主，IOC去毒处理

## 🔍 数据源

### 必须配置
| 模块 | 能力 |
|------|------|
| **VirusTotal** | 94+引擎检测、被动DNS、关联样本 |
| **FOFA** | 端口服务、Web指纹、SSL证书、JARM |

### 推荐配置
| 模块 | 能力 |
|------|------|
| **AlienVault OTX** | APT关联、MITRE ATT&CK映射 |
| **IPInfo** | 地理位置、ASN、VPN/Proxy检测 |
| **AbuseIPDB** | 置信度评分、攻击类型分布 |

### 免费使用（无需API Key）
| 模块 | 能力 |
|------|------|
| **ThreatFox** | 恶意家族IOC匹配 |
| **ICP Filing** | 中国大陆备案查询 |
| **RDAP / LocalWhois** | 域名注册信息 |
| **crt.sh** | SSL证书透明度、子域名 |
| **Shodan InternetDB** | 基础端口扫描 |
| **WebFingerprint** | HTTP Headers指纹 |
| **SSL Info** | OpenSSL证书探测 |

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

### 方式二：可编辑安装（推荐，支持`cti-aggregator-mcp`命令启动）

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

获取API Key：[VirusTotal](https://www.virustotal.com/gui/my-apikey) · [FOFA](https://fofa.info/api) · [OTX](https://otx.alienvault.com/api) · [IPInfo](https://ipinfo.io/signup)

## 💻 IDE集成

支持任何实现[MCP协议](https://modelcontextprotocol.io/)的客户端。配置文件本质相同 —— 告诉IDE「用什么命令启动MCP服务器」。

### WorkBuddy（推荐）

配置文件路径：**`~/.workbuddy/mcp.json`**（用户级，全项目复用）或`<项目目录>/.workbuddy/mcp.json`（项目级）。

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

> ⚠️ WorkBuddy读取的是`mcp.json`（**不带点前缀**），不是`.mcp.json`。

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

- Cursor：`Cmd+Shift+P` → "MCP: Show Servers" → 确认`cti-aggregator`
- Windsurf：`~/.codeium/windsurf/mcp_config.json`
- Claude Desktop：`~/Library/Application Support/Claude/claude_desktop_config.json`
- Trae：自动检测项目根目录MCP配置

### DeepSeek Harness (dsh)

通过官方插件`@deepseek-ai/dsh-mcp-client`接入（cordis.yml或`.dsh`工作区配置）：

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

Agent通过`mcp__cti-aggregator__investigate_ip`等`mcp__<server>__<tool>`形式调用。

## 🗣️ 使用方式

### MCP快速查询（直接调用）

适合快速判定，几秒内返回结构化报告：

```markdown
分析 IP 134.122.128.131
调查域名 co-journal163.com
这个哈希是否恶意：a260aa8f...
检查 URL https://evil.example.com
批量分析：1.1.1.1, example.com, 8.8.8.8
```

### Agent深度分析（自动路由）

包含MCP全部能力，额外提供MITRE ATT&CK映射、威胁归因、攻击时间线、狩猎策略：

```markdown
深度分析域名 whm.gidosdelicacy.com
追踪这个 IP 背后的攻击者
对这批 IOC 做完整归因分析
我们可能被入侵了，帮我应急响应
```

**路由规则**：主Agent自动判断 — 快速判定走MCP，深度/归因/批量走Agent。

### Agent配置

Agent提示词位于`agents/threat-intel-analyst.md`，包含完整的分析工作流、MITRE ATT&CK映射规则和报告模板。

**WorkBuddy**：将文件复制到`.workbuddy/agents/`目录即可。文件末尾已附CodeBuddy风格frontmatter（`model: auto` / `mcpServers: mcp-cti`等），无需手动添加。

**其他Agent框架**：将`agents/threat-intel-analyst.md`内容作为系统提示词注入，并确保Agent可调用cti-aggregator-mcp工具。

## 🦊 配套Skill

### `silver-fox-detector`（银狐网站识别）

专精识别仿冒/钓鱼网站，按2026-08银狐基础设施测绘数据（L1口径N=17,342）标定品牌库与阈值，**九规则+三层证据架构**评分。

| 文件 | 说明 |
|------|------|
| `skills/silver-fox-detector/SKILL.md` | Skill入口（触发词、九规则速查、执行流程、报告模板） |
| `skills/silver-fox-detector/references/detection-rules.md` | 完整判据与参数标定依据 |
| `skills/silver-fox-detector/references/brand-database.md` | 仿冒品牌库（~132条）+黑产供应链常量 |
| `skills/silver-fox-detector/scripts/detect.js` | Node.js检测引擎（独立可跑，也可require） |
| `skills/silver-fox-detector/scripts/mcpClient.js` | 可选：通过stdio调用cti-aggregator-mcp的client |

**部署形态（双轨制）**：

| 模式 | 依赖 | 数据来源 | 命令 |
|------|------|----------|------|
| **A. 独立（默认）** | 仅Node.js ≥ 14 | 自抓页面+RDAP.org+手动WHOIS | `node skills/silver-fox-detector/scripts/detect.js URL` |
| **B. 联动MCP** | Node.js+本项目`pip install -e .` | MCP `investigate_domain`工具 | `node skills/.../detect.js URL --use-mcp` |

<<<<<<< HEAD
两种模式**完全独立**——仓库里的`skills/silver-fox-detector/`目录也可直接`cp -r`到独立的银狐skill仓库发布。单文件目录就能跑。

**安装到WorkBuddy**：
=======
**安装到 WorkBuddy**：
>>>>>>> f8a0c27917b8d3ca7bcbc6e11071dba127e95636

```bash
# 独立模式（无需本 MCP 服务器）
cp -r skills/silver-fox-detector ~/.workbuddy/skills/

# 项目级（仅当前项目）
cp -r skills/silver-fox-detector .workbuddy/skills/
```

**触发词**：「检测网站/安全扫描/仿冒检测/钓鱼识别/网站风险评估/银狐检测/检查网站安全」。

## 🛠️ MCP工具

| 工具 | 参数 | 说明 |
|------|------|------|
| `investigate_ip` | `ip` | IP威胁情报报告 |
| `investigate_domain` | `domain` | 域名四步分析报告 |
| `investigate_hash` | `hash` | 文件哈希检测报告 |
| `investigate_url` | `url` | URL威胁分析报告 |
| `investigate_batch` | `targets` | 批量混合分析 |
| `resolve_domain_ips` | `domain` | 域名DNS解析 |
| `health_check` | - | 系统状态与API配置检查 |

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

Agent深度模式额外输出：MITRE ATT&CK映射 · 威胁归因 · 攻击时间线 · 威胁狩猎策略

## 🔐 传输模式与安全

**默认且推荐：`stdio`传输**（本地进程通信，不监听网络端口）

```bash
python server.py  # 自动以 stdio 启动，无端口暴露
```

`server.py`已硬编码`mcp.run(transport="stdio")`，防止误改HTTP transport。

### 为什么不用HTTP？

| 风险 | stdio | Streamable HTTP |
|------|-------|-----------------|
| 监听网络端口 | ❌ 无 | ✅ 默认8000+ |
| 攻击面 | 仅本机进程可达 | 端口可达的任意进程/网络 |
| 鉴权 | OS进程隔离 | 必须自己实现token/OAuth |
| 同机进程可连 | 否 | 是 |
| CORS/CSRF | 不适用 | 必须配置 |

### 远程访问的推荐做法

如需从其他机器调用，**优先用SSH隧道+stdio**，不要直接开HTTP：

```bash
# 远端：按 stdio 启动 MCP（默认行为）
python server.py

# 本地：通过 SSH 把远端的 stdio 隧道过来
ssh -L local_port:localhost:remote_port user@remote-host
```

### 如必须HTTP（含loopback风险自担）

需要自行加三层防护：

1. **绑定`127.0.0.1`**（绝不绑`0.0.0.0`）
2. **加token鉴权**（或NetworkPolicy/防火墙）
3. **走TLS**（自签证书也行，至少加密token）

任何一条缺失都等于把API Key暴露给本机任意进程。

## ❓ 常见问题

**Q: 端口信息少？** 未配Shodan Key时使用免费InternetDB，数据有限。配FOFA或Shodan可获取更多信息。

**Q: FOFA未启用？** 需同时配`FOFA_EMAIL` + `FOFA_API_KEY`。

**Q: 没有网站指纹？** 默认关闭主动采集（OPSEC）。`config.py`设置`fingerprint.active_scan = True`开启。

**Q: JARM不显示？** 需安装Salesforce开源[jarm](https://github.com/salesforce/jarm)命令行工具（`git clone https://github.com/salesforce/jarm.git && cd jarm && pip install -r requirements.txt`），或配置Shodan/FOFA API。

**Q: 域名解析为空？** 可能域名未配置DNS/已过期/查询超时。用`resolve_domain_ips`工具单独查看。

## 🔗 相关链接

- [MCP官方文档](https://modelcontextprotocol.io/)
- [VirusTotal API](https://developers.virustotal.com/reference)
- [FOFA API](https://fofa.info/api)
- [AlienVault OTX](https://otx.alienvault.com/help)

## 📄 许可证

MIT License

---

⭐ 有帮助请Star · 🐛 问题提[Issue](https://github.com/0x783kb/cti-aggregator-mcp/issues) · 💡 建议提[PR](https://github.com/0x783kb/cti-aggregator-mcp/pulls)
