import asyncio
import logging
import os
import re
import socket
from typing import List, Dict, Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# 加载环境变量 —— 必须在导入 config / providers 之前，
# 否则 config.py 顶部读取 os.getenv 时拿不到 .env 中的密钥。
load_dotenv()

# 导入插件模块
from providers import (virustotal, virustotal_hash, virustotal_url, threatfox, portscan)
from providers import get_providers
from providers.base import format_result, validate_ip_address, validate_domain_name, ProviderError, error_to_result
from utils.cache import TTLCache
from utils.report_generator import generate_report, generate_hash_report, generate_url_report
from config import CACHE_ENABLED, CACHE_TTL, setup_logging

# 配置日志（统一使用 config 中的日志配置，包含 httpx 日志降噪）
setup_logging()
logger = logging.getLogger(__name__)

# 初始化缓存
global_cache = TTLCache(default_ttl=CACHE_TTL) if CACHE_ENABLED else None
if CACHE_ENABLED:
    logger.info(f"本地缓存已启用 (TTL: {CACHE_TTL}s)")

# 初始化 Server
mcp = FastMCP("cti-aggregator")


# query_type -> provider 方法名
_QUERY_METHOD = {
    "ip": "query_ip",
    "domain": "query_domain",
    "hash": "query_hash",
    "url": "query_url",
}


async def execute_provider_queries(client: httpx.AsyncClient, target: str,
                                   query_type: str = "ip") -> List[Dict[str, Any]]:
    """根据 query_type 从注册表取出 provider 并行查询。

    通过 zip(task, result) 绑定 provider 模块名，异常处理优先识别 ProviderError。
    """
    method_name = _QUERY_METHOD.get(query_type)
    if not method_name:
        return []

    # 构造 (短名, coroutine) 对，避免后续靠 traceback 字符串匹配 provider 名
    task_pairs = []
    for name, provider in get_providers(query_type):
        method = getattr(provider, method_name, None)
        if method is None:
            continue
        try:
            task_pairs.append((name, method(client, target)))
        except Exception as e:
            logger.error(f"创建 {name} 任务失败: {e}")
            task_pairs.append((name, _immediate_error(name, e)))

    if not task_pairs:
        return []

    coros = [t for _, t in task_pairs]
    results = await asyncio.gather(*coros, return_exceptions=True)

    processed = []
    for (mod_name, _), result in zip(task_pairs, results):
        if isinstance(result, BaseException):
            logger.error(f"{mod_name} 查询异常: {result}", exc_info=True)
            processed.append(error_to_result(mod_name, result))
        else:
            processed.append(result)
    return processed


def _immediate_error(provider_name: str, exc: Exception):
    """构造一个返回 error dict 的协程，用于 provider 任务创建失败场景。"""

    async def _coro():
        return format_result(provider_name, error=f"task creation failed: {exc}")
    return _coro()


@mcp.tool()
async def investigate_ip(ip: str) -> str:
    """
    [多源聚合] 调查 IP 地址。
    查询 VirusTotal 信誉、关联样本、Shodan/FOFA 端口、AlienVault OTX 情报。
    返回 Markdown 格式的聚合报告。
    """
    logger.info(f"开始调查 IP 地址: {ip}")

    # 检查缓存
    if global_cache:
        cache_key = f"report_ip_{ip}"
        cached_report = await global_cache.get(cache_key)
        if cached_report:
            logger.info(f"命中缓存: {ip}")
            return cached_report

    try:
        # 增加超时时间以适应大量关联数据的查询
        async with httpx.AsyncClient(timeout=60.0) as client:
            results = await execute_provider_queries(client, ip, "ip")
            report = generate_report(ip, results, "ip")

            # 写入缓存
            if global_cache:
                await global_cache.set(cache_key, report)

            logger.info(f"IP 地址 {ip} 调查完成")
            return report
    except Exception as e:
        logger.error(f"调查 IP 地址 {ip} 失败: {e}", exc_info=True)
        return f"# ❌ 调查失败\n\n错误信息: {str(e)}"


@mcp.tool()
async def investigate_domain(domain: str) -> str:
    """
    [多源聚合] 调查域名。
    执行四步分析法：1.解析(DNS/历史) -> 2.属性(Whois/备案) -> 3.威胁(信誉/样本) -> 4.资产(指纹/证书)。
    """
    logger.info(f"开始调查域名: {domain}")

    # 检查缓存
    if global_cache:
        cache_key = f"report_domain_{domain}"
        cached_report = await global_cache.get(cache_key)
        if cached_report:
            logger.info(f"命中缓存: {domain}")
            return cached_report

    try:
        # 增加超时时间以适应大量关联数据的查询
        async with httpx.AsyncClient(timeout=60.0) as client:
            results = await execute_provider_queries(client, domain, "domain")
            vt_ips: List[str] = []
            try:
                for r in results:
                    if r.get("source") == "VirusTotal" and r.get("status") == "success":
                        data = r.get("data", {})
                        resolved = data.get("resolved_ips", [])
                        vt_ips = [ip.get("ip", ip) if isinstance(ip, dict) else ip for ip in resolved]
                        break
            except Exception:
                vt_ips = []
            if not vt_ips:
                try:
                    _, _, addr_list = socket.gethostbyname_ex(domain)
                    vt_ips = list(dict.fromkeys(addr_list))
                except Exception:
                    vt_ips = []
            if vt_ips:
                try:
                    ps = await portscan.query_ip(client, vt_ips[0])
                    results.append(ps)
                except Exception as e:
                    logger.warning(f"端口扫描失败: {e}")
            report = generate_report(domain, results, "domain")

            # 写入缓存
            if global_cache:
                await global_cache.set(cache_key, report)

            logger.info(f"域名 {domain} 调查完成")
            return report
    except Exception as e:
        logger.error(f"调查域名 {domain} 失败: {e}", exc_info=True)
        return f"# ❌ 域名调查失败\n\n错误信息: {str(e)}"


@mcp.tool()
async def investigate_hash(hash_value: str) -> str:
    """
    [多源聚合] 调查文件哈希 (SHA256/SHA1/MD5)。
    查询 VirusTotal 文件报告（检出率、标签、家族、行为、C2 通信）。
    返回 Markdown 格式的聚合报告。
    """
    logger.info(f"开始调查文件哈希: {hash_value[:16]}...")

    # 检查缓存
    if global_cache:
        cache_key = f"report_hash_{hash_value}"
        cached_report = await global_cache.get(cache_key)
        if cached_report:
            logger.info(f"命中缓存: {hash_value[:16]}...")
            return cached_report

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            results = await execute_provider_queries(client, hash_value.strip().lower(), "hash")

            report = generate_hash_report(hash_value, results)

            # 写入缓存
            if global_cache:
                await global_cache.set(cache_key, report)

            logger.info(f"文件哈希 {hash_value[:16]}... 调查完成")
            return report
    except Exception as e:
        logger.error(f"调查文件哈希 {hash_value[:16]}... 失败: {e}", exc_info=True)
        return f"# ❌ 哈希调查失败\n\n错误信息: {str(e)}"


@mcp.tool()
async def investigate_url(url: str) -> str:
    """
    [多源聚合] 调查 URL 威胁情报。
    查询 VirusTotal URL 扫描结果，自动提取关联域名和 IP 进行深度分析。
    返回 Markdown 格式的聚合报告。
    """
    logger.info(f"开始调查 URL: {url[:60]}...")

    # 检查缓存
    if global_cache:
        cache_key = f"report_url_{url}"
        cached_report = await global_cache.get(cache_key)
        if cached_report:
            logger.info(f"命中缓存: {url[:60]}...")
            return cached_report

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            results = await execute_provider_queries(client, url, "url")

            report = generate_url_report(url, results)

            # 写入缓存
            if global_cache:
                await global_cache.set(cache_key, report)

            logger.info(f"URL {url[:60]}... 调查完成")
            return report
    except Exception as e:
        logger.error(f"调查 URL {url[:60]}... 失败: {e}", exc_info=True)
        return f"# ❌ URL 调查失败\n\n错误信息: {str(e)}"


@mcp.tool()
async def investigate_batch(targets: List[str]) -> str:
    """
    [批量分析] 自动识别 IP 或域名并并行调查。
    输入示例: ["1.1.1.1", "baidu.com"] 或 "1.1.1.1, baidu.com" (如果是字符串会自动分割)
    返回合并的简报和详细报告链接。
    """
    # 处理字符串输入 (如果用户传入逗号分隔字符串)
    final_targets = []
    if isinstance(targets, str):
        # 替换中文逗号
        targets = targets.replace("，", ",")
        final_targets = [t.strip() for t in targets.split(",") if t.strip()]
    else:
        final_targets = targets

    if not final_targets:
        return "❌ 请提供至少一个 IP 或域名"

    if len(final_targets) > 20:
        return "⚠️ 批量查询限制最多 20 个目标，请分批进行。"

    logger.info(f"开始批量调查: {final_targets}")

    # 并发控制
    semaphore = asyncio.Semaphore(5) # 最多5个并发目标

    async def limited_investigate(target: str):
        async with semaphore:
            async with httpx.AsyncClient(timeout=60.0) as client:
                query_type = "ip" if validate_ip_address(target) else "domain"
                if query_type == "domain" and not validate_domain_name(target):
                    return {"target": target, "error": "Invalid Format", "report": ""}

                results = await execute_provider_queries(client, target, query_type)
                report = generate_report(target, results, query_type)
                return {"target": target, "type": query_type, "results": results, "report": report}

    # 执行任务
    tasks = [limited_investigate(t) for t in final_targets]
    batch_results = await asyncio.gather(*tasks)

    # 生成汇总报告
    summary_report = ["# 📊 Batch Analysis Summary", "", "| Target | Type | Risk Score (VT) | Key Findings |", "| :--- | :--- | :--- | :--- |"]

    detailed_reports = []

    for res in batch_results:
        target = res.get("target")
        if "error" in res:
            summary_report.append(f"| {target} | N/A | N/A | ❌ {res['error']} |")
            continue

        # 提取关键信息用于汇总
        # 简单的提取 VT 分数
        vt_score = "N/A"
        key_findings = []

        # 解析 results 来获取摘要
        for r in res.get("results", []):
            if r.get("source") == "VirusTotal" and r.get("status") == "success":
                data = r.get("data", {})
                vt_score = f"{data.get('malicious', 0)}/{data.get('malicious', 0) + data.get('harmless', 0)}"

            if r.get("source") == "AbuseIPDB" and r.get("status") == "success":
                 score = r.get("data", {}).get("abuseConfidenceScore")
                 if score and score > 0:
                     key_findings.append(f"Abuse:{score}%")

            if r.get("source") == "PortScan (Shodan)" and r.get("status") == "success":
                 ports = r.get("data", {}).get("open_ports", [])
                 if ports:
                     key_findings.append(f"Ports:{len(ports)}")

        findings_str = ", ".join(key_findings) or "No critical findings"
        summary_report.append(f"| {target} | {res.get('type')} | {vt_score} | {findings_str} |")

        detailed_reports.append(res.get("report"))

    final_output = "\n".join(summary_report) + "\n\n---\n\n" + "\n\n---\n\n".join(detailed_reports)
    return final_output


@mcp.tool()
async def health_check() -> str:
    """
    检查系统健康状态，包括环境变量和提供商配置。
    """
    status = ["# 🔧 系统健康检查", "---"]
    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        status.append("- ✅ **VirusTotal API密钥**: 已配置")
    else:
        status.append("- ⚠️ **VirusTotal API密钥**: 未配置 (VirusTotal查询将受限)")

    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        status.append("- ✅ **Shodan API密钥**: 已配置 (使用完整 API)")
    else:
        status.append("- ℹ️ **Shodan API密钥**: 未配置 (使用免费 InternetDB)")

    fofa_email = os.getenv("FOFA_EMAIL")
    fofa_key = os.getenv("FOFA_API_KEY")
    if fofa_email and fofa_key:
        status.append("- ✅ **FOFA API配置**: 已配置")
    else:
        status.append("- ⚠️ **FOFA API配置**: 未配置 (需同时配置 EMAIL 和 KEY)")

    status.append("\n### 活跃提供商")
    status.append("- ✅ VirusTotal")
    status.append("- ✅ LocalWhois")
    status.append("- ✅ RDAP (Registration Data)")
    status.append("- ✅ crt.sh (Certificate History)")
    status.append("- ✅ WebFingerprint (Headers/Favicon)")
    if shodan_key:
        status.append("- ✅ PortScan (Shodan API)")
    else:
        status.append("- ✅ PortScan (Shodan InternetDB)")
    status.append("- ✅ AlienVault OTX (Threat Intelligence)")
    status.append("- ✅ IPInfo (Geolocation & Privacy)")
    status.append("- ✅ ICP Filing (beianx.cn)")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        status.append("- ✅ AbuseIPDB (Reputation & Reports)")
    else:
        status.append("- ⚠️ AbuseIPDB (Not Configured)")

    if fofa_email and fofa_key:
        status.append("- ✅ FOFA (Cyberspace Search)")
    else:
        status.append("- ⚠️ FOFA (Not Configured)")

    return "\n".join(status)


@mcp.tool()
async def resolve_domain_ips(domain: str) -> str:
    """
    [DNS 解析] 获取域名当前解析的 IPv4 / IPv6 地址列表。
    用于快速查看域名解析状态，与威胁情报调查互补。
    """
    if not validate_domain_name(domain):
        return "❌ 输入域名无效"
    ipv4 = []
    ipv6 = []
    try:
        infos = socket.getaddrinfo(domain, None)
        for family, _, _, _, addr in infos:
            ip = addr[0]
            if ":" in ip:
                if ip not in ipv6:
                    ipv6.append(ip)
            else:
                if ip not in ipv4:
                    ipv4.append(ip)
    except Exception as e:
        return f"# 🌐 当前解析 IP: {domain}\n\n- IPv4: `无`\n- IPv6: `无`\n\n错误: {str(e)}"
    ipv4_str = ", ".join(ipv4) if ipv4 else "`无`"
    ipv6_str = ", ".join(ipv6) if ipv6 else "`无`"
    return f"# 🌐 当前解析 IP: {domain}\n\n- IPv4: {ipv4_str}\n- IPv6: {ipv6_str}"


def cli_main() -> None:
    """`cti-aggregator-mcp` 命令行入口（pyproject.toml scripts 引用）。

    IDE 配置里通常直接调用 `python server.py`，会走下面的 `if __name__` 块。
    本函数用于 `pip install` 后通过 `cti-aggregator-mcp` 命令启动。
    """
    logger.info("启动 cti-aggregator MCP 服务器")
    # 硬编码 stdio 传输：避免误用 HTTP transport 暴露网络端口。
    # 如需远程访问，推荐在 Claude/Cursor 侧开启 SSH 隧道 + stdio，而非启动 HTTP。
    # 必须用 HTTP 时请走 FastMCP(..., host="127.0.0.1", port=...) + 鉴权中间件。
    mcp.run(transport="stdio")


if __name__ == "__main__":
    cli_main()
