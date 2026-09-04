"""
Provider 注册表：按 query_type 分组，动态加载。

设计动机：原 server.py 硬编码 provider 列表，加新 provider 必须改 server.py。
改为注册表后，加 provider 只改本文件。

设计要点：
- 注册表存的是**模块名**（字符串），不是模块对象。
- get_providers() 用 importlib.import_module 按需加载；缺依赖的 provider 自动跳过 + 警告，
  不会拖垮整个包。
- 加 provider 步骤：
  1. 在 providers/ 下新建 provider 模块，实现 query_ip / query_domain / query_hash / query_url 之一
  2. 在下方 PROVIDER_NAMES_BY_QUERY_TYPE 对应类型列表里加上模块名
"""

import importlib
import logging
from typing import List

logger = logging.getLogger(__name__)


# ---- IP / 域名场景：通用网络威胁情报 ----
# 各 provider 模块用途（与原 server.py 顶部 import 注释保持一致）：
#   virustotal        - VirusTotal IP / 域名信誉
#   local_whois       - 本地 whois 兜底（依赖 python-whois）
#   rdap              - RDAP 域名注册信息
#   crtsh             - crt.sh 子证书透明度
#   fingerprint       - Web 指纹（依赖 beautifulsoup4）
#   portscan          - 端口扫描
#   otx               - AlienVault OTX 威胁情报
#   ipinfo            - IPInfo 地理位置/ASN
#   icp               - ICP 备案查询（仅中国场景，依赖 requests-html）
#   fofa              - FOFA 资产搜索引擎
#   threatfox         - ThreatFox 恶意 IoC
#   ssl_info          - SSL 证书 / JARM 指纹
#   abuseipdb         - AbuseIPDB IP 信誉（仅 IP 场景使用）
#   virustotal_hash   - VT 文件哈希报告
#   virustotal_url    - VT URL 报告


# query_type -> provider 模块名列表
PROVIDER_NAMES_BY_QUERY_TYPE = {
    "ip": [
        "virustotal", "local_whois", "rdap", "crtsh", "fingerprint", "portscan",
        "otx", "ipinfo", "icp", "abuseipdb", "fofa", "threatfox", "ssl_info",
    ],
    "domain": [
        # 域名场景不查 AbuseIPDB（没有 IP 上下文）
        "virustotal", "local_whois", "rdap", "crtsh", "fingerprint", "portscan",
        "otx", "ipinfo", "icp", "fofa", "threatfox", "ssl_info",
    ],
    "hash": ["virustotal_hash", "threatfox"],
    "url": ["virustotal_url"],
}


def get_providers(query_type: str) -> List[tuple]:
    """根据 query_type 返回 [(短模块名, module), ...] 列表。

    用 importlib.import_module 按需加载，缺依赖的 provider 跳过 + 写警告日志。
    模块被加载后会缓存到 sys.modules，后续调用零开销。

    返回元组的原因：module.__name__ 默认带 'providers.' 前缀（如 'providers.threatfox'），
    不适合直接作为 source 标识。返回短名（'threatfox'）让 server.py 用作日志/报告的 provider 名。
    """
    names = PROVIDER_NAMES_BY_QUERY_TYPE.get(query_type, [])
    providers = []
    for name in names:
        try:
            mod = importlib.import_module(f".{name}", package="providers")
            providers.append((name, mod))
        except ImportError as e:
            logger.warning(f"Provider {name} 加载失败（缺依赖？），跳过: {e}")
    return providers
