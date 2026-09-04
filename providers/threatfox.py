from typing import Dict, Any, List
import logging
from .base import format_result, validate_ip_address, validate_domain_name

logger = logging.getLogger(__name__)

API_URL = "https://threatfox.abuse.ch/api/"

async def _query(client, indicator: str) -> Dict[str, Any]:
    payload = {"query": "ioc", "search_term": indicator}
    try:
        resp = await client.post(API_URL, json=payload, timeout=20.0)
        if resp.status_code != 200:
            return format_result("ThreatFox", error=f"HTTP {resp.status_code}")
        data = resp.json()
        items = data.get("data") or []
        records: List[Dict[str, Any]] = []
        families = set()
        for it in items[:50]:
            rec = {
                "ioc": it.get("ioc"),
                "type": it.get("ioc_type"),
                "malware": it.get("malware"),
                "confidence": it.get("confidence_level"),
                "first_seen": it.get("first_seen"),
                "last_seen": it.get("last_seen"),
                "tags": it.get("tags") or []
            }
            if rec["malware"]:
                families.add(rec["malware"])
            records.append(rec)
        result = {
            "count": len(items),
            "malware_families": list(families),
            "records": records
        }
        return format_result("ThreatFox", result)
    except Exception as e:
        logger.error(f"ThreatFox query failed: {e}")
        return format_result("ThreatFox", error=str(e))

async def query_ip(client, ip: str) -> Dict[str, Any]:
    if not validate_ip_address(ip):
        return format_result("ThreatFox", error=f"无效的IP地址: {ip}")
    return await _query(client, ip)

async def query_domain(client, domain: str) -> Dict[str, Any]:
    if not validate_domain_name(domain):
        return format_result("ThreatFox", error=f"无效的域名: {domain}")
    return await _query(client, domain)

async def query_hash(client, hash_value: str) -> Dict[str, Any]:
    """通过文件哈希查询 ThreatFox。

    支持 SHA256/MD5/SHA1，调用方负责预校验格式。
    """
    return await _query(client, hash_value)
