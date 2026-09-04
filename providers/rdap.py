"""
RDAP (Registration Data Access Protocol) 查询模块
提供现代化的域名注册信息查询，替代传统的 WHOIS
"""
from typing import Dict, Any, List
import logging
from .base import format_result

# 设置 RDAP 引导服务 URL
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"

logger = logging.getLogger(__name__)

def _parse_rdap_events(events: List[Dict]) -> Dict[str, str]:
    """解析 RDAP 事件（时间戳）"""
    result = {}
    for event in events:
        action = event.get('eventAction')
        date = event.get('eventDate')
        if action and date:
            result[action] = date
    return result

def _parse_rdap_entities(entities: List[Dict]) -> Dict[str, Any]:
    """解析 RDAP 实体（注册商、注册人等）"""
    result = {}
    for entity in entities:
        roles = entity.get('roles', [])
        handle = entity.get('handle')
        vcard_array = entity.get('vcardArray', [])
        
        # 尝试提取名称
        name = "Unknown"
        if vcard_array and len(vcard_array) > 1:
            for item in vcard_array[1]:
                if item[0] == 'fn':  # Formatted Name
                    name = item[3]
                    break
        
        for role in roles:
            if role not in result:
                result[role] = []
            result[role].append({
                "handle": handle,
                "name": name
            })
    return result

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    查询域名的 RDAP 信息
    """
    try:
        url = f"{RDAP_BOOTSTRAP_URL}{domain}"
        # RDAP 经常需要重定向，务必开启 follow_redirects
        response = await client.get(url, follow_redirects=True)
        
        if response.status_code == 404:
            return format_result("RDAP", error="Domain not found in RDAP")
        
        if response.status_code != 200:
            return format_result("RDAP", error=f"HTTP {response.status_code}")
            
        data = response.json()
        
        # 提取关键信息
        parsed_data = {
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "events": _parse_rdap_events(data.get("events", [])),
            "entities": _parse_rdap_entities(data.get("entities", [])),
            "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
            "rdap_conformance": data.get("rdapConformance", [])
        }
        
        return format_result("RDAP", parsed_data)
        
    except Exception as e:
        logger.error(f"RDAP query failed for {domain}: {e}")
        return format_result("RDAP", error=str(e))
