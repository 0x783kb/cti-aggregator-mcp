"""
AlienVault OTX (Open Threat Exchange) Provider
查询 IP 或域名关联的威胁情报 Pulse (脉冲) 和 IOCs
支持检测 APT 组织关联和 MITRE ATT&CK 映射
"""
import os
import logging
from typing import Dict, Any, List
from .base import format_result, validate_ip_address, validate_domain_name

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def get_api_key() -> str:
    return os.getenv("OTX_API_KEY", "")

async def _query_otx(client, indicator: str, indicator_type: str) -> Dict[str, Any]:
    """
    通用 OTX 查询函数
    indicator_type: 'IPv4', 'IPv6', 'domain', 'hostname'
    """
    api_key = get_api_key()
    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    
    # OTX 的 API 即使没有 Key 也可以访问部分公开数据，但建议配置 Key
    # 如果没有 Key，访问频率限制会很严，且可能看不到部分数据
    
    url = f"{OTX_BASE_URL}/indicators/{indicator_type}/{indicator}/general"
    
    try:
        response = await client.get(url, headers=headers, timeout=20.0)
        
        if response.status_code == 404:
            return format_result("AlienVault OTX", {
                "status": "no_data",
                "message": "OTX 中未找到此 IOC 的记录"
            })
            
        if response.status_code != 200:
            return format_result("AlienVault OTX", error=f"API 请求失败: {response.status_code}")

        data = response.json()
        
        # 提取 Pulse 信息
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        count = pulse_info.get("count", 0)
        
        # 提取威胁情报精简列表
        threat_data = []
        mitre_techniques = set()
        apt_groups = set()
        
        for pulse in pulses:
            # 提取 MITRE ATT&CK 信息
            attack_ids = pulse.get("attack_ids", [])
            for attack in attack_ids:
                if isinstance(attack, dict):
                    mitre_techniques.add(f"{attack.get('display_name')} ({attack.get('id')})")
                else:
                    mitre_techniques.add(str(attack))
            
            # 提取恶意家族或组织标签 (从 tags 中简单的关键词匹配)
            tags = pulse.get("tags", [])
            for tag in tags:
                tag_lower = tag.lower()
                if "apt" in tag_lower or "group" in tag_lower:
                    apt_groups.add(tag)
            
            threat_data.append({
                "name": pulse.get("name"),
                "author": pulse.get("author", {}).get("username", "Unknown"),
                "created": pulse.get("created"),
                "tags": tags[:5], # 只取前5个标签
                "subscribers": pulse.get("subscriber_count", 0),
                "references": pulse.get("references", [])[:2] # 只取前2个参考链接
            })
            
        # 基础信息
        base_info = {
            "whois": data.get("whois", "N/A"), # 简单的 WHOIS 链接
            "reputation": data.get("reputation", 0) # OTX 的信誉分
        }

        # 验证部分 (Validation)
        validation = data.get("validation", [])
        
        result = {
            "pulse_count": count,
            "pulses": threat_data[:10], # 限制显示最近的 10 个 Pulse
            "mitre_techniques": list(mitre_techniques),
            "apt_groups": list(apt_groups),
            "reputation": base_info["reputation"],
            "validation": validation
        }
        
        return format_result("AlienVault OTX", result)

    except Exception as e:
        logger.error(f"OTX query failed for {indicator}: {e}")
        return format_result("AlienVault OTX", error=f"查询失败: {str(e)}")

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """查询 IP 的 OTX 情报"""
    if not validate_ip_address(ip):
        return format_result("AlienVault OTX", error=f"无效的IP地址: {ip}")
    return await _query_otx(client, ip, "IPv4")

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """查询域名的 OTX 情报"""
    if not validate_domain_name(domain):
        return format_result("AlienVault OTX", error=f"无效的域名: {domain}")
    return await _query_otx(client, domain, "domain")
