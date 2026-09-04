"""
IPInfo Provider (ipinfo.io)
提供精准的 IP 地理位置、ASN、运营商和 IP 类型（托管/家庭宽带）
"""
import os
import re
import logging
from typing import Dict, Any, Tuple
from .base import format_result, validate_ip_address

logger = logging.getLogger(__name__)

# IPInfo API Endpoint
IPINFO_BASE_URL = "https://ipinfo.io/{ip}/json"

def get_api_key() -> str:
    return os.getenv("IPINFO_API_KEY", "")


def _parse_org(org: str) -> Tuple[str, str]:
    """
    解析 IPInfo 的 org 字段（形如 "AS15169 Google LLC"），
    拆分为 ASN 编号与组织名称。
    """
    if not org:
        return "", ""
    m = re.match(r"^AS(\d+)\s+(.*)$", org.strip())
    if m:
        return m.group(1), m.group(2)
    return "", org

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    查询 IP 的精准地理位置和类型信息
    """
    if not validate_ip_address(ip):
        return format_result("IPInfo", error=f"无效的IP地址: {ip}")

    api_key = get_api_key()
    
    # 检查是否为占位符或无效 Key
    if api_key and (len(api_key) < 10 or "IPInfoKey" in api_key):
        api_key = ""

    url = IPINFO_BASE_URL.format(ip=ip)
    
    # 如果有 Key，拼接到 URL 参数
    params = {}
    if api_key:
        params["token"] = api_key
    
    try:
        # IPInfo 即使无 Key 也可以免费使用（有频率限制，且缺少隐私/VPN检测字段）
        # 有 Key 后会解锁 Privacy (VPN/Proxy/Tor) 检测字段
        response = await client.get(url, params=params, timeout=10.0)
        
        if response.status_code == 404:
             return format_result("IPInfo", {
                "status": "no_data",
                "message": "IPInfo 中未收录此 IP"
            })
            
        if response.status_code != 200:
             return format_result("IPInfo", error=f"API 请求失败: {response.status_code}")

        data = response.json()
        
        # 提取关键字段
        # 基础地理位置
        city = data.get("city", "Unknown")
        region = data.get("region", "Unknown")
        country = data.get("country", "Unknown")
        loc = data.get("loc", "")  # 经纬度
        timezone = data.get("timezone", "")
        hostname = data.get("hostname", "")
        
        # 组织信息（org 字段形如 "AS15169 Google LLC"）
        org = data.get("org", "")
        asn, org_name = _parse_org(org)
        
        # 隐私/类型检测 (需要 Token/付费计划才会有完整字段，免费版可能只有基础部分)
        privacy = data.get("privacy", {})
        ip_type = "Unknown"
        
        if privacy:
            if privacy.get("vpn"): ip_type = "VPN"
            elif privacy.get("proxy"): ip_type = "Proxy"
            elif privacy.get("tor"): ip_type = "Tor"
            elif privacy.get("hosting"): ip_type = "Hosting (IDC)"
            else: ip_type = "Residential/Business" # 排除法
        else:
            # 简单的关键词推测
            org_lower = org.lower()
            if any(k in org_lower for k in ["cloud", "hosting", "data center", "cdn", "alibaba", "tencent", "amazon", "google"]):
                ip_type = "Hosting (IDC) [推测]"
            elif any(k in org_lower for k in ["telecom", "unicom", "mobile", "broadband", "isp"]):
                ip_type = "Residential/ISP [推测]"
        
        result = {
            "city": city,
            "region": region,
            "country": country,
            "location": f"{city}, {region}, {country}",
            "coordinates": loc,
            "asn": asn,
            "organization": org_name or org,
            "org": org_name or org,
            "timezone": timezone,
            "ip_type": ip_type,
            "rdns": hostname,
            "hostname": hostname or "N/A",
            # 如果有隐私字段，完整返回
            "privacy_flags": {k: v for k, v in privacy.items() if v} if privacy else None
        }
        
        return format_result("IPInfo", result)
        
    except Exception as e:
        logger.error(f"IPInfo query failed for {ip}: {e}")
        return format_result("IPInfo", error=f"查询失败: {str(e)}")
