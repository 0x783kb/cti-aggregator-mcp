"""
PortScan 模块 (Powered by Shodan)
支持 Shodan API (需 Key) 和 Shodan InternetDB (免费无 Key)
"""
import logging
from typing import Dict, Any, List
from .base import format_result, validate_ip_address
from config import PROVIDER_CONFIG

logger = logging.getLogger(__name__)

# Shodan InternetDB API (Free, No Auth)
INTERNETDB_API_URL = "https://internetdb.shodan.io/{ip}"
# Shodan Host API (Requires Key)
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    获取 IP 的开放端口和漏洞信息
    优先使用 Shodan API (如果配置了 Key)，否则降级使用 InternetDB
    """
    if not validate_ip_address(ip):
        return format_result("PortScan", error=f"无效的IP地址: {ip}")

    config = PROVIDER_CONFIG.get("portscan", {})
    api_key = config.get("api_key")
    
    # 检查是否为占位符
    if api_key and (len(api_key) < 10 or "ShodanAPIKey" in api_key):
        api_key = None

    try:
        if api_key:
            # 1. 使用 Shodan 完整 API
            return await _query_shodan_api(client, ip, api_key)
        else:
            # 2. 使用 InternetDB
            return await _query_internetdb(client, ip)
            
    except Exception as e:
        logger.error(f"PortScan query failed for {ip}: {e}")
        return format_result("PortScan", error=f"查询失败: {str(e)}")

async def _query_shodan_api(client, ip: str, api_key: str) -> Dict[str, Any]:
    """使用 Shodan 完整 API 查询"""
    url = SHODAN_HOST_URL.format(ip=ip, key=api_key)
    response = await client.get(url, timeout=15.0)
    
    if response.status_code == 404:
        return format_result("PortScan", {
            "status": "no_data",
            "message": "Shodan (API) 中未收录此 IP"
        })
    
    if response.status_code != 200:
        # 如果 Key 无效，尝试降级到 InternetDB ? 
        # 这里暂时直接报错，提示用户检查 Key
        return format_result("PortScan", error=f"Shodan API 请求失败: {response.status_code} (请检查 API Key)")

    data = response.json()
    
    # 提取信息
    ports = data.get("ports", [])
    vulns = data.get("vulns", []) # API 返回的是 list of CVE strings (如果 minify=true?) 
    # 注意：如果不加 minify=true，vulns 可能是 dict。加上 minify=true 后 vulns 是 list。
    # 上面的 URL 已经加了 minify=true
    
    hostnames = data.get("hostnames", [])
    tags = data.get("tags", [])
    # CPEs 在 minify 模式下可能不直接返回，或者在 data 中
    # 完整 API 的 data 字段包含详细服务信息
    
    open_ports = []
    # 解析服务详情
    service_data = data.get("data", [])
    jarm_set = set()
    for service in service_data:
        port = service.get("port")
        product = service.get("product", "Unknown")
        version = service.get("version", "")
        transport = service.get("transport", "tcp")
        ssl_info = service.get("ssl") or {}
        jarm = ssl_info.get("jarm")
        if isinstance(jarm, str) and jarm:
            jarm_set.add(jarm)
        
        service_str = product
        if version:
            service_str += f" {version}"
            
        open_ports.append({
            "port": port,
            "service": service_str,
            "transport": transport,
            "status": "open",
            "jarm": jarm if isinstance(jarm, str) else None
        })
    
    # 如果 data 中没有覆盖所有 ports (极少情况)，补充
    known_ports = {p["port"] for p in open_ports}
    for port in ports:
        if port not in known_ports:
            open_ports.append({
                "port": port,
                "service": "Unknown",
                "status": "open"
            })
            
    result = {
        "source": "Shodan API",
        "open_ports": open_ports,
        "open_ports_count": len(open_ports),
        "vulns": vulns,
        "vulns_count": len(vulns),
        "hostnames": hostnames,
        "tags": tags,
        "os": data.get("os"),
        "isp": data.get("isp"),
        "last_update": data.get("last_update"),
        "jarm_fingerprints": list(jarm_set),
        "jarm_count": len(jarm_set)
    }
    
    return format_result("PortScan", result)

async def _query_internetdb(client, ip: str) -> Dict[str, Any]:
    """使用 Shodan InternetDB 查询"""
    url = INTERNETDB_API_URL.format(ip=ip)
    response = await client.get(url, timeout=10.0)
    
    if response.status_code == 404:
            return format_result("PortScan", {
            "status": "no_data",
            "message": "Shodan InternetDB 中未收录此 IP"
        })
        
    if response.status_code != 200:
            return format_result("PortScan", error=f"InternetDB 请求失败: {response.status_code}")

    data = response.json()
    
    ports = data.get("ports", [])
    vulns = data.get("vulns", [])
    hostnames = data.get("hostnames", [])
    tags = data.get("tags", [])
    cpes = data.get("cpes", [])
    
    open_ports = []
    for port in ports:
            open_ports.append({
                "port": port,
                "service": "Unknown", 
                "status": "open"
            })
            
    result = {
        "source": "Shodan InternetDB",
        "open_ports": open_ports,
        "open_ports_count": len(open_ports),
        "vulns": vulns,
        "vulns_count": len(vulns),
        "hostnames": hostnames,
        "tags": tags,
        "cpes": cpes
    }
    
    return format_result("PortScan", result)
