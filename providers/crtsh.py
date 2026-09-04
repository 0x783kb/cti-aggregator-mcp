"""
crt.sh (Certificate Transparency) 查询模块
提供域名证书历史记录，用于监控域名活动和变更
"""
from typing import Dict, Any, List
import logging
from .base import format_result

CRTSH_URL = "https://crt.sh/"

logger = logging.getLogger(__name__)

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    查询域名的证书透明度记录
    """
    try:
        params = {
            "q": domain,
            "output": "json",
            "exclude": "expired",  # 可选：仅显示未过期证书（crt.sh参数可能变动，需测试）
            "limit": 20            # 限制返回数量，避免数据过大
        }
        
        # crt.sh 有时不稳定，设置较长的超时
        response = await client.get(CRTSH_URL, params=params, timeout=30.0)
        
        if response.status_code != 200:
            return format_result("crt.sh", error=f"HTTP {response.status_code}")
            
        data = response.json()
        
        # 处理和清洗数据
        certs = []
        seen_serials = set()
        
        for item in data:
            serial = item.get("serial_number")
            if serial in seen_serials:
                continue
            seen_serials.add(serial)
            
            certs.append({
                "issued_date": item.get("entry_timestamp"),
                "issuer": item.get("issuer_name"),
                "common_name": item.get("common_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after")
            })
            
        # 按时间倒序排序
        certs.sort(key=lambda x: x.get("issued_date", ""), reverse=True)
        
        return format_result("crt.sh", {
            "total_found": len(data),
            "recent_certs": certs[:10], # 只返回最近10条去重后的记录
            "note": "仅显示最近签发的证书记录"
        })
        
    except Exception as e:
        logger.error(f"crt.sh query failed for {domain}: {e}")
        # crt.sh 经常超时或 502，这是一个“软错误”，不应阻断流程
        return format_result("crt.sh", error=f"Service unavailable or timeout: {str(e)}")
