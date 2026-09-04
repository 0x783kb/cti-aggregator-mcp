"""
AbuseIPDB 威胁情报模块
查询 IP 的滥用报告记录、置信度评分和相关域名
"""
import logging
from typing import Dict, Any
from .base import format_result, validate_ip_address
from config import PROVIDER_CONFIG

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    查询 AbuseIPDB 获取 IP 信誉报告
    """
    if not validate_ip_address(ip):
        return format_result("AbuseIPDB", error=f"无效的IP地址: {ip}")

    config = PROVIDER_CONFIG.get("abuseipdb", {})
    api_key = config.get("api_key")

    if not api_key:
        return format_result("AbuseIPDB", error="未配置 API Key")

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""  # 包含报告详情
    }

    try:
        resp = await client.get(API_URL, headers=headers, params=params)
        
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            
            # 提取关键信息
            result = {
                "score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "is_tor": data.get("isTor", False)
            }
            
            # 提取最近的报告类别（如果 verbose 启用）
            reports = data.get("reports", [])
            if reports:
                # 聚合 top 类别
                categories = {}
                for r in reports[:10]: # 只看最近10条
                    cats = r.get("categories", [])
                    for c in cats:
                        categories[c] = categories.get(c, 0) + 1
                result["top_categories"] = [k for k, v in sorted(categories.items(), key=lambda item: item[1], reverse=True)]

            return format_result("AbuseIPDB", data=result)
            
        elif resp.status_code == 401:
            return format_result("AbuseIPDB", error="API Key 无效或过期")
        elif resp.status_code == 429:
            return format_result("AbuseIPDB", error="API 请求超限")
        else:
            return format_result("AbuseIPDB", error=f"HTTP Error {resp.status_code}")

    except Exception as e:
        logger.error(f"AbuseIPDB query failed for {ip}: {e}")
        return format_result("AbuseIPDB", error=f"查询失败: {str(e)}")
