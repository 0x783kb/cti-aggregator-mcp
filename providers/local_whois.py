
"""
本地 WHOIS 查询模块
使用 python-whois 库直接查询 WHOIS 服务器，无需 API Key
"""
import logging
import whois
import asyncio
from typing import Dict, Any, List, Optional
from .base import format_result, validate_domain_name

logger = logging.getLogger(__name__)

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    查询域名的 WHOIS 信息
    由于 python-whois 是同步阻塞的，需要运行在 executor 中
    """
    if not validate_domain_name(domain):
        return format_result("LocalWhois", error=f"无效的域名格式: {domain}")

    logger.info(f"LocalWhois 开始查询域名: {domain}")

    try:
        # 在线程池中运行同步的 whois 查询
        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, lambda: whois.whois(domain))
        
        if not w or not w.domain_name:
             return format_result("LocalWhois", error="无匹配的 WHOIS 记录")

        summary = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "emails": w.emails,
            "name_servers": w.name_servers,
            "status": w.status,
            "org": w.org,
            "city": w.city,
            "country": w.country
        }
        
        # 清理 None 值
        summary = {k: v for k, v in summary.items() if v is not None}

        # 格式化列表为字符串 (如果只有一个元素)
        for k, v in summary.items():
            if isinstance(v, list) and len(v) == 1:
                summary[k] = v[0]

        logger.info(f"LocalWhois 成功查询域名 {domain}")
        return format_result("LocalWhois", summary)

    except Exception as e:
        logger.error(f"LocalWhois 查询异常: {e}")
        return format_result("LocalWhois", error=f"查询异常: {str(e)}")
