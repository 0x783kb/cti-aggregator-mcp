"""
Web Fingerprint 模块
提供 Web 指纹识别功能，包括 HTTP 头信息、页面标题和 Favicon Hash
"""
import logging
import base64
import mmh3
import codecs
from typing import Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .base import format_result
# 引入配置以检查主动扫描开关
from config import PROVIDER_CONFIG

logger = logging.getLogger(__name__)

async def _get_favicon_hash(client, base_url: str, soup: BeautifulSoup) -> Dict[str, Any]:
    """获取 Favicon 并计算 Hash (Shodan 算法)"""
    favicon_url = None
    
    # 1. 尝试从 link 标签获取
    icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
    if icon_link and icon_link.get('href'):
        favicon_url = urljoin(base_url, icon_link.get('href'))
    else:
        # 2. 尝试默认路径
        parsed = urlparse(base_url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        
    if not favicon_url:
        return {}

    try:
        resp = await client.get(favicon_url, timeout=5.0)
        if resp.status_code == 200:
            content = resp.content
            # Shodan 算法: base64 -> split lines -> murmurhash3
            b64 = codecs.encode(content, "base64")
            # mmh3 需要 bytes 或 string，但 shodan hash 是对 base64 后的字符串计算
            fav_hash = mmh3.hash(b64)
            return {
                "url": favicon_url,
                "hash": fav_hash,
                "size": len(content)
            }
    except Exception as e:
        logger.debug(f"Failed to fetch favicon from {favicon_url}: {e}")
        
    return {}

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    获取 Web 指纹信息
    """
    # 检查主动扫描开关
    config = PROVIDER_CONFIG.get("fingerprint", {})
    if not config.get("active_scan", False):
        return format_result("WebFingerprint", {
            "status": "skipped",
            "message": "主动扫描已禁用 (OPSEC保护)"
        })

    # 优先尝试 HTTPS，失败则尝试 HTTP
    urls = [f"https://{domain}", f"http://{domain}"]
    
    result_data = {}
    error = None

    for url in urls:
        try:
            resp = await client.get(url, timeout=10.0, follow_redirects=True)
            
            # 基础头信息
            headers = {
                "server": resp.headers.get("server"),
                "x-powered-by": resp.headers.get("x-powered-by"),
                "via": resp.headers.get("via"),
                "strict-transport-security": resp.headers.get("strict-transport-security")
            }
            # 过滤掉 None
            headers = {k: v for k, v in headers.items() if v}

            # HTML 解析
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No Title"
            
            # Meta Generator
            generator = soup.find("meta", attrs={"name": "generator"})
            meta_generator = generator.get("content") if generator else None

            # Favicon Hash
            favicon_info = await _get_favicon_hash(client, resp.url, soup)

            result_data = {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "title": title,
                "headers": headers,
                "meta_generator": meta_generator,
                "favicon": favicon_info
            }
            
            # 成功获取则跳出循环
            break
            
        except Exception as e:
            error = str(e)
            continue
            
    if not result_data:
        return format_result("WebFingerprint", error=f"无法连接到 Web 服务: {error}")
        
    return format_result("WebFingerprint", result_data)

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    获取 IP 的 Web 指纹信息 (复用 query_domain 逻辑)
    """
    return await query_domain(client, ip)
