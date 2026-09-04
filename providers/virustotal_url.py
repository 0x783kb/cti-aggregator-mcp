"""
VirusTotal URL 威胁分析提供商
支持 URL 的威胁情报查询，提取关联域名和 IP 进行二次关联分析
"""
import os
import re
import logging
import base64
import hashlib
from typing import Dict, Any, List
from .base import format_result, validate_ip_address, validate_domain_name, sanitize_data
from .virustotal import get_api_key, make_vt_request

logger = logging.getLogger(__name__)


def _validate_url(url: str) -> bool:
    """验证 URL 格式"""
    url_pattern = re.compile(
        r'^https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*'
        r'(:[0-9]{1,5})?(/[^\s]*)?$'
    )
    return bool(url_pattern.match(url.strip()))


def _extract_domain_from_url(url: str) -> str:
    """从 URL 中提取域名"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def _url_to_vt_id(url: str) -> str:
    """
    将 URL 转换为 VirusTotal URL ID（base64 无填充编码）
    VT v3 API 使用 base64(url) 作为 URL 标识符
    """
    return base64.urlsafe_b64encode(url.encode('utf-8')).rstrip(b'=').decode('ascii')


async def query_url(client, url: str) -> Dict[str, Any]:
    """
    查询 VirusTotal：通过 URL 获取威胁情报
    
    Args:
        client: HTTP客户端
        url: 待查询的 URL
    
    Returns:
        格式化的查询结果
    """
    url = url.strip()
    
    # 自动补全协议
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    if not _validate_url(url):
        return format_result("VirusTotal (URL)", error=f"无效的 URL 格式: {url[:50]}...")
    
    try:
        api_key = get_api_key()
        headers = {"x-apikey": api_key}
        
        logger.info(f"VirusTotal 开始查询 URL: {url[:60]}...")
        
        import asyncio
        
        url_id = _url_to_vt_id(url)
        
        # 并行查询 URL 报告
        url_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        url_res = await make_vt_request(client, url_report_url, headers)
        
        if isinstance(url_res, Exception):
            raise url_res
        
        data = url_res.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        
        # 提取域名
        domain = _extract_domain_from_url(url)
        
        # 基本信息
        summary = {
            "url": sanitize_data(url, max_length=300),
            "url_id": url_id,
            "domain": domain,
            "malicious": malicious,
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "detection_ratio": f"{malicious}/{total}",
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0),
        }
        
        # 标签
        tags = attributes.get("tags", [])
        if tags:
            summary["tags"] = sanitize_data(tags, max_length=300)
        
        # 威胁分类
        popular_threat = attributes.get("popular_threat_classification", {})
        if popular_threat:
            summary["threat_category"] = popular_threat.get("suggested_threat_label", "")
            categories = popular_threat.get("popular_threat_category", [])
            if categories:
                summary["threat_categories"] = sanitize_data(categories, max_length=200)
        
        # 分类信息
        categories = attributes.get("categories", {})
        if categories:
            summary["categories"] = sanitize_data(list(categories.keys()), max_length=200)
        
        # 如果有域名，查询域名的关联信息（一次额外查询获取更多上下文）
        if domain and validate_domain_name(domain):
            try:
                domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                domain_res = await make_vt_request(client, domain_url, headers)
                if not isinstance(domain_res, Exception) and domain_res:
                    dom_data = domain_res.get("data", {}).get("attributes", {})
                    dom_stats = dom_data.get("last_analysis_stats", {})
                    summary["domain_info"] = {
                        "domain": domain,
                        "malicious": dom_stats.get("malicious", 0),
                        "suspicious": dom_stats.get("suspicious", 0),
                        "harmless": dom_stats.get("harmless", 0),
                        "reputation": dom_data.get("reputation", 0),
                        "creation_date": dom_data.get("creation_date"),
                        "registrar": dom_data.get("registrar", ""),
                        "jarm": dom_data.get("jarm", ""),
                    }
                    
                    # 域名关联的恶意样本
                    try:
                        files_url = f"https://www.virustotal.com/api/v3/domains/{domain}/communicating_files"
                        files_res = await make_vt_request(client, files_url, headers)
                        if not isinstance(files_res, Exception) and files_res and "data" in files_res:
                            samples = []
                            for sample in files_res["data"][:5]:
                                s_attrs = sample.get("attributes", {})
                                samples.append({
                                    "sha256": s_attrs.get("sha256", ""),
                                    "type": s_attrs.get("type_description", "Unknown"),
                                    "name": s_attrs.get("meaningful_name", "N/A"),
                                    "malicious": s_attrs.get("last_analysis_stats", {}).get("malicious", 0),
                                    "total": sum(s_attrs.get("last_analysis_stats", {}).values()),
                                })
                            if samples:
                                summary["domain_samples"] = samples
                    except Exception as e:
                        logger.warning(f"查询域名关联样本失败: {e}")
            except Exception as e:
                logger.warning(f"查询域名信息失败: {e}")
        
        # 提取 URL 中包含的 IP
        ip_in_url = re.search(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
        if ip_in_url:
            ip = ip_in_url.group(1)
            summary["direct_ip"] = ip
        
        logger.info(f"VirusTotal 成功查询 URL: {url[:60]}...")
        return format_result("VirusTotal (URL)", summary)
        
    except ValueError as e:
        return format_result("VirusTotal (URL)", error=str(e))
    except Exception as e:
        logger.error(f"VirusTotal URL 查询异常: {e}", exc_info=True)
        return format_result("VirusTotal (URL)", error=f"查询异常: {str(e)}")
