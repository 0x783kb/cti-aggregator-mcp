"""
VirusTotal 文件哈希查询提供商
支持 SHA256/SHA1/MD5 哈希的威胁情报查询
"""
import os
import re
import logging
from typing import Dict, Any
from .base import format_result, sanitize_data
from .virustotal import get_api_key, make_vt_request

logger = logging.getLogger(__name__)


def _validate_hash(hash_value: str) -> str:
    """
    验证哈希格式并返回哈希类型。
    
    Returns:
        "sha256" | "sha1" | "md5" | "" (无效)
    """
    hash_value = hash_value.strip().lower()
    if re.match(r'^[a-f0-9]{64}$', hash_value):
        return "sha256"
    elif re.match(r'^[a-f0-9]{40}$', hash_value):
        return "sha1"
    elif re.match(r'^[a-f0-9]{32}$', hash_value):
        return "md5"
    return ""


async def query_hash(client, hash_value: str) -> Dict[str, Any]:
    """
    查询 VirusTotal：通过文件哈希获取威胁情报
    
    Args:
        client: HTTP客户端
        hash_value: 文件哈希值 (SHA256/SHA1/MD5)
    
    Returns:
        格式化的查询结果
    """
    hash_value = hash_value.strip().lower()
    hash_type = _validate_hash(hash_value)
    
    if not hash_type:
        return format_result("VirusTotal (File)", error=f"无效的哈希格式（支持 SHA256/SHA1/MD5）: {hash_value[:32]}...")
    
    try:
        api_key = get_api_key()
        headers = {"x-apikey": api_key}
        
        logger.info(f"VirusTotal 开始查询文件哈希 ({hash_type}): {hash_value[:16]}...")
        
        import asyncio
        
        # 并行查询文件报告、关联URL、接触的IP
        file_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        contacted_ips_url = f"https://www.virustotal.com/api/v3/files/{hash_value}/contacted_ips"
        contacted_domains_url = f"https://www.virustotal.com/api/v3/files/{hash_value}/contacted_domains"
        
        tasks = [
            make_vt_request(client, file_url, headers),
            make_vt_request(client, contacted_ips_url, headers),
            make_vt_request(client, contacted_domains_url, headers),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        file_res, contacted_ips_res, contacted_domains_res = results
        
        if isinstance(file_res, Exception):
            raise file_res
        
        data = file_res.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        
        # 基本信息
        summary = {
            "hash_type": hash_type,
            "sha256": attributes.get("sha256", hash_value if hash_type == "sha256" else ""),
            "md5": attributes.get("md5", ""),
            "sha1": attributes.get("sha1", ""),
            "malicious": malicious,
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "detection_ratio": f"{malicious}/{total}",
            "file_type": attributes.get("type_description", "Unknown"),
            "file_size": attributes.get("size", 0),
            "meaningful_name": sanitize_data(attributes.get("meaningful_name", "N/A"), max_length=200),
            "names": sanitize_data(attributes.get("meaningful_names", []), max_length=300),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "creation_date": attributes.get("creation_date"),
        }
        
        # 标签
        tags = attributes.get("tags", [])
        if tags:
            summary["tags"] = sanitize_data(tags, max_length=300)
        
        # 恶意软件分类 (从流行名称中提取)
        popular_threat = attributes.get("popular_threat_classification", {})
        if popular_threat:
            summary["threat_category"] = popular_threat.get("suggested_threat_label", "")
            categories = popular_threat.get("popular_threat_category", [])
            if categories:
                summary["threat_categories"] = sanitize_data(categories, max_length=200)
        
        # Sigma 规则匹配
        sigma_analysis = attributes.get("sigma_analysis_summary", {})
        if sigma_analysis:
            summary["sigma_results"] = sanitize_data(sigma_analysis, max_length=300)
        
        # PE 信息
        pe_info = attributes.get("pe_info", {})
        if pe_info:
            summary["pe_info"] = {
                "machine_type": pe_info.get("machine_type", ""),
                "entry_point": pe_info.get("entry_point", ""),
                "imphash": pe_info.get("imphash", ""),
            }
        
        # 接触的 IP
        if isinstance(contacted_ips_res, Exception):
            logger.warning(f"查询关联IP失败: {contacted_ips_res}")
        elif contacted_ips_res and "data" in contacted_ips_res:
            contacted_ips = []
            for item in contacted_ips_res["data"][:10]:
                ip_attrs = item.get("attributes", {})
                ip_id = item.get("id", "")
                ip_stats = ip_attrs.get("last_analysis_stats", {})
                contacted_ips.append({
                    "ip": ip_id,
                    "country": ip_attrs.get("country", "Unknown"),
                    "as_owner": ip_attrs.get("as_owner", "Unknown"),
                    "malicious": ip_stats.get("malicious", 0),
                })
            if contacted_ips:
                summary["contacted_ips"] = contacted_ips
        
        # 接触的域名
        if isinstance(contacted_domains_res, Exception):
            logger.warning(f"查询关联域名失败: {contacted_domains_res}")
        elif contacted_domains_res and "data" in contacted_domains_res:
            contacted_domains = []
            for item in contacted_domains_res["data"][:10]:
                dom_attrs = item.get("attributes", {})
                dom_id = item.get("id", "")
                dom_stats = dom_attrs.get("last_analysis_stats", {})
                contacted_domains.append({
                    "domain": dom_id,
                    "malicious": dom_stats.get("malicious", 0),
                    "creation_date": dom_attrs.get("creation_date"),
                })
            if contacted_domains:
                summary["contacted_domains"] = contacted_domains
        
        # 传播方式
        trid = attributes.get("trid", [])
        if trid:
            summary["trid"] = sanitize_data(trid, max_length=200)
        
        # 代码签名信息
        signature_info = attributes.get("signature_info", {})
        if signature_info:
            summary["signature_info"] = {
                "signers": sanitize_data(signature_info.get("signers", ""), max_length=100),
                "verified": signature_info.get("verified", ""),
            }
        
        logger.info(f"VirusTotal 成功查询文件哈希 ({hash_type}): {hash_value[:16]}...")
        return format_result("VirusTotal (File)", summary)
        
    except ValueError as e:
        return format_result("VirusTotal (File)", error=str(e))
    except Exception as e:
        logger.error(f"VirusTotal 哈希查询异常: {e}", exc_info=True)
        return format_result("VirusTotal (File)", error=f"查询异常: {str(e)}")
