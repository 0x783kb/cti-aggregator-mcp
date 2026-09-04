"""
VirusTotal 威胁情报提供商
提供IP地址和域名的威胁情报查询功能
"""
import os
import logging
import socket
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from .base import format_result, validate_ip_address, validate_domain_name, sanitize_data
import httpx

logger = logging.getLogger(__name__)

# 常见云厂商/CDN关键词列表
CLOUD_PROVIDERS = [
    "AMAZON", "AWS", "GOOGLE", "MICROSOFT", "AZURE", "ALIBABA", "TENCENT", 
    "CLOUDFLARE", "AKAMAI", "FASTLY", "DIGITALOCEAN", "HETZNER", "OVH", 
    "CDN77", "INCAPSULA", "LIMELIGHT", "EDGECAST", "WANGSU", "BAIDU", "HUAWEI"
]

def _detect_cloud_provider(asn_owner: str) -> Optional[str]:
    """根据ASN拥有者检测云厂商/CDN"""
    if not asn_owner:
        return None
    owner_upper = asn_owner.upper()
    for provider in CLOUD_PROVIDERS:
        if provider in owner_upper:
            return provider
    return None


def _parse_related_samples(items: list) -> list:
    """
    解析 VirusTotal 关联样本列表，统一提取字段并按提交时间降序排序。
    供 query_ip / query_domain 复用，避免重复代码。
    """
    samples = []
    for sample in items:
        sample_attrs = sample.get("attributes", {})
        stats = sample_attrs.get("last_analysis_stats", {})

        # 尝试从 last_analysis_results 中提取 MD5
        md5_hash = None
        last_results = sample_attrs.get("last_analysis_results")
        if last_results:
            for engine_result in last_results.values():
                if "md5" in engine_result:
                    md5_hash = engine_result["md5"]
                    break

        meaningful_name = sample_attrs.get("meaningful_name")
        samples.append({
            "sha256": sample_attrs.get("sha256"),
            "md5": md5_hash,
            "type": sample_attrs.get("type_description"),
            "size": sample_attrs.get("size"),
            "name": meaningful_name or "N/A",
            "meaningful_names": sample_attrs.get("meaningful_names")
                                or ([meaningful_name] if meaningful_name else []),
            "creation_date": sample_attrs.get("creation_date", "N/A"),
            "score": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "date": sample_attrs.get("first_submission_date")
                    or sample_attrs.get("last_analysis_date") or 0,
            "last_analysis_stats": stats,
        })

    samples.sort(key=lambda x: x.get("date") or 0, reverse=True)
    return samples


async def _get_ip_metadata(client, ip: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    获取IP的元数据（国家、ASN等），用于域名解析IP的快速分析
    为避免递归调用 query_ip，这里单独实现简化的查询逻辑
    """
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        # 使用较短的超时，避免阻塞主流程
        resp = await client.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            asn_owner = data.get("as_owner", "Unknown")
            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "as_owner": asn_owner,
                "asn": data.get("asn", 0),
                "cloud_provider": _detect_cloud_provider(asn_owner)
            }
    except Exception as e:
        logger.warning(f"获取IP {ip} 元数据失败: {e}")
    
    return {"ip": ip, "error": "Failed to fetch metadata"}


def get_api_key() -> str:
    """
    获取VirusTotal API密钥
    
    Returns:
        API密钥
    
    Raises:
        ValueError: 如果API密钥未配置
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise ValueError("缺少 VT_API_KEY 环境变量")
    return api_key


async def make_vt_request(client, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    向VirusTotal API发送请求
    
    Args:
        client: HTTP客户端
        url: 请求URL
        headers: 请求头
    
    Returns:
        API响应数据
    
    Raises:
        httpx.HTTPStatusError: HTTP错误
        httpx.RequestError: 请求错误
    """
    try:
        resp = await client.get(url, headers=headers)
        
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403:
            logger.error("VirusTotal API密钥无效或额度耗尽")
            raise ValueError("API密钥无效或额度耗尽")
        elif resp.status_code == 404:
            logger.info(f"VirusTotal 未找到相关数据: {url}")
            raise ValueError("未找到相关数据")
        else:
            logger.error(f"VirusTotal HTTP 错误: {resp.status_code}")
            raise httpx.HTTPStatusError(
                f"HTTP {resp.status_code}", 
                request=resp.request, 
                response=resp
            )
            
    except httpx.TimeoutException:
        logger.error("VirusTotal 查询超时")
        raise ValueError("查询超时")
    except httpx.ConnectError:
        logger.error("VirusTotal 连接失败")
        raise ValueError("无法连接到VirusTotal服务")
    except Exception as e:
        logger.error(f"VirusTotal 请求异常: {e}", exc_info=True)
        raise


async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    查询 VirusTotal：获取IP地址威胁情报和关联样本
    
    Args:
        client: HTTP客户端
        ip: 待查询的IP地址
    
    Returns:
        格式化的查询结果
    """
    # 验证IP地址格式
    if not validate_ip_address(ip):
        return format_result("VirusTotal", error=f"无效的IP地址格式: {ip}")
    
    try:
        api_key = get_api_key()
        headers = {"x-apikey": api_key}
        
        logger.info(f"VirusTotal 开始查询 IP: {ip}")
        
        # 并行查询IP信息、关联样本、引用样本和被动DNS解析
        ip_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        files_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files"
        referrer_files_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/referrer_files"
        resolutions_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        
        tasks = [
            make_vt_request(client, ip_url, headers),
            make_vt_request(client, files_url, headers),
            make_vt_request(client, referrer_files_url, headers),
            make_vt_request(client, resolutions_url, headers)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ip_info_res, samples_res, referrer_res, resolutions_res = results

        # 如果主查询失败，则直接抛出异常
        if isinstance(ip_info_res, Exception):
            raise ip_info_res

        response_data = ip_info_res
        
        # 提取关键情报
        data = response_data.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        summary = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "country": sanitize_data(attributes.get("country", "Unknown"), max_length=50),
            "as_owner": sanitize_data(attributes.get("as_owner", "Unknown"), max_length=100),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date", "Unknown")
        }

        # 检测云厂商
        cloud = _detect_cloud_provider(summary.get("as_owner"))
        if cloud:
            summary["cloud_provider"] = cloud
        
        # 添加网络信息
        network_info = attributes.get("network", "")
        if network_info:
            summary["network"] = sanitize_data(str(network_info), max_length=100)
        
        # 添加标签信息
        tags = attributes.get("tags", [])
        if tags:
            summary["tags"] = sanitize_data(tags, max_length=200)

        # 处理关联样本信息 (Communicating Files)
        if isinstance(samples_res, Exception):
            logger.warning(f"VirusTotal 查询 IP {ip} 的关联样本失败：{samples_res}")
        elif samples_res and "data" in samples_res:
            samples = _parse_related_samples(samples_res["data"])
            if samples:
                summary["communicating_files"] = samples[:10]

        # 处理引用样本信息 (Referrer Files)
        if isinstance(referrer_res, Exception):
            logger.warning(f"VirusTotal 查询 IP {ip} 的引用样本失败：{referrer_res}")
        elif referrer_res and "data" in referrer_res:
            samples = _parse_related_samples(referrer_res["data"])
            if samples:
                summary["referrer_files"] = samples[:10]

        # 处理关联域名 (Resolutions)
        if isinstance(resolutions_res, Exception):
            logger.warning(f"VirusTotal 查询IP {ip} 的关联域名失败: {resolutions_res}")
        elif resolutions_res and "data" in resolutions_res:
            resolutions = []
            for res_item in resolutions_res["data"][:10]: # 最多获取10个关联域名
                res_attrs = res_item.get("attributes", {})
                resolutions.append({
                    "host_name": res_attrs.get("host_name"),
                    "last_resolved": res_attrs.get("last_resolved", "Unknown"),
                })
            if resolutions:
                summary["resolutions"] = resolutions
        
        logger.info(f"VirusTotal 成功查询 IP {ip}")
        return format_result("VirusTotal", summary)
        
    except ValueError as e:
        return format_result("VirusTotal", error=str(e))
    except Exception as e:
        logger.error(f"VirusTotal 查询异常: {e}", exc_info=True)
        return format_result("VirusTotal", error=f"查询异常: {str(e)}")


async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    查询 VirusTotal：获取域名威胁情报和关联样本
    
    Args:
        client: HTTP客户端
        domain: 待查询的域名
    
    Returns:
        格式化的查询结果
    """
    # 验证域名格式
    if not validate_domain_name(domain):
        return format_result("VirusTotal", error=f"无效的域名格式: {domain}")
    
    try:
        api_key = get_api_key()
        headers = {"x-apikey": api_key}
        
        logger.info(f"VirusTotal 开始查询域名: {domain}")

        # 1. 实时解析域名 IP
        resolved_ips_info = []
        try:
            # 获取所有解析IP (IPv4)
            _, _, ips = await asyncio.get_running_loop().run_in_executor(
                None, socket.gethostbyname_ex, domain
            )
            logger.info(f"域名 {domain} 实时解析结果: {ips}")
            
            # 对第一个 IP 获取详细元数据 (避免过多请求)
            if ips:
                ip_meta = await _get_ip_metadata(client, ips[0], headers)
                resolved_ips_info.append(ip_meta)
                # 如果有更多IP，仅添加IP地址，不再查详情
                for other_ip in ips[1:5]: # 限制最多显示5个
                     resolved_ips_info.append({"ip": other_ip})

        except Exception as e:
            logger.warning(f"域名 {domain} 实时解析失败: {e}")
        
        # 并行查询域名信息、关联样本和引用样本
        domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        files_url = f"https://www.virustotal.com/api/v3/domains/{domain}/communicating_files"
        referrer_files_url = f"https://www.virustotal.com/api/v3/domains/{domain}/referrer_files"
        
        tasks = [
            make_vt_request(client, domain_url, headers),
            make_vt_request(client, files_url, headers),
            make_vt_request(client, referrer_files_url, headers)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        domain_info_res, samples_res, referrer_res = results

        # 如果主查询失败，则直接抛出异常
        if isinstance(domain_info_res, Exception):
            raise domain_info_res

        response_data = domain_info_res
        
        # 提取关键情报
        data = response_data.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        summary = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date", "Unknown")
        }

        # 添加解析IP信息
        if resolved_ips_info:
            summary["resolved_ips"] = resolved_ips_info
        
        # 添加域名注册信息
        creation_date = attributes.get("creation_date")
        if creation_date:
            try:
                # 转换时间戳为可读格式
                if isinstance(creation_date, int):
                    creation_dt = datetime.fromtimestamp(creation_date)
                    summary["creation_date"] = creation_dt.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    summary["creation_date"] = str(creation_date)
            except Exception:
                summary["creation_date"] = str(creation_date)
        
        registrar = attributes.get("registrar")
        if registrar:
            summary["registrar"] = sanitize_data(registrar, max_length=100)
            
        # 提取 WHOIS 文本片段
        whois_text = attributes.get("whois")
        if whois_text:
            summary["whois_preview"] = sanitize_data(whois_text, max_length=300)
        
        # 添加分类信息
        categories = attributes.get("categories", {})
        if categories:
            summary["categories"] = sanitize_data(list(categories.keys()), max_length=200)
        
        # 添加标签信息
        tags = attributes.get("tags", [])
        if tags:
            summary["tags"] = sanitize_data(tags, max_length=200)
        
        # 添加流行度信息
        popularity_ranks = attributes.get("popularity_ranks", {})
        if popularity_ranks:
            summary["popularity_ranks"] = sanitize_data(
                {k: v.get("rank", 0) for k, v in popularity_ranks.items() if isinstance(v, dict)},
                max_length=200
            )
        
        # 添加 JARM 指纹 (TLS 服务器指纹)
        jarm = attributes.get("jarm")
        if jarm:
            summary["jarm"] = jarm
        
        # 处理关联样本信息
        if isinstance(samples_res, Exception):
            logger.warning(f"VirusTotal 查询域名 {domain} 的关联样本失败：{samples_res}")
        elif samples_res and "data" in samples_res:
            samples = _parse_related_samples(samples_res["data"])
            if samples:
                summary["related_samples"] = samples[:10]

        logger.info(f"VirusTotal 成功查询域名 {domain}")
        return format_result("VirusTotal", summary)
        
    except ValueError as e:
        return format_result("VirusTotal", error=str(e))
    except Exception as e:
        logger.error(f"VirusTotal 查询异常: {e}", exc_info=True)
        return format_result("VirusTotal", error=f"查询异常: {str(e)}")
