"""
FOFA 模块 - 优化版
提供 IP 和域名的网络空间资产搜索功能
需要配置 FOFA_EMAIL 和 FOFA_API_KEY

FOFA API 文档：https://fofa.info/api
支持查询语法：
- ip="1.1.1.1" - 精确 IP 搜索
- domain="example.com" - 搜索根域名
- host="*.example.com" - 搜索子域名
- cert.subject="example.com" - 搜索证书
- title="admin" - 网页标题
- server=="nginx" - 精确匹配服务器
- country="CN" - 国家代码
- after="2023-01-01" - 时间范围
"""
import logging
import base64
import os
from typing import Dict, Any, List
from .base import format_result, validate_ip_address, validate_domain_name

logger = logging.getLogger(__name__)

# FOFA API URL
FOFA_API_URL = "https://fofa.info/api/v1/search/all"

# FOFA 字段说明
FOFA_FIELDS = {
    "ip": "IP 地址",
    "port": "端口号",
    "protocol": "协议类型",
    "country": "国家代码",
    "region": "省份/州",
    "city": "城市",
    "title": "网站标题",
    "server": "服务器标识",
    "banner": "Banner 信息",
    "domain": "域名",
    "host": "主机名",
    "org": "组织",
    "isp": "运营商",
    "icp": "ICP 备案号",
    "os": "操作系统",
    "link": "完整 URL",
    "jarm": "JARM 指纹",
    "cert": "SSL 证书信息"
}

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    使用 FOFA 查询 IP 资产信息
    
    Returns:
        包含 FOFA 资产信息的格式化结果
    """
    if not validate_ip_address(ip):
        return format_result("FOFA", error=f"无效的 IP 地址：{ip}")

    # 直接从环境变量读取，不依赖 PROVIDER_CONFIG
    email = os.getenv("FOFA_EMAIL")
    key = os.getenv("FOFA_API_KEY")
    
    # 检查是否配置
    if not email or not key:
         return format_result("FOFA", {
            "status": "skipped",
            "message": "FOFA 未启用 (请配置 FOFA_EMAIL 和 FOFA_API_KEY)"
        })
    
    # 构造查询语句 - 使用精确 IP 查询
    query = f'ip="{ip}"'
    qbase64 = base64.b64encode(query.encode()).decode()
    
    # FOFA API 参数配置
    params = {
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "fields": ",".join(FOFA_FIELDS.keys()),  # 获取所有字段
        "size": 100,  # 每次返回最大 1000 条，默认 100
        "page": 1,
        "full": "false"  # 是否返回完整信息
    }
    
    try:
        response = await client.get(FOFA_API_URL, params=params, timeout=30.0)
        
        if response.status_code != 200:
            return format_result("FOFA", error=f"FOFA API 请求失败：{response.status_code}")
            
        data = response.json()
        
        # 检查 API 错误
        if data.get("error"):
            error_msg = data.get('errmsg', 'Unknown error')
            # 常见错误码：
            # -700: 账号无效
            # -500: 积分不足
            # -400: 语法错误
            return format_result("FOFA", error=f"FOFA API 错误 ({error_msg})")
            
        results = data.get("results", [])
        total_size = data.get("size", 0)  # 总结果数
        page = data.get("page", 1)  # 当前页
        
        logger.info(f"FOFA 查询 IP {ip}: 返回 {len(results)} 条结果，总计 {total_size} 条")
        
        # 整理返回数据
        assets = []
        for item in results:
            # FOFA API 返回的是数组，按 FOFA_FIELDS 定义的顺序排列
            try:
                asset = {}
                field_list = list(FOFA_FIELDS.keys())
                for idx, field_name in enumerate(field_list):
                    asset[field_name] = item[idx] if len(item) > idx else "N/A"
                assets.append(asset)
            except (IndexError, TypeError) as e:
                logger.warning(f"FOFA 解析结果异常：{e}, item: {item}")
                continue
            
        return format_result("FOFA", {
            "query": query,
            "total_size": total_size,
            "page": page,
            "count": len(assets),
            "assets": assets
        })
        
    except Exception as e:
        logger.error(f"FOFA 查询失败：{e}", exc_info=True)
        return format_result("FOFA", error=f"FOFA 查询异常：{str(e)}")

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    使用 FOFA 查询域名资产信息
    
    支持语法：
    - domain="example.com" - 搜索根域名
    - host="*.example.com" - 搜索子域名
    - cert.subject="example.com" - 搜索证书包含该域名
    
    Returns:
        包含 FOFA 资产信息的格式化结果
    """
    if not validate_domain_name(domain):
        return format_result("FOFA", error=f"无效的域名：{domain}")

    # 直接从环境变量读取，不依赖 PROVIDER_CONFIG
    email = os.getenv("FOFA_EMAIL")
    key = os.getenv("FOFA_API_KEY")
    
    # 检查是否配置
    if not email or not key:
         return format_result("FOFA", {
            "status": "skipped",
            "message": "FOFA 未启用 (请配置 FOFA_EMAIL 和 FOFA_API_KEY)"
        })
    
    # 构造查询语句 - 搜索根域名及其所有子域名
    query = f'domain="{domain}"'
    qbase64 = base64.b64encode(query.encode()).decode()
    
    params = {
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "fields": ",".join(FOFA_FIELDS.keys()),
        "size": 100,
        "page": 1,
        "full": "false"
    }
    
    try:
        response = await client.get(FOFA_API_URL, params=params, timeout=30.0)
        
        if response.status_code != 200:
            return format_result("FOFA", error=f"FOFA API 请求失败：{response.status_code}")
            
        data = response.json()
        if data.get("error"):
            return format_result("FOFA", error=f"FOFA API 错误：{data.get('errmsg')}")
            
        results = data.get("results", [])
        total_size = data.get("size", 0)
        
        logger.info(f"FOFA 查询域名 {domain}: 返回 {len(results)} 条结果，总计 {total_size} 条")
        
        assets = []
        for item in results:
            try:
                asset = {}
                field_list = list(FOFA_FIELDS.keys())
                for idx, field_name in enumerate(field_list):
                    asset[field_name] = item[idx] if len(item) > idx else "N/A"
                assets.append(asset)
            except (IndexError, TypeError) as e:
                logger.warning(f"FOFA 解析结果异常：{e}, item: {item}")
                continue
            
        return format_result("FOFA", {
            "query": query,
            "total_size": total_size,
            "count": len(assets),
            "assets": assets
        })
        
    except Exception as e:
        logger.error(f"FOFA 查询失败：{e}", exc_info=True)
        return format_result("FOFA", error=f"FOFA 查询异常：{str(e)}")
