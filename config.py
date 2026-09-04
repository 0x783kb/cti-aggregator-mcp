"""
配置文件 - 管理应用程序设置和常量
"""
import os
import logging
from typing import List, Dict, Any

# 日志配置
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# 缓存配置
CACHE_ENABLED = os.getenv("CACHE_ENABLED", "true").lower() == "true"
CACHE_TTL = int(os.getenv("CACHE_TTL", 3600))  # 默认缓存 1 小时

# 威胁情报提供商配置
PROVIDER_CONFIG = {
    "virustotal": {
        "name": "VirusTotal",
        "enabled": os.getenv("VT_API_KEY") is not None,  # 只有配置了API密钥才启用
        "timeout": 15,  # 秒
        "max_retries": 2,
        "description": "提供IP和域名的威胁情报数据"
    },
    "local_whois": {
        "name": "LocalWhois",
        "enabled": True,
        "timeout": 15,
        "max_retries": 1,
        "description": "本地WHOIS查询（无需API Key）"
    },
    "rdap": {
        "name": "RDAP",
        "enabled": True,
        "timeout": 15,
        "max_retries": 1,
        "description": "现代化域名注册数据 (RDAP)"
    },
    "crtsh": {
        "name": "crt.sh",
        "enabled": True,
        "timeout": 30,
        "max_retries": 2,
        "description": "证书透明度历史记录"
    },
    "fingerprint": {
        "name": "WebFingerprint",
        "enabled": True,  # 模块整体启用开关
        "active_scan": False, # [关键配置] 主动扫描开关，默认关闭以保护隐私 (OPSEC)
        "timeout": 20,
        "max_retries": 1,
        "description": "Web 指纹识别 (HTTP头/Favicon)"
    },
    "portscan": {
        "name": "PortScan (Shodan)",
        "enabled": True,  # 即使无 Key 也可使用 InternetDB
        "api_key": os.getenv("SHODAN_API_KEY"),
        "timeout": 20,
        "max_retries": 1,
        "description": "端口扫描与漏洞探测 (Shodan)"
    },
    "fofa": {
        "name": "FOFA",
        "enabled": os.getenv("FOFA_EMAIL") is not None and os.getenv("FOFA_API_KEY") is not None,
        "email": os.getenv("FOFA_EMAIL"),
        "api_key": os.getenv("FOFA_API_KEY"),
        "timeout": 20,
        "max_retries": 1,
        "description": "网络空间资产搜索 (FOFA)"
    },
    "otx": {
        "name": "AlienVault OTX",
        "enabled": True, # 建议配置 OTX_API_KEY，但无 Key 也可尝试
        "timeout": 20,
        "max_retries": 1,
        "description": "威胁情报脉冲 (Pulses) 与 APT 关联分析"
    },
    "ipinfo": {
        "name": "IPInfo",
        "enabled": True, # 无 Key 可用基础版，有 Key (IPINFO_API_KEY) 可解锁隐私检测
        "timeout": 10,
        "max_retries": 1,
        "description": "精准 IP 归属地与类型 (Hosting/ISP/VPN)"
    },
    "icp": {
        "name": "ICP Filing",
        "enabled": True,
        "timeout": 20,
        "max_retries": 1,
        "description": "ICP 备案查询 (beianx.cn)"
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "enabled": os.getenv("ABUSEIPDB_API_KEY") is not None,
        "api_key": os.getenv("ABUSEIPDB_API_KEY"),
        "timeout": 10,
        "max_retries": 1,
        "description": "IP 滥用报告与信誉评分"
    },
    "threatfox": {
        "name": "ThreatFox",
        "enabled": True,
        "timeout": 20,
        "max_retries": 1,
        "description": "IOC 匹配与恶意家族关联（abuse.ch）"
    }
}

# 查询限制配置
QUERY_LIMITS = {
    "max_domains_per_ip": 10,  # 每个IP最多返回的关联域名数量
    "max_data_length": 1000,   # 单个数据字段最大长度
    "max_list_items": 100,     # 列表最大项目数
    "request_timeout": 30      # HTTP请求超时时间（秒）
}

# 报告配置
REPORT_CONFIG = {
    "include_empty_results": True,  # 是否在报告中包含空结果
    "max_error_detail_length": 200,  # 错误信息最大长度
    "show_provider_status": True     # 是否显示提供商状态
}


def get_enabled_providers() -> List[str]:
    """
    获取启用的威胁情报提供商列表
    
    Returns:
        启用的提供商名称列表
    """
    return [
        provider for provider, config in PROVIDER_CONFIG.items()
        if config["enabled"]
    ]


def setup_logging() -> None:
    """
    配置应用程序日志
    """
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # 设置特定模块的日志级别
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_provider_config(provider: str) -> Dict[str, Any]:
    """
    获取指定提供商的配置
    
    Args:
        provider: 提供商名称
    
    Returns:
        提供商配置字典
    """
    return PROVIDER_CONFIG.get(provider, {})


def validate_environment() -> Dict[str, Any]:
    """
    验证环境配置
    
    Returns:
        验证结果字典，包含状态和消息
    """
    issues = []
    warnings = []
    
    # 检查API密钥
    if not os.getenv("VT_API_KEY"):
        warnings.append("VirusTotal API密钥未配置，相关功能将被禁用")
    
    if not os.getenv("SECURITYTRAILS_API_KEY"):
        warnings.append("SecurityTrails API密钥未配置，WHOIS查询功能将被禁用")

    # 检查日志级别
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if LOG_LEVEL not in valid_log_levels:
        issues.append(f"无效的日志级别: {LOG_LEVEL}")
    
    # 检查提供商配置
    enabled_providers = get_enabled_providers()
    if not enabled_providers:
        issues.append("没有启用的威胁情报提供商")
    
    return {
        "status": "error" if issues else "warning" if warnings else "success",
        "issues": issues,
        "warnings": warnings,
        "enabled_providers": enabled_providers
    }
