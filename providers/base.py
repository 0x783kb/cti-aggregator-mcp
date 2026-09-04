"""
基础工具模块 - 提供通用的数据格式化和验证功能
"""
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ProviderError(Exception):
    """Provider 业务异常：携带 provider 名称，可被 server 层一次性捕获并转 dict。

    使用场景：provider 内部遇到 API Key 失效、配额耗尽、目标格式错误等
    已知失败原因时，raise ProviderError(provider_name, "具体原因")，由
    execute_provider_queries 统一捕获并转成 {"status": "error", ...}。
    """
    def __init__(self, provider_name: str, message: str, original: Optional[Exception] = None):
        self.provider_name = provider_name
        self.original = original
        super().__init__(message)

    def __str__(self):
        return f"[{self.provider_name}] {self.args[0]}"


def error_to_result(provider_name: str, exc: BaseException) -> dict:
    """把任意异常转成统一的 error 格式 dict。

    ProviderError 会原样取 provider_name 和 message；其他异常归为 'Unknown'。
    """
    if isinstance(exc, ProviderError):
        return format_result(exc.provider_name, error=str(exc))
    return format_result(provider_name, error=f"{type(exc).__name__}: {exc}")


def format_result(source: str, data: dict = None, error: str = None) -> dict:
    """
    统一格式化威胁情报查询结果

    Args:
        source: 数据来源名称
        data: 成功时的数据字典
        error: 错误信息（如果有）

    Returns:
        统一格式的结果字典
    """
    return {
        "source": source,
        "status": "error" if error else "success",
        "data": data if data else {},
        "error_msg": error
    }


def validate_ip_address(ip: str) -> bool:
    """
    验证IP地址格式
    
    Args:
        ip: 待验证的IP地址
    
    Returns:
        是否有效的IP地址
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logger.warning(f"无效的IP地址格式: {ip}")
        return False


def validate_domain_name(domain: str) -> bool:
    """
    验证域名格式
    
    Args:
        domain: 待验证的域名
    
    Returns:
        是否有效的域名
    """
    import re
    # 简化的域名验证正则表达式
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    if len(domain) > 253:  # 域名最大长度
        logger.warning(f"域名过长: {domain}")
        return False
    
    if not domain_pattern.match(domain):
        logger.warning(f"无效的域名格式: {domain}")
        return False
    
    return True


def sanitize_data(data: Any, max_length: int = 1000) -> Any:
    """
    清理和限制数据大小
    
    Args:
        data: 待清理的数据
        max_length: 最大长度限制
    
    Returns:
        清理后的数据
    """
    if isinstance(data, str):
        if len(data) > max_length:
            logger.warning(f"数据长度超过限制，进行截断: {len(data)} > {max_length}")
            return data[:max_length] + "..."
        return data
    elif isinstance(data, (list, dict)):
        # 对于复杂数据结构，限制元素数量
        if isinstance(data, list) and len(data) > 100:
            logger.warning(f"列表数据元素过多，进行截断: {len(data)} > 100")
            return data[:100]
        return data
    else:
        return data