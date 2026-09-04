"""
SSL 证书与 JARM 指纹模块
提供详细的 SSL 证书信息解析及 JARM 指纹探测（依赖系统 openssl 和 jarm 命令）
"""
import logging
import asyncio
import shutil
import subprocess
from typing import Dict, Any
from .base import format_result, validate_ip_address, validate_domain_name

logger = logging.getLogger(__name__)

def get_cert_details(host: str, port: int = 443, timeout: float = 20.0) -> Dict[str, Any]:
    """使用 openssl 命令获取详细 SSL 证书信息（无 shell，避免命令注入）"""
    try:
        if not shutil.which("openssl"):
            return {"valid": False, "error": "System 'openssl' command not found"}

        # 第一步：s_client 建立 TLS 连接并输出证书 PEM
        s_client = subprocess.run(
            ["openssl", "s_client", "-servername", host, "-connect", f"{host}:{port}"],
            input=b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if s_client.returncode != 0:
            return {"valid": False, "error": "SSL handshake failed"}

        # 第二步：x509 解析证书文本
        x509 = subprocess.run(
            ["openssl", "x509", "-noout", "-text", "-fingerprint", "-sha256"],
            input=s_client.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if x509.returncode != 0:
            return {"valid": False, "error": "SSL handshake or certificate parsing failed"}

        output = x509.stdout.decode('utf-8', errors='ignore')
        
        # 解析输出
        data = {
            "valid": True,
            "subject": {},
            "issuer": {},
            "sans": [],
            "fingerprint_sha256": "",
            "fingerprint_sha1": "", # OpenSSL output usually includes one fingerprint based on flags
            "notBefore": "",
            "notAfter": ""
        }
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("Subject:"):
                # 简单解析 Subject: CN=example.com, O=...
                # 注意：OpenSSL输出格式可能包含未转义字符，这里做简单处理
                parts = line.replace("Subject:", "").strip().split(",")
                for p in parts:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        data["subject"][k.strip()] = v.strip()
                        # 兼容前端展示常用的 commonName
                        if k.strip() == "CN":
                            data["subject"]["commonName"] = v.strip()
                            
            elif line.startswith("Issuer:"):
                parts = line.replace("Issuer:", "").strip().split(",")
                for p in parts:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        data["issuer"][k.strip()] = v.strip()
                        if k.strip() == "CN":
                            data["issuer"]["commonName"] = v.strip()
                            
            elif "Fingerprint=" in line:
                if "SHA256" in line.upper():
                    data["fingerprint_sha256"] = line.split("=")[1].strip()
                elif "SHA1" in line.upper():
                    data["fingerprint_sha1"] = line.split("=")[1].strip()

            elif line.startswith("Not Before:"):
                data["notBefore"] = line.replace("Not Before:", "").strip()
            elif line.startswith("Not After :"):
                data["notAfter"] = line.replace("Not After :", "").strip()
            elif "DNS:" in line:
                # SANs usually appear as "DNS:example.com, DNS:www.example.com"
                sans = [x.strip().replace("DNS:", "") for x in line.split(",") if "DNS:" in x.strip()]
                data["sans"].extend(sans)

        # 如果没有获取到有效信息
        if not data["subject"] and not data["fingerprint_sha256"]:
             return {"valid": False, "error": "Empty certificate data parsed"}

        return data
        
    except Exception as e:
        return {"valid": False, "error": str(e)}

async def get_jarm_fingerprint(host: str, port: int = 443) -> Dict[str, Any]:
    """尝试调用系统 jarm 命令获取指纹"""
    if not shutil.which("jarm"):
        return {"status": "missing", "error": "System 'jarm' command not found"}
        
    try:
        # command: jarm <host> -p <port>
        proc = await asyncio.create_subprocess_exec(
            "jarm", host, "-p", str(port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            return {"status": "error", "error": stderr.decode().strip()}
            
        output = stdout.decode().strip()
        return {"status": "success", "raw": output}
        
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """查询域名的 SSL 和 JARM 信息"""
    if not validate_domain_name(domain):
        return format_result("SSL/JARM", error=f"无效的域名: {domain}")

    loop = asyncio.get_running_loop()
    
    # 1. SSL Info (Run in executor to avoid blocking)
    ssl_info = await loop.run_in_executor(None, get_cert_details, domain)
    
    # 2. JARM
    jarm_info = await get_jarm_fingerprint(domain)
    
    return format_result("SSL/JARM", {
        "ssl": ssl_info,
        "jarm": jarm_info
    })

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """查询 IP 的 SSL 和 JARM 信息"""
    if not validate_ip_address(ip):
        return format_result("SSL/JARM", error=f"无效的IP地址: {ip}")

    loop = asyncio.get_running_loop()
    
    ssl_info = await loop.run_in_executor(None, get_cert_details, ip)
    jarm_info = await get_jarm_fingerprint(ip)
    
    return format_result("SSL/JARM", {
        "ssl": ssl_info,
        "jarm": jarm_info
    })
