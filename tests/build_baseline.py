"""
为 report_generator 三份报告生成基线 fixture。
覆盖 IP / domain / hash / url 四种 query_type 的关键路径，
供后续三合一重构做字节级 diff 验证。

关键：mock socket.getaddrinfo 和 datetime.now，确保输出完全可复现。
"""
import os
import sys
import socket
import json
from unittest.mock import patch
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.report_generator import (
    generate_report,
    generate_hash_report,
    generate_url_report,
)


# ============================================================
# Mock 数据 — 覆盖每个报告类型的关键字段
# ============================================================

# ---- IP 报告 (恶意) ----
IP_HIGH_RISK_RESULTS = [
    {"source": "VirusTotal", "status": "success", "data": {
        "malicious": 18, "suspicious": 2, "harmless": 55, "undetected": 1,
        "tags": ["c2", "malware"],
        "first_submission_date": 1700000000,
        "country": "RU", "as_owner": "Example ASN",
        "communicating_files": [
            {"sha256": "a" * 64, "type_description": "Win32 EXE",
             "meaningful_names": ["evil.exe"],
             "last_analysis_stats": {"malicious": 40, "total": 70},
             "first_submission_date": 1720000000},
            {"sha256": "b" * 64, "type_description": "Win DLL",
             "meaningful_names": ["loader.dll"],
             "last_analysis_stats": {"malicious": 30, "total": 70},
             "first_submission_date": 1715000000},
        ],
        "resolutions": [
            {"host_name": "evil.example.com"},
            {"host_name": "panel.evil.example.com"},
        ],
    }},
    {"source": "AbuseIPDB", "status": "success", "data": {
        "score": 87, "reports": 100, "isp": "Bad ISP",
    }},
    {"source": "IPInfo", "status": "success", "data": {
        "city": "Moscow", "region": "Moscow", "country": "RU",
        "org": "AS12345 Example Hosting", "asn": "12345",
        "ip_type": "Hosting", "rdns": "vps-bad.example.net",
    }},
    {"source": "PortScan", "status": "success", "data": {
        "open_ports": [
            {"port": 22, "service": "SSH", "version": "OpenSSH 7.4"},
            {"port": 80, "service": "HTTP", "version": "nginx 1.14"},
            {"port": 443, "service": "HTTPS"},
            {"port": 3389, "service": "RDP"},
        ],
    }},
    {"source": "FOFA", "status": "success", "data": {
        "assets": [
            {"port": 80, "title": "Evil C2 Panel", "server": "nginx", "jarm": "deadbeefdeadbeefdeadbeefdeadbeef"},
            {"port": 443, "title": "Login", "server": "nginx"},
        ],
    }},
    {"source": "AlienVault OTX", "status": "success", "data": {
        "apt_groups": ["APT28"],
        "pulses": [
            {"name": "Evil Campaign Q3"},
            {"name": "Phishing Wave"},
        ],
    }},
    {"source": "ThreatFox", "status": "success", "data": {
        "records": [
            {"ioc": "1.2.3.4", "type": "ip:port", "malware": "CobaltStrike", "confidence": 90},
        ],
        "malware_families": ["CobaltStrike"],
    }},
    {"source": "SSL/JARM", "status": "success", "data": {
        "ssl": {
            "valid": True,
            "subject": {"commonName": "bad.example.com"},
            "issuer": {"commonName": "Let's Encrypt"},
        },
        "jarm": {"status": "success", "raw": "deadbeefdeadbeefdeadbeefdeadbeef"},
    }},
    {"source": "RDAP", "status": "success", "data": {
        "registrar": "N/A", "creation_date": "N/A", "nameservers": [], "org": "N/A",
    }},
]

# ---- 域名报告 (低风险) ----
DOMAIN_LOW_RISK_RESULTS = [
    {"source": "VirusTotal", "status": "success", "data": {
        "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5,
        "tags": [],
        "first_submission_date": 1600000000,
        "registrar": "MarkMonitor Inc.", "creation_date": "2005-01-15",
        "resolved_ips": ["8.8.8.8", "8.8.4.4"],
    }},
    {"source": "RDAP", "status": "success", "data": {
        "registrar": "MarkMonitor Inc.", "creation_date": "2005-01-15",
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "org": "Example Corp",
    }},
    {"source": "ICP Filing", "status": "success", "data": {
        "results": [{"domain": "example.com", "holder": "Example Inc"}],
    }},
    {"source": "PortScan", "status": "success", "data": {
        "open_ports": [],
    }},
    {"source": "FOFA", "status": "success", "data": {"assets": []}},
    {"source": "AlienVault OTX", "status": "success", "data": {
        "apt_groups": [], "pulses": [],
    }},
    {"source": "ThreatFox", "status": "error", "error_msg": "no records"},
    {"source": "IPInfo", "status": "success", "data": {
        "city": "Mountain View", "region": "California", "country": "US",
        "org": "AS15169 Google LLC", "asn": "15169",
        "ip_type": "Business",
    }},
]

# ---- HASH 报告 (高危) ----
HASH_HIGH_RISK_RESULTS = [
    {"source": "VirusTotal (File)", "status": "success", "data": {
        "malicious": 45, "suspicious": 0, "harmless": 10, "undetected": 5,
        "total_engines": 60,
        "sha256": "a" * 64, "md5": "b" * 32, "sha1": "c" * 40,
        "file_type": "Win32 EXE", "file_size": 1024 * 1024 * 2,
        "meaningful_name": "evil_payload.exe",
        "threat_category": "trojan.generic",
        "threat_categories": ["trojan", "downloader"],
        "tags": ["c2", "packed"],
        "first_submission_date": 1715000000,
        "last_analysis_date": 1720000000,
        "creation_date": 1714000000,
        "contacted_ips": [
            {"ip": "1.2.3.4", "country": "RU", "as_owner": "BadHost", "malicious": 5},
            {"ip": "5.6.7.8", "country": "CN", "as_owner": "C2Net", "malicious": 3},
        ],
        "contacted_domains": [
            {"domain": "evil.example.com", "malicious": 8, "creation_date": 1700000000},
        ],
        "pe_info": {
            "machine_type": "x86",
            "entry_point": "0x401000",
            "imphash": "deadbeef12345678",
        },
        "trid": ["Win32 Executable MS Visual C++ (generic) - 85%"],
        "signature_info": {"signers": "Unsigned", "verified": "Unsigned"},
        "names": ["payload.exe", "trojan_x64.exe"],
    }},
    {"source": "ThreatFox", "status": "success", "data": {
        "records": [
            {"ioc": "1.2.3.4", "type": "ip:port", "malware": "CobaltStrike",
             "confidence": 95, "first_seen": "2024-08-01"},
        ],
        "malware_families": ["CobaltStrike", "Emotet"],
    }},
]

# ---- HASH 报告 (低风险) ----
HASH_LOW_RISK_RESULTS = [
    {"source": "VirusTotal (File)", "status": "success", "data": {
        "malicious": 0, "suspicious": 0, "harmless": 65, "undetected": 10,
        "total_engines": 75,
        "sha256": "f" * 64, "md5": "0" * 32, "sha1": "1" * 40,
        "file_type": "Text", "file_size": 1024,
        "meaningful_name": "N/A",
        "tags": [],
    }},
]

# ---- URL 报告 (中风险) ----
URL_MEDIUM_RISK_RESULTS = [
    {"source": "VirusTotal (URL)", "status": "success", "data": {
        "malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 5,
        "total_engines": 69,
        "domain": "suspicious.example.org",
        "domain_info": {
            "malicious": 2, "suspicious": 1, "reputation": -10,
            "creation_date": 1710000000, "registrar": "NameCheap",
        },
        "domain_samples": [
            {"sha256": "d" * 64, "type": "Win32 EXE", "malicious": 30, "total": 70},
        ],
        "tags": ["phishing"],
        "threat_category": "phishing",
        "categories": ["Technology", "Search Engines"],
        "reputation": -5,
    }},
]

# ---- URL 报告 (低风险) ----
URL_LOW_RISK_RESULTS = [
    {"source": "VirusTotal (URL)", "status": "success", "data": {
        "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5,
        "total_engines": 75,
        "domain": "google.com",
        "domain_info": {},
        "domain_samples": [],
        "tags": [],
        "categories": ["Search Engine"],
        "reputation": 100,
    }},
]


# ============================================================
# 冻结时间和 DNS，让输出完全可复现
# ============================================================
FROZEN_TIME = datetime(2026, 9, 4, 12, 0, 0)


def _mock_getaddrinfo(host, port, *args, **kwargs):
    return [(2, 1, 6, "", ("93.184.216.34", 0))]


def _mock_now(timespec=None):
    return FROZEN_TIME


def main():
    fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)

    with patch("socket.getaddrinfo", _mock_getaddrinfo), \
         patch("utils.report_renderer.datetime") as mock_dt:
        mock_dt.now.return_value = FROZEN_TIME
        # 从 timestamp 转换仍需要真实 datetime
        mock_dt.fromtimestamp = datetime.fromtimestamp
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        # 生成 5 份基线报告
        cases = [
            ("baseline_ip_high.md",
             generate_report("1.2.3.4", IP_HIGH_RISK_RESULTS, report_type="ip")),
            ("baseline_domain_low.md",
             generate_report("example.com", DOMAIN_LOW_RISK_RESULTS, report_type="domain")),
            ("baseline_hash_high.md",
             generate_hash_report("a" * 64, HASH_HIGH_RISK_RESULTS)),
            ("baseline_hash_low.md",
             generate_hash_report("f" * 64, HASH_LOW_RISK_RESULTS)),
            ("baseline_url_medium.md",
             generate_url_report("https://suspicious.example.org/login", URL_MEDIUM_RISK_RESULTS)),
            ("baseline_url_low.md",
             generate_url_report("https://google.com/", URL_LOW_RISK_RESULTS)),
        ]

        for name, content in cases:
            path = os.path.join(fixtures_dir, name)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  ✓ {name} ({len(content)} chars)")

    print(f"\n  共生成 {len(cases)} 份基线报告 → {fixtures_dir}")


if __name__ == "__main__":
    main()
