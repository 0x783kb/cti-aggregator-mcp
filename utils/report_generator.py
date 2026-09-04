"""
威胁情报报告生成模块
统一输出格式：核心预警 → Emoji 章节编号 → 风险评估矩阵 → 三级处置建议

本文件保留三份报告（IP/域名/HASH/URL）各自的章节组装逻辑；
跨报告重复的渲染片段（头部/摘要/风险表/IOC/尾部）抽到 utils/report_renderer.py。
"""

import socket
from typing import List, Dict, Any

from .report_renderer import (
    render_header,
    render_alert_summary,
    render_section_heading,
    render_subsection_heading,
    render_risk_table,
    render_judgment_heading,
    render_recommendations_heading,
    render_ioc_intro,
    render_footer,
    _defang_ioc,
    _format_timestamp,
    _coerce_unix_timestamp,
    _format_file_size,
    _pct,
    _risk_badge,
    now_utc8_str,
)


# ============================================================
# generate_report — IP / 域名共用
# ============================================================

def generate_report(target: str, results: List[Dict[str, Any]], report_type: str = "ip") -> str:
    """生成专业格式的威胁情报分析报告（使用示例风格）"""

    # --- 解析数据 ---
    data_map = {}
    for res in results:
        source = res.get("source", "Unknown")
        if res.get("status") == "success":
            data_map[source] = res.get("data", {})

    vt_data = data_map.get("VirusTotal", {})
    abuse_data = data_map.get("AbuseIPDB", {})
    ipinfo_data = data_map.get("IPInfo", {})
    icp_data = data_map.get("ICP Filing", {}).get("results", [])
    shodan_data = data_map.get("PortScan", {})
    fofa_data = data_map.get("FOFA", {})
    rdap_data = data_map.get("RDAP", {}) or data_map.get("LocalWhois", {})
    fp_data = data_map.get("WebFingerprint", {})
    otx_data = data_map.get("AlienVault OTX", {})
    threatfox_data = data_map.get("ThreatFox", {})
    ssl_jarm_data = data_map.get("SSL/JARM", {})

    # --- 风险研判 ---
    malicious = vt_data.get('malicious', 0)
    total_vt = malicious + vt_data.get('harmless', 0) + vt_data.get('suspicious', 0) + vt_data.get('undetected', 0)
    apt_groups = otx_data.get("apt_groups", [])
    samples = vt_data.get("communicating_files", []) or vt_data.get("related_samples", [])
    pulses = otx_data.get("pulses", [])

    if malicious > 5 or len(apt_groups) > 0:
        risk_level = "🔴 High"
        risk_label = "🔴 **恶意**"
    elif malicious > 0 or len(samples) > 0:
        risk_level = "🟡 Medium"
        risk_label = "⚠️ **可疑**"
    else:
        risk_level = "🟢 Low"
        risk_label = "✅ **正常**"

    analysis_time = now_utc8_str()

    # --- 域名辅助数据 ---
    cur_v4 = []
    hist_ips = []
    if report_type == "domain":
        try:
            infos = socket.getaddrinfo(target, None)
            for _, _, _, _, addr in infos:
                ip = addr[0]
                if ":" not in ip and ip not in cur_v4:
                    cur_v4.append(ip)
        except Exception:
            pass
        resolved_ips = vt_data.get("resolved_ips", [])
        hist_ips = [ip.get('ip', ip) if isinstance(ip, dict) else ip for ip in resolved_ips] if resolved_ips else []

    open_ports = shodan_data.get("open_ports", [])
    fofa_assets = fofa_data.get("assets", [])

    # ==================== 报告开始 ====================
    type_label = "域名" if report_type == "domain" else "IP"
    r = []
    r.extend(render_header(f"{type_label} 威胁情报分析报告：{target}", risk_level))

    # --- 核心预警摘要 ---
    alert_rows = [
        f"| **VirusTotal** | {'🔴' if malicious > 0 else '🟢'} {malicious}/{total_vt} 恶意引擎标记 |"
    ]
    if report_type == "ip":
        alert_rows.append(f"| **AbuseIPDB** | {'🔴' if abuse_data.get('score', 0) > 50 else '🟢'} 置信度 {abuse_data.get('score', 0)}% |")
    if apt_groups:
        alert_rows.append(f"| **APT 关联** | ⚠️ 关联 {', '.join(apt_groups)} 恶意活动 |")
    if samples:
        alert_rows.append(f"| **恶意样本** | 🔴 发现 {len(samples)} 个关联恶意软件 |")
    if pulses and not apt_groups:
        alert_rows.append(f"| **OTX 情报** | ⚠️ {len(pulses)} 条威胁脉冲 |")
    if not apt_groups and not samples:
        alert_rows.append(f"| **关联威胁** | 🟢 无已知关联 |")
    r.extend(render_alert_summary(alert_rows))

    # ==================== 1️⃣ 基础信息 ====================
    r.extend(render_section_heading("1️⃣", "基础信息"))

    if report_type == "domain":
        registrar = rdap_data.get('registrar') or vt_data.get('registrar') or 'N/A'
        creation_date = rdap_data.get('creation_date') or vt_data.get('creation_date') or 'N/A'
        nameservers = rdap_data.get('nameservers', [])
        ns_str = ", ".join(nameservers[:2]) if nameservers else 'N/A'
        registrant_org = rdap_data.get('org') or '隐私保护/未公开'
        domain_age_days = "N/A"
        try:
            from datetime import datetime as dt
            if isinstance(creation_date, str) and creation_date != 'N/A':
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
                    try:
                        created_dt = dt.strptime(creation_date, fmt)
                        age = (dt.now() - created_dt).days
                        domain_age_days = f"{age} 天"
                        break
                    except ValueError:
                        continue
        except Exception:
            pass

        r.append(f"- **域名**: `{target}`")
        r.append(f"- **注册商**: {registrar}")
        r.append(f"- **注册组织**: {registrant_org}")
        r.append(f"- **注册时间**: {creation_date}")
        if domain_age_days != "N/A":
            r.append(f"- **域名年龄**: {domain_age_days}")
        r.append(f"- **DNS 服务器**: {ns_str}")
        r.append(f"- **ICP 备案**: {'已备案' if icp_data else '未备案'}")
        if cur_v4:
            r.append(f"- **当前解析 IP**: `{', '.join(cur_v4[:5])}`")
        if domain_age_days != "N/A":
            try:
                age_num = int(domain_age_days.split()[0])
                if age_num < 30:
                    r.append("")
                    r.append(f"> ⚠️ **域名注册时间极短（仅 {domain_age_days}），符合短期恶意基础设施典型特征**")
            except Exception:
                pass
    else:
        city = ipinfo_data.get("city", "N/A")
        region = ipinfo_data.get("region", "N/A")
        country = ipinfo_data.get("country", "N/A")
        org = ipinfo_data.get("organization") or ipinfo_data.get("org", "N/A")
        asn = ipinfo_data.get("asn", "N/A")
        ip_type = ipinfo_data.get("ip_type", "N/A")
        rdns = ipinfo_data.get("rdns", "")

        r.append(f"- **IP 地址**: `{target}`")
        if rdns and rdns != "N/A":
            r.append(f"- **反向 DNS**: `{rdns}`")
        r.append(f"- **ASN / ISP**: AS{asn} {org}")
        r.append(f"- **主机类型**: {ip_type}")
        r.append(f"- **地理位置**: {country}, {region}, {city}")

    r.append("")

    # ==================== 2️⃣ 威胁情报分析 ====================
    r.extend(render_section_heading("2️⃣", "威胁情报分析"))

    # --- VirusTotal ---
    vt_emoji = "🔴" if malicious > 5 else "🟠" if malicious > 0 else "🟢"
    r.extend(render_subsection_heading(vt_emoji, "VirusTotal 信誉评分"))
    r.append(f"- **恶意**: {malicious} 家安全厂商标记")
    r.append(f"- **无害**: {vt_data.get('harmless', 0)} 家")
    r.append(f"- **未检测**: {vt_data.get('undetected', 0)} 家")
    if vt_data.get('first_submission_date'):
        r.append(f"- **首次提交**: {_format_timestamp(vt_data['first_submission_date']).split()[0]}")
    vt_tags = vt_data.get('tags', [])
    if vt_tags:
        r.append(f"- **标签**: {', '.join(vt_tags[:5])}")
    if report_type == "ip" and abuse_data.get('score', 0) > 0:
        r.append(f"- **AbuseIPDB**: 置信度 {abuse_data.get('score')}%")
    r.append("")

    # --- OTX ---
    if pulses:
        otx_emoji = "🔴" if apt_groups else "⚠️"
        r.extend(render_subsection_heading(otx_emoji, "AlienVault OTX 威胁情报"))
        r.append(f"发现 **{len(pulses)} 条**威胁情报{'，均与 **' + ', '.join(apt_groups) + '** 相关' if apt_groups else ''}：")
        r.append("")
        for i, p in enumerate(pulses[:3], 1):
            r.append(f"{i}. **{p.get('name', 'N/A')}**")
        if apt_groups:
            r.append("")
            r.append(f"> **{', '.join(apt_groups)}** 是{'朝鲜' if any('APT37' in g or 'Lazarus' in g for g in apt_groups) else ''}支持的高级持续性威胁组织，主要针对特定目标进行网络间谍活动。")
        r.append("")

    # --- 恶意样本 ---
    if samples:
        r.extend(render_subsection_heading("🦠", "关联恶意样本"))
        r.append("")
        r.append("| 时间 | 样本 Hash | 文件名 | 检测率 | 类型 |")
        r.append("|------|----------|--------|--------|------|")

        malware_family_map = {}
        samples_with_ts = []
        for s in samples:
            ts = _coerce_unix_timestamp(s.get("date") or s.get("creation_date") or 0)
            samples_with_ts.append((ts, s))
            for name in (s.get("meaningful_names", []) or []):
                if isinstance(name, str) and 2 < len(name) < 40:
                    malware_family_map.setdefault(name, 0)
                    malware_family_map[name] += 1
        samples_with_ts.sort(key=lambda x: x[0], reverse=True)

        for ts, s in samples_with_ts[:5]:
            sha256 = s.get("sha256", "N/A")
            short_hash = sha256[:8] if sha256 != "N/A" else "N/A"
            date_str = _format_timestamp(ts).split()[0] if ts else "N/A"
            sample_type = s.get("type_description") or s.get("type") or "Unknown"
            score = s.get("score", "N/A")
            total_engines = s.get("total", 76)
            if isinstance(score, (int, float)) and total_engines:
                detection_str = f"**{score}/{total_engines}**"
            else:
                detection_str = str(score)
            names = s.get("meaningful_names", []) or []
            family_name = names[0] if names else ""
            r.append(f"| {date_str} | `{short_hash}...` | {family_name or '-'} | {detection_str} | {sample_type} |")

        if malware_family_map:
            top_families = sorted(malware_family_map.items(), key=lambda x: x[1], reverse=True)[:3]
            family_str = " / ".join([f[0] for f in top_families])
            r.append("")
            r.append(f"**恶意软件家族**: {family_str}")
        r.append("")

    # --- ThreatFox ---
    tf_records = threatfox_data.get("records", []) if threatfox_data else []
    tf_families = threatfox_data.get("malware_families", []) if threatfox_data else []
    if tf_records:
        r.extend(render_subsection_heading("🔍", "ThreatFox 情报关联"))
        if tf_families:
            r.append(f"**恶意软件家族**: {', '.join(tf_families[:5])}")
        r.append("")
        r.append("| IOC | 类型 | 恶意软件 | 置信度 |")
        r.append("|-----|------|----------|--------|")
        for rec in tf_records[:5]:
            r.append(f"| `{_defang_ioc(str(rec.get('ioc', '')))}` | {rec.get('type', '')} | {rec.get('malware', '')} | {rec.get('confidence', '')} |")
        r.append("")

    r.append("")

    # ==================== 3️⃣ 开放端口与服务 ====================
    r.extend(render_section_heading("3️⃣", "开放端口与服务"))

    if open_ports:
        r.extend(render_subsection_heading("", f"Shodan 扫描结果（{len(open_ports)} 个端口）"))
        for p in open_ports[:8]:
            port = p.get('port', '?')
            service = p.get('service', 'Unknown')
            version = p.get('version', '')
            ver_str = f" ({version})" if version else ""
            r.append(f"- **{port}**: {service}{ver_str}")
        r.append("")

    if fofa_assets:
        seen_ports = set()
        unique_assets = [a for a in fofa_assets if a.get('port', 'N/A') not in seen_ports and not seen_ports.add(a.get('port', 'N/A'))]
        r.extend(render_subsection_heading("", f"FOFA 详细扫描（{len(fofa_assets)} 个资产）"))
        r.append("")
        for a in unique_assets[:12]:
            port = a.get('port', 'N/A')
            title = (a.get('title', '') or a.get('service', 'N/A')).strip()
            if len(title) > 40:
                title = title[:40] + "..."
            server = a.get('server', '')
            jarm = a.get('jarm', '')
            notes = []
            if server:
                notes.append(f"Server: {server}")
            if jarm:
                notes.append(f"JARM: {jarm[:16]}...")
            note_str = ", ".join(notes) if notes else ""
            r.append(f"- **{port}**: {title}{' — ' + note_str if note_str else ''}")
        r.append("")

    if not open_ports and not fofa_assets:
        r.append("- 未发现开放端口")
        r.append("")

    # --- SSL / JARM ---
    ssl_info = ssl_jarm_data.get("ssl", {})
    jarm_list = []
    jarm_info = ssl_jarm_data.get("jarm", {})
    if jarm_info and jarm_info.get("status") == "success":
        jarm_list.append(jarm_info.get('raw'))
    for j in shodan_data.get("jarm_fingerprints", [])[:3]:
        jarm_list.append(j)
    fofa_jarm_set = {a.get("jarm") for a in fofa_data.get("assets", [])[:20] if isinstance(a.get("jarm"), str) and a.get("jarm")}
    jarm_list.extend(list(fofa_jarm_set)[:3])

    if ssl_info and ssl_info.get("valid"):
        subject = ssl_info.get("subject", {})
        issuer = ssl_info.get("issuer", {})
        r.append(f"🔒 **SSL 证书**: 颁发给 `{subject.get('commonName', 'N/A')}`，颁发机构 {issuer.get('commonName', 'N/A')}")
    else:
        r.append("🔒 **SSL 证书**: 未检测到有效证书")

    if jarm_list:
        unique_jarms = list(set(jarm_list))[:3]
        r.append(f"🔑 **JARM 指纹**: `{', '.join(unique_jarms)}`")
    r.append("")

    # ==================== 4️⃣ 风险评估 ====================
    risk_rows = []

    # 恶意活动
    if apt_groups:
        risk_rows.append(f"| **恶意活动** | 🔴 极高 | 关联 {', '.join(apt_groups)} 国家级黑客组织 |")
    elif malicious > 5:
        risk_rows.append(f"| **恶意活动** | 🔴 高 | {malicious}/{total_vt} 安全厂商标记为恶意 |")
    elif malicious > 0:
        risk_rows.append(f"| **恶意活动** | 🟠 中高 | {malicious}/{total_vt} 安全厂商标记为恶意 |")
    else:
        risk_rows.append(f"| **恶意活动** | 🟢 低 | 无安全厂商直接标记为恶意 |")

    # 恶意软件
    if samples:
        risk_rows.append(f"| **恶意软件** | 🔴 高 | 直接关联 {len(samples)} 个恶意样本 |")
    elif tf_records:
        risk_rows.append(f"| **恶意软件** | 🟠 中高 | ThreatFox 存在关联记录 |")
    else:
        risk_rows.append(f"| **恶意软件** | 🟢 低 | 未发现关联恶意软件 |")

    # 端口暴露
    if open_ports:
        high_risk_ports = [p for p in open_ports if p.get('port') in [22, 23, 3389, 5985, 445]]
        if high_risk_ports:
            risk_rows.append(f"| **端口暴露** | 🟠 中高 | 高危端口暴露（{', '.join([str(p.get('port')) for p in high_risk_ports[:4]])}）|")
        else:
            risk_rows.append(f"| **端口暴露** | 🟡 中 | {len(open_ports)} 个端口开放 |")
    else:
        risk_rows.append(f"| **端口暴露** | 🟢 低 | 未发现开放端口 |")

    # 基础设施
    if report_type == "ip":
        ip_type = ipinfo_data.get("ip_type", "")
        if "Hosting" in str(ip_type) or "IDC" in str(ip_type):
            risk_rows.append(f"| **基础设施** | 🟠 中 | 托管在 IDC，可能为被攻陷服务器 |")
        elif ip_type and ip_type != "N/A":
            risk_rows.append(f"| **基础设施** | 🟡 中 | {ip_type} |")
        else:
            risk_rows.append(f"| **基础设施** | 🟢 低 | — |")
    else:
        if rdap_data.get('org') == '隐私保护/未公开' or not rdap_data.get('registrar'):
            risk_rows.append(f"| **基础设施** | 🟠 中 | 注册信息隐私保护，溯源困难 |")
        else:
            risk_rows.append(f"| **基础设施** | 🟡 中 | 注册商 {rdap_data.get('registrar', 'N/A')} |")

    r.extend(render_risk_table("4", risk_rows))

    # ==================== 🎯 综合研判 ====================
    r.extend(render_judgment_heading())

    if risk_level == "🔴 High":
        r.append(f"该{type_label}具有**多重高危特征**：")
        r.append("")
        idx = 1
        if apt_groups:
            r.append(f"{idx}. ✅ **确认与 APT 组织相关**：AlienVault OTX 明确标记为 {', '.join(apt_groups)} 基础设施")
            idx += 1
        if malicious > 0:
            r.append(f"{idx}. ✅ **多引擎恶意检出**：{malicious}/{total_vt} 个安全厂商标记为恶意")
            idx += 1
        if samples:
            r.append(f"{idx}. ✅ **分发恶意软件**：关联 {len(samples)} 个高检测率恶意样本")
            idx += 1
        if open_ports:
            r.append(f"{idx}. ✅ **典型 C2 服务器特征**：开放 {len(open_ports)} 个端口，多协议 C2 通信能力")
            idx += 1
        if abuse_data.get('score', 0) > 50:
            r.append(f"{idx}. ✅ **AbuseIPDB 高置信度**：恶意置信度 {abuse_data.get('score')}%")
            idx += 1

        # 低风险因素
        low_risk = []
        if total_vt > 0 and malicious / total_vt < 0.1:
            low_risk.append("VirusTotal 检出率低于 10%")
        if not abuse_data.get('score', 0):
            low_risk.append(f"{type_label}本身未被 AbuseIPDB 列入黑名单")
        if low_risk:
            r.append("")
            r.append("**低风险因素**: " + "；".join(low_risk))

    elif risk_level == "🟡 Medium":
        r.append(f"该{type_label}存在**可疑特征**，需要关注：")
        r.append("")
        idx = 1
        if malicious > 0:
            r.append(f"{idx}. ⚠️ **部分引擎检出**：{malicious}/{total_vt} 个安全厂商标记为恶意")
            idx += 1
        if samples:
            r.append(f"{idx}. ⚠️ **恶意样本关联**：发现 {len(samples)} 个关联样本")
            idx += 1
        if pulses:
            r.append(f"{idx}. ⚠️ **威胁情报关联**：OTX 中 {len(pulses)} 条情报脉冲相关")
            idx += 1
        if report_type == "domain" and rdap_data.get('org') == '隐私保护/未公开':
            r.append(f"{idx}. ⚠️ **注册信息隐藏**：使用隐私保护服务，增加溯源难度")
            idx += 1

        low_risk = []
        if not apt_groups:
            low_risk.append("未发现与已知 APT 组织的直接关联")
        if not abuse_data.get('score', 0):
            low_risk.append(f"{type_label}未被 AbuseIPDB 列入黑名单")
        if low_risk:
            r.append("")
            r.append("**低风险因素**: " + "；".join(low_risk))
    else:
        r.append(f"该{type_label}目前**未发现明显恶意行为**。")
        normal_evidence = []
        if total_vt > 0 and malicious == 0:
            normal_evidence.append("无安全厂商直接标记为恶意")
        if not abuse_data.get('score', 0):
            normal_evidence.append("未被 AbuseIPDB 列入黑名单")
        if not samples:
            normal_evidence.append("未发现关联恶意样本")
        if normal_evidence:
            r.append("")
            r.append("**支持正常的证据**: " + "；".join(normal_evidence))

        concerns = []
        if open_ports and len(open_ports) > 3:
            concerns.append(f"暴露面较大（{len(open_ports)} 个端口）")
        if not ipinfo_data.get("city"):
            concerns.append("地理位置/ASN 信息缺失")
        if concerns:
            r.append("")
            r.append("**需关注**: " + "；".join(concerns))

    r.append("")

    # ==================== 📋 处置建议 ====================
    r.extend(render_recommendations_heading())

    if risk_level == "🔴 High":
        r.append("#### 立即行动：")
        r.append(f"- ❌ **禁止任何与该{type_label}的通信**")
        r.append(f"- 🔥 在防火墙/边界设备添加黑名单规则")
        r.append(f"- 🔍 检查内部是否有主机与该{type_label}有过连接")
        r.append(f"- 📊 如已连接，立即隔离相关主机并进行取证")
        r.append("")
        r.append("#### 深度排查：")
        r.append(f"- 📝 检查防火墙日志，搜索该{type_label}的所有出入站记录")
        r.append("- 🦠 对可能受影响的主机进行全盘恶意软件扫描")
        if apt_groups:
            r.append(f"- 📧 检查邮件网关，防范 {', '.join(apt_groups)} 钓鱼邮件")
        r.append("- 🔐 审查 RDP/SMB 等服务的访问控制策略")
        r.append("")
        r.append("#### 威胁狩猎：")
        r.append(f"- 在 SIEM 中添加该{type_label}为 IOC")
        if report_type == "ip":
            r.append(f"- 监控与该 IP 同网段的其他地址（{'.'.join(target.split('.')[:3])}.0/24）")
        if apt_groups:
            r.append(f"- 关注 {', '.join(apt_groups)} 最新 TTPs 和 IOCs")
        if samples:
            for s in samples[:2]:
                sha256 = s.get("sha256", "")
                if sha256:
                    r.append(f"- 搜索样本 SHA256: `{sha256[:16]}...`")

    elif risk_level == "🟡 Medium":
        r.append("#### 立即行动：")
        r.append(f"- ⚠️ 考虑限制对 `{target}` 的出站连接，开启出站流量审计")
        r.append("- 🚫 限制非业务必要的对外连接")
        r.append(f"- 🔍 检索过去 30 天内是否有内网用户访问该{type_label}")
        r.append("")
        r.append("#### 持续监控：")
        r.append(f"- 将该{type_label}加入威胁监控列表，关注其信誉变化")
        r.append("- 每周复查一次威胁情报状态")
        r.append("- 关注新增关联样本和被动 DNS 记录")
        r.append("- 若发现异常，立即提升风险等级并采取封禁措施")

    else:
        r.append("#### 常规关注：")
        r.append(f"- 🟢 无需立即封禁，可保持正常访问")
        r.append("- 建议将目标加入监控列表，定期复查信誉变化")
        if report_type == "ip" and open_ports:
            r.append("")
            r.append("#### 端口安全加固（如为自有资产）：")
            r.append("- 限制管理面板的访问来源 IP")
            r.append("- 确保管理面板使用强密码和双因素认证")
            r.append("- 配置有效的 SSL 证书")
        r.append("")
        r.append("#### 持续监控：")
        r.append("- 每月复查一次 VirusTotal 信誉变化")
        r.append("- 若发现异常，立即提升风险等级")

    r.append("")

    # ==================== IOC 清单 ====================
    r.extend(render_ioc_intro())

    if risk_level in ("🔴 High", "🟡 Medium"):
        ioc_rows = [
            f"| `{target}` | {type_label} | {risk_level} | {'恶意软件C2服务器' if risk_level == '🔴 High' else '可疑基础设施'} |"
        ]
        if samples:
            for s in samples[:3]:
                sha256 = s.get("sha256", "N/A")
                short_hash = sha256[:16] + "..." if sha256 != "N/A" else "N/A"
                ioc_rows.append(f"| `{short_hash}` | SHA256 | 🔴 High | 关联恶意样本 |")
        if report_type == "ip":
            resolutions = vt_data.get("resolutions", [])
            for res_obj in resolutions[:3]:
                hostname = res_obj.get('host_name')
                if hostname:
                    ioc_rows.append(f"| `{_defang_ioc(hostname)}` | 域名 | 🟡 Medium | C2 关联域名 |")
        else:
            for ip in cur_v4[:3]:
                ioc_rows.append(f"| `{ip}` | IP | 🟡 Medium | 当前解析 IP |")
        r.append("| IOC | 类型 | 威胁等级 | 说明 |")
        r.append("|-----|------|----------|------|")
        r.extend(ioc_rows)
        r.append("")
    else:
        r.append("暂无需立即封禁的 IOC")
        r.append("")

    r.extend(render_footer(analysis_time))

    return "\n".join(r)


# ============================================================
# generate_hash_report — 文件哈希
# ============================================================

def generate_hash_report(hash_value: str, results: List[Dict[str, Any]]) -> str:
    """生成文件哈希威胁情报分析报告"""

    data_map = {}
    for res in results:
        source = res.get("source", "Unknown")
        if res.get("status") == "success":
            data_map[source] = res.get("data", {})

    vt_data = data_map.get("VirusTotal (File)", {})
    tf_data = data_map.get("ThreatFox", {})

    malicious = vt_data.get("malicious", 0)
    total = vt_data.get("total_engines", 0)
    suspicious = vt_data.get("suspicious", 0)
    sha256 = vt_data.get("sha256", hash_value)
    md5 = vt_data.get("md5", "N/A")
    sha1 = vt_data.get("sha1", "N/A")
    file_type = vt_data.get("file_type", "Unknown")
    file_size = vt_data.get("file_size", 0)
    meaningful_name = vt_data.get("meaningful_name", "N/A")
    threat_category = vt_data.get("threat_category", "")
    threat_categories = vt_data.get("threat_categories", [])
    tags = vt_data.get("tags", [])
    contacted_ips = vt_data.get("contacted_ips", [])
    contacted_domains = vt_data.get("contacted_domains", [])
    pe_info = vt_data.get("pe_info", {})
    trid = vt_data.get("trid", [])
    signature_info = vt_data.get("signature_info", {})
    names = vt_data.get("names", [])

    tf_records = tf_data.get("records", []) if tf_data else []
    tf_families = tf_data.get("malware_families", []) if tf_data else []

    if malicious > 10:
        risk_level = "🔴 High"
        risk_label = "🔴 **恶意**"
    elif malicious > 0 or suspicious > 3:
        risk_level = "🟡 Medium"
        risk_label = "⚠️ **可疑**"
    else:
        risk_level = "🟢 Low"
        risk_label = "✅ **正常**"

    analysis_time = now_utc8_str()

    r = []
    r.extend(render_header(f"文件哈希威胁情报分析报告：`{hash_value[:24]}...`", risk_level))

    # --- 核心预警摘要 ---
    alert_rows = [
        f"| **VirusTotal** | {'🔴' if malicious > 5 else '🟠' if malicious > 0 else '🟢'} {malicious}/{total} 恶意引擎标记 |"
    ]
    if threat_category:
        alert_rows.append(f"| **威胁分类** | 🔴 {threat_category} |")
    if tf_families:
        alert_rows.append(f"| **恶意软件家族** | 🔴 {', '.join(tf_families[:3])} |")
    if contacted_ips or contacted_domains:
        total_c2 = len(contacted_ips) + len(contacted_domains)
        alert_rows.append(f"| **C2 通信** | 🔴 关联 {total_c2} 个 C2 基础设施 |")
    if not threat_category and not tf_families and not contacted_ips and not contacted_domains:
        alert_rows.append(f"| **关联威胁** | 🟢 无已知关联 |")
    r.extend(render_alert_summary(alert_rows))

    # ==================== 1️⃣ 文件基本信息 ====================
    r.extend(render_section_heading("1️⃣", "文件基本信息"))
    r.append(f"- **SHA256**: `{sha256}`")
    if md5 and md5 != "N/A":
        r.append(f"- **MD5**: `{md5}`")
    if sha1 and sha1 != "N/A":
        r.append(f"- **SHA1**: `{sha1}`")
    r.append(f"- **文件类型**: {file_type}")
    r.append(f"- **文件大小**: {_format_file_size(file_size)}")
    r.append(f"- **检出率**: {malicious}/{total} ({_pct(malicious, total)})")
    if meaningful_name and meaningful_name != "N/A":
        r.append(f"- **识别名称**: {meaningful_name}")
    if threat_category:
        r.append(f"- **威胁分类**: {threat_category}")
    if tags:
        r.append(f"- **标签**: {', '.join(str(t) for t in tags[:8])}")
    r.append("")

    # ==================== 2️⃣ 威胁检测分析 ====================
    r.extend(render_section_heading("2️⃣", "威胁检测分析"))
    r.append(f"- **恶意**: {malicious}/{total} ({_pct(malicious, total)})")
    r.append(f"- **可疑**: {suspicious}")
    r.append(f"- **无害**: {vt_data.get('harmless', 0)}")
    r.append(f"- **未检测**: {vt_data.get('undetected', 0)}")
    if vt_data.get("first_submission_date"):
        r.append(f"- **首次提交**: {_format_timestamp(vt_data['first_submission_date'])}")
    if vt_data.get("last_analysis_date"):
        r.append(f"- **最后分析**: {_format_timestamp(vt_data['last_analysis_date'])}")
    if vt_data.get("creation_date"):
        r.append(f"- **文件创建时间**: {_format_timestamp(vt_data['creation_date'])}")
    r.append("")

    if threat_categories:
        r.append(f"**威胁分类**: {', '.join(str(c) for c in threat_categories[:5])}")
        r.append("")

    # ThreatFox
    if tf_records:
        r.extend(render_subsection_heading("🔍", "ThreatFox 情报关联"))
        if tf_families:
            r.append(f"**恶意软件家族**: {', '.join(tf_families[:5])}")
        r.append("")
        r.append("| IOC | 类型 | 恶意软件 | 置信度 | 首次发现 |")
        r.append("|-----|------|----------|--------|----------|")
        for rec in tf_records[:5]:
            r.append(f"| `{_defang_ioc(str(rec.get('ioc', '')))}` | {rec.get('type', '')} | {rec.get('malware', '')} | {rec.get('confidence', '')} | {rec.get('first_seen', '')} |")
        r.append("")

    # ==================== 3️⃣ 网络行为分析 ====================
    r.extend(render_section_heading("3️⃣", "网络行为分析 (C2 通信)"))

    if contacted_ips:
        r.extend(render_subsection_heading("🔴", "关联 C2 IP"))
        r.append("")
        r.append("| IP | 国家 | 运营商 | 恶意检出 |")
        r.append("|----|------|--------|----------|")
        for ip_info in contacted_ips[:10]:
            r.append(f"| `{_defang_ioc(str(ip_info.get('ip', '')))}` | {ip_info.get('country', '')} | {ip_info.get('as_owner', '')} | {ip_info.get('malicious', 0)} |")
        r.append("")

    if contacted_domains:
        r.extend(render_subsection_heading("🔴", "关联 C2 域名"))
        r.append("")
        r.append("| 域名 | 恶意检出 | 注册时间 |")
        r.append("|------|----------|----------|")
        for dom_info in contacted_domains[:10]:
            dom = _defang_ioc(str(dom_info.get('domain', '')))
            dom_date = dom_info.get("creation_date")
            date_str = _format_timestamp(dom_date) if dom_date and dom_date != "N/A" else "N/A"
            r.append(f"| `{dom}` | {dom_info.get('malicious', 0)} | {date_str} |")
        r.append("")

    if not contacted_ips and not contacted_domains:
        r.append("- 未发现关联的网络通信")
        r.append("")

    # ==================== 4️⃣ 文件特征分析 ====================
    r.extend(render_section_heading("4️⃣", "文件特征分析"))

    if pe_info:
        r.extend(render_subsection_heading("🔧", "PE 信息"))
        r.append(f"- **目标平台**: {pe_info.get('machine_type', 'N/A')}")
        r.append(f"- **入口点**: {pe_info.get('entry_point', 'N/A')}")
        if pe_info.get("imphash"):
            r.append(f"- **Imphash**: `{pe_info['imphash']}`")
        r.append("")

    if trid:
        r.extend(render_subsection_heading("📄", "文件类型识别 (TrID)"))
        for t in trid[:5]:
            if isinstance(t, str):
                r.append(f"- {t}")
        r.append("")

    if signature_info and signature_info.get("signers"):
        verified = signature_info.get('verified') == 'Signed'
        r.extend(render_subsection_heading("🔏", "代码签名"))
        r.append(f"- **签名者**: {signature_info.get('signers', 'N/A')}")
        r.append(f"- **验证状态**: {'✅ 已验证' if verified else '❌ 未验证/无效'}")
        r.append("")

    if names:
        r.append(f"**已知名称**: {', '.join(str(n) for n in names[:5])}")
        r.append("")

    # ==================== 5️⃣ 风险评估 ====================
    risk_rows = []
    if malicious > 10:
        risk_rows.append(f"| **恶意检出** | 🔴 极高 | {malicious}/{total} 引擎标记为恶意 |")
    elif malicious > 0:
        risk_rows.append(f"| **恶意检出** | 🟠 中高 | {malicious}/{total} 引擎标记为恶意 |")
    else:
        risk_rows.append(f"| **恶意检出** | 🟢 低 | 无引擎标记为恶意 |")

    if contacted_ips or contacted_domains:
        total_c2 = len(contacted_ips) + len(contacted_domains)
        risk_rows.append(f"| **C2 通信** | 🔴 高 | 关联 {total_c2} 个 C2 基础设施 |")
    else:
        risk_rows.append(f"| **C2 通信** | 🟢 低 | 未发现 C2 通信行为 |")

    if tf_families:
        risk_rows.append(f"| **恶意软件家族** | 🔴 高 | ThreatFox 确认: {', '.join(tf_families[:3])} |")
    elif threat_category:
        risk_rows.append(f"| **威胁分类** | 🟠 中高 | 已知分类: {threat_category} |")
    else:
        risk_rows.append(f"| **威胁分类** | 🟡 中 | 未分类 |")

    r.extend(render_risk_table("5", risk_rows))

    # ==================== 🎯 综合研判 ====================
    r.extend(render_judgment_heading())

    if risk_level == "🔴 High":
        r.append(f"该文件被判定为**高危恶意软件**：")
        r.append("")
        idx = 1
        if malicious > 0:
            r.append(f"{idx}. ✅ **多引擎恶意检出**: {malicious}/{total} 个安全引擎标记为恶意")
            idx += 1
        if threat_category:
            r.append(f"{idx}. ✅ **已知威胁分类**: 归类为 `{threat_category}`")
            idx += 1
        if contacted_ips or contacted_domains:
            total_c2 = len(contacted_ips) + len(contacted_domains)
            r.append(f"{idx}. ✅ **C2 通信行为**: 关联 {total_c2} 个 C2 基础设施")
            idx += 1
        if tf_families:
            r.append(f"{idx}. ✅ **ThreatFox 确认**: 关联恶意软件家族 {', '.join(tf_families[:3])}")
            idx += 1
    elif risk_level == "🟡 Medium":
        r.append(f"该文件被判定为**可疑**：")
        r.append("")
        if malicious > 0:
            r.append(f"1. ⚠️ **部分引擎检出**: {malicious}/{total} 个引擎标记为恶意")
        if suspicious > 0:
            r.append(f"2. ⚠️ **可疑判定**: {suspicious} 个引擎标记为可疑")
    else:
        r.append(f"该文件目前**未发现明显恶意行为**。")

    r.append("")

    # ==================== 📋 处置建议 ====================
    r.extend(render_recommendations_heading())

    if risk_level in ("🔴 High", "🟡 Medium"):
        r.append("#### 立即行动：")
        r.append("- 🚫 **立即隔离**: 在所有终端上隔离或删除该文件")
        if contacted_domains:
            r.append("#### 封禁 C2 基础设施：")
            for dom_info in contacted_domains[:3]:
                r.append(f"- 封禁域名 `{_defang_ioc(str(dom_info.get('domain', '')))}`")
        if contacted_ips:
            for ip_info in contacted_ips[:3]:
                r.append(f"- 封禁 IP `{_defang_ioc(str(ip_info.get('ip', '')))}`")
        r.append("")
        r.append("#### 深度排查：")
        r.append("- 🔍 搜索内网是否有主机下载或执行过该样本")
        r.append("- 🧪 提交到沙箱环境进行动态行为分析")
        r.append("- 📝 排查相关 IOC 在内网的出现记录")
        r.append("")
        r.append("#### 威胁狩猎：")
        r.append(f"- 在 SIEM 中添加 SHA256: `{sha256[:32]}...` 为 IOC")
        if contacted_domains:
            r.append(f"- 监控 DNS 日志中对该域名的解析请求")
        if contacted_ips:
            r.append(f"- 监控防火墙日志中对 C2 IP 的连接记录")
    else:
        r.append("#### 常规关注：")
        r.append("- 🟢 建议持续关注该文件的检出率变化")
        r.append("- 如有疑虑可提交沙箱进行动态分析")

    r.append("")

    # ==================== IOC 清单 ====================
    r.extend(render_ioc_intro())

    ioc_rows = [f"| `{sha256[:32]}...` | SHA256 | {risk_level} | 恶意文件 |"]
    if md5 and md5 != "N/A":
        ioc_rows.append(f"| `{md5}` | MD5 | {risk_level} | 恶意文件 |")
    for ip_info in contacted_ips[:3]:
        ioc_rows.append(f"| `{_defang_ioc(str(ip_info.get('ip', '')))}` | IP | 🟡 Medium | C2 通信 |")
    for dom_info in contacted_domains[:3]:
        ioc_rows.append(f"| `{_defang_ioc(str(dom_info.get('domain', '')))}` | 域名 | 🟡 Medium | C2 通信 |")
    r.append("| IOC | 类型 | 威胁等级 | 说明 |")
    r.append("|-----|------|----------|------|")
    r.extend(ioc_rows)
    r.append("")
    r.append(f"🔗 **VT 报告链接**: https://www.virustotal.com/gui/file/{sha256}")
    r.append("")
    r.extend(render_footer(analysis_time))

    return "\n".join(r)


# ============================================================
# generate_url_report — URL
# ============================================================

def generate_url_report(url: str, results: List[Dict[str, Any]]) -> str:
    """生成 URL 威胁情报分析报告"""

    data_map = {}
    for res in results:
        source = res.get("source", "Unknown")
        if res.get("status") == "success":
            data_map[source] = res.get("data", {})

    vt_data = data_map.get("VirusTotal (URL)", {})

    malicious = vt_data.get("malicious", 0)
    total = vt_data.get("total_engines", 0)
    suspicious = vt_data.get("suspicious", 0)
    domain = vt_data.get("domain", "")
    domain_info = vt_data.get("domain_info", {})
    domain_samples = vt_data.get("domain_samples", [])
    direct_ip = vt_data.get("direct_ip", "")
    tags = vt_data.get("tags", [])
    threat_category = vt_data.get("threat_category", "")
    threat_categories = vt_data.get("threat_categories", [])
    categories = vt_data.get("categories", [])
    reputation = vt_data.get("reputation", 0)

    if malicious > 5:
        risk_level = "🔴 High"
        risk_label = "🔴 **恶意**"
    elif malicious > 0 or suspicious > 3:
        risk_level = "🟡 Medium"
        risk_label = "⚠️ **可疑**"
    else:
        risk_level = "🟢 Low"
        risk_label = "✅ **正常**"

    analysis_time = now_utc8_str()

    r = []
    r.extend(render_header(f"URL 威胁情报分析报告：`{_defang_ioc(url[:60])}...`", risk_level))

    # --- 核心预警摘要 ---
    alert_rows = [
        f"| **VirusTotal** | {'🔴' if malicious > 5 else '🟠' if malicious > 0 else '🟢'} {malicious}/{total} 恶意引擎标记 |"
    ]
    if threat_category:
        alert_rows.append(f"| **威胁分类** | 🔴 {threat_category} |")
    if domain_info and domain_info.get("malicious", 0) > 0:
        alert_rows.append(f"| **关联域名** | ⚠️ 域名 `{_defang_ioc(domain)}` 也被标记恶意 |")
    if domain_samples:
        alert_rows.append(f"| **恶意样本** | 🔴 域名关联 {len(domain_samples)} 个恶意样本 |")
    if direct_ip:
        alert_rows.append(f"| **直连 IP** | ⚠️ `{direct_ip}` |")
    r.extend(render_alert_summary(alert_rows))

    # ==================== 1️⃣ URL 基本信息 ====================
    r.extend(render_section_heading("1️⃣", "URL 基本信息"))
    r.append(f"- **URL**: `{_defang_ioc(url)}`")
    r.append(f"- **关联域名**: `{_defang_ioc(domain)}`")
    if direct_ip:
        r.append(f"- **直连 IP**: `{direct_ip}`")
    r.append(f"- **检出率**: {malicious}/{total} ({_pct(malicious, total)})")
    r.append(f"- **信誉分**: {reputation}")
    if threat_category:
        r.append(f"- **威胁分类**: {threat_category}")
    if categories:
        r.append(f"- **网站分类**: {', '.join(str(c) for c in categories[:5])}")
    r.append("")

    # ==================== 2️⃣ 威胁检测分析 ====================
    r.extend(render_section_heading("2️⃣", "威胁检测分析"))
    r.append(f"- **恶意**: {malicious}/{total} ({_pct(malicious, total)})")
    r.append(f"- **可疑**: {suspicious}")
    r.append(f"- **无害**: {vt_data.get('harmless', 0)}")
    r.append(f"- **未检测**: {vt_data.get('undetected', 0)}")
    if vt_data.get("first_submission_date"):
        r.append(f"- **首次提交**: {_format_timestamp(vt_data['first_submission_date'])}")
    if vt_data.get("last_analysis_date"):
        r.append(f"- **最后分析**: {_format_timestamp(vt_data['last_analysis_date'])}")
    if tags:
        r.append(f"- **标签**: {', '.join(str(t) for t in tags[:8])}")
    if threat_categories:
        r.append(f"- **威胁分类**: {', '.join(str(c) for c in threat_categories[:5])}")
    r.append("")

    # ==================== 3️⃣ 域名关联分析 ====================
    r.extend(render_section_heading("3️⃣", "域名关联分析"))

    if domain_info:
        r.append(f"**域名** `{_defang_ioc(domain)}` 的威胁状态：")
        r.append("")
        r.append(f"- **域名恶意检出**: {domain_info.get('malicious', 0)}")
        r.append(f"- **可疑**: {domain_info.get('suspicious', 0)}")
        r.append(f"- **信誉分**: {domain_info.get('reputation', 0)}")
        if domain_info.get("creation_date"):
            r.append(f"- **注册时间**: {_format_timestamp(domain_info['creation_date'])}")
        if domain_info.get("registrar"):
            r.append(f"- **注册商**: {domain_info['registrar']}")
        if domain_info.get("jarm"):
            r.append(f"- **JARM 指纹**: `{domain_info['jarm']}`")
        r.append("")

    if domain_samples:
        r.extend(render_subsection_heading("🦠", "域名关联恶意样本"))
        r.append("")
        r.append("| SHA256 (前16字符) | 文件类型 | 检出率 |")
        r.append("|-------------------|----------|--------|")
        for s in domain_samples[:5]:
            sha_short = s.get("sha256", "")[:16]
            r.append(f"| `{sha_short}...` | {s.get('type', 'Unknown')} | {s.get('malicious', 0)}/{s.get('total', 0)} |")
        r.append("")

    if not domain_info and not domain_samples:
        r.append("- 未发现域名关联信息")
        r.append("")

    # ==================== 4️⃣ 风险评估 ====================
    risk_rows = []
    if malicious > 5:
        risk_rows.append(f"| **URL 恶意度** | 🔴 极高 | {malicious}/{total} 引擎标记为恶意 |")
    elif malicious > 0:
        risk_rows.append(f"| **URL 恶意度** | 🟠 中高 | {malicious}/{total} 引擎标记为恶意 |")
    else:
        risk_rows.append(f"| **URL 恶意度** | 🟢 低 | 无引擎标记为恶意 |")

    if domain_info and domain_info.get("malicious", 0) > 0:
        risk_rows.append(f"| **域名风险** | 🔴 高 | 关联域名也被标记为恶意 |")
    elif domain_info and domain_info.get("suspicious", 0) > 0:
        risk_rows.append(f"| **域名风险** | 🟠 中高 | 关联域名被标记为可疑 |")
    else:
        risk_rows.append(f"| **域名风险** | 🟢 低 | 关联域名未发现恶意行为 |")

    if domain_samples:
        risk_rows.append(f"| **恶意样本** | 🔴 高 | 域名关联 {len(domain_samples)} 个恶意样本 |")
    else:
        risk_rows.append(f"| **恶意样本** | 🟢 低 | 未发现关联恶意样本 |")

    r.extend(render_risk_table("4", risk_rows))

    # ==================== 🎯 综合研判 ====================
    r.extend(render_judgment_heading())

    if risk_level == "🔴 High":
        r.append(f"该 URL 被判定为**高危恶意**：")
        r.append("")
        idx = 1
        if malicious > 0:
            r.append(f"{idx}. ✅ **多引擎恶意检出**: {malicious}/{total} 个安全引擎标记为恶意")
            idx += 1
        if domain_info and domain_info.get("malicious", 0) > 0:
            r.append(f"{idx}. ✅ **域名本身被标记恶意**: 关联域名 `{_defang_ioc(domain)}` 也被标记为恶意")
            idx += 1
        if threat_category:
            r.append(f"{idx}. ✅ **已知威胁分类**: 归类为 `{threat_category}`")
            idx += 1
        if domain_samples:
            r.append(f"{idx}. ✅ **关联恶意样本**: 域名关联 {len(domain_samples)} 个恶意样本")
            idx += 1
    elif risk_level == "🟡 Medium":
        r.append(f"该 URL 被判定为**可疑**：")
        r.append("")
        if malicious > 0:
            r.append(f"1. ⚠️ **部分引擎检出**: {malicious}/{total} 个引擎标记为恶意")
        if suspicious > 0:
            r.append(f"2. ⚠️ **可疑判定**: {suspicious} 个引擎标记为可疑")
    else:
        r.append(f"该 URL 目前**未发现明显恶意行为**。")
    r.append("")

    # ==================== 📋 处置建议 ====================
    r.extend(render_recommendations_heading())

    if risk_level in ("🔴 High", "🟡 Medium"):
        r.append("#### 立即行动：")
        r.append(f"- ❌ **封禁 URL**: 在防火墙/Web代理中封禁 `{_defang_ioc(url)}`")
        if domain:
            r.append(f"- 🔥 **DNS 层拦截**: 阻止内网解析 `{_defang_ioc(domain)}`")
        if direct_ip:
            r.append(f"- 🔥 **封禁 IP**: 封禁 `{direct_ip}` 的出站连接")
        r.append("- 🔍 排查内网是否有主机访问过该 URL")
        r.append("")
        r.append("#### 深度排查：")
        r.append("- 📝 检查代理/Web过滤日志")
        r.append("- 🧹 如有用户访问过，清理浏览器缓存和下载记录")
        r.append("")
        r.append("#### 威胁狩猎：")
        r.append(f"- 在 SIEM 中添加 URL 和域名为 IOC")
        if domain_samples:
            r.append(f"- 搜索域名关联样本在内网的出现记录")
    else:
        r.append("#### 常规关注：")
        r.append("- 🟢 建议持续关注该 URL 的检出率变化")
        r.append("- 如有疑虑可在沙箱中打开该 URL 进行分析")

    r.append("")

    # ==================== IOC 清单 ====================
    r.extend(render_ioc_intro())

    ioc_rows = [f"| `{_defang_ioc(url[:60])}...` | URL | {risk_level} | 恶意链接 |"]
    if domain:
        ioc_rows.append(f"| `{_defang_ioc(domain)}` | 域名 | 🟡 Medium | URL 关联域名 |")
    if direct_ip:
        ioc_rows.append(f"| `{direct_ip}` | IP | 🟡 Medium | URL 直连 IP |")
    for s in domain_samples[:3]:
        sha_short = s.get("sha256", "")[:16]
        ioc_rows.append(f"| `{sha_short}...` | SHA256 | 🟡 Medium | 域名关联恶意样本 |")
    r.append("| IOC | 类型 | 威胁等级 | 说明 |")
    r.append("|-----|------|----------|------|")
    r.extend(ioc_rows)
    r.append("")
    r.extend(render_footer(analysis_time))

    return "\n".join(r)
