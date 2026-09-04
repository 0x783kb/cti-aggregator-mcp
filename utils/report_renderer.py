"""
报告渲染辅助原语。

三份报告（IP/域名/HASH/URL）共用的渲染片段集中在这里。
设计原则：

- 每个公开函数返回 list[str]，与原 generate_* 函数的拼接结果**逐行等价**。
- 重构后必须用 tests/build_baseline.py 重新生成 fixture 并 diff 验证字节级一致。
- 章节内容逻辑（中间小节）保留在 report_generator.py 的三个 generate_* 函数里，
  不强行统一，因为三份报告的小节顺序、空行模式差异较大，统一反而损失可读性。
"""

from datetime import datetime
from typing import Any, Dict, List


# ============================================================
# 文本原语（已有的小工具函数，集中到这里便于复用）
# ============================================================

def _risk_badge(level: str) -> str:
    """把内部风险等级枚举转成中文徽章。"""
    return {"🔴 High": "🔴 极高风险", "🟡 Medium": "🟡 可疑", "🟢 Low": "🟢 正常"}.get(level, level)


def _defang_ioc(text: str) -> str:
    """对 IOC 进行去毒处理（破坏自动点击）。"""
    if not text:
        return ""
    text = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return text


def _format_timestamp(ts: Any) -> str:
    """Unix 时间戳 → 'YYYY-MM-DD HH:MM:SS'。"""
    if not isinstance(ts, (int, float)):
        return str(ts)
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(ts)


def _coerce_unix_timestamp(value: Any) -> float:
    """把 int/float/数字字符串统一转成 float 时间戳，无法转则返回 0.0。"""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _format_file_size(size: int) -> str:
    """字节数 → 'B' / 'KB' / 'MB'。"""
    if size <= 0:
        return "N/A"
    if size > 1024 * 1024:
        return f"{size / (1024*1024):.1f} MB"
    if size > 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _pct(numerator: int, denominator: int) -> str:
    """整数百分比（向下取整）。"""
    if denominator <= 0:
        return "0%"
    return f"{numerator * 100 // denominator}%"


def now_utc8_str() -> str:
    """当前时间戳的 'YYYY-MM-DD HH:MM (UTC+8)' 字符串（与原 generate_* 函数同源）。"""
    return datetime.now().strftime('%Y-%m-%d %H:%M') + " (UTC+8)"


# ============================================================
# 报告片段原语
# 约定：所有函数返回 list[str]，调用方 extend 到主 r 列表后由 r.join("\n") 拼成报告
# ============================================================

def render_header(title: str, risk_level: str) -> List[str]:
    """报告头部：6 行（标题 + 空 + 风险等级 + 空 + --- + 空）"""
    return [
        f"# 🛡️ {title}",
        "",
        f"### 🚨 风险等级：**{_risk_badge(risk_level)}**",
        "",
        "---",
        "",
    ]


def render_alert_summary(rows: List[str]) -> List[str]:
    """核心预警摘要表（含前后分隔线）。

    rows: 已格式化的表格行（含前导 "| "）。每份报告的占位行由调用方决定，
    本函数不做兜底。
    """
    return [
        "### 核心预警摘要",
        "",
        "| 威胁指标 | 详情 |",
        "|---------|------|",
        *rows,
        "",
        "---",
        "",
    ]


def render_section_heading(emoji: str, title: str) -> List[str]:
    """一级章节标题：`### {emoji} {title}` + 空行。

    对齐 markdown 约定：### 标题后接 1 个空行再接内容。
    """
    return [f"### {emoji} {title}", ""]


def render_subsection_heading(emoji: str, title: str) -> List[str]:
    """二级章节标题：`#### {emoji} {title}`，**不**附加空行。

    原代码中所有 #### 处置建议/小节标题后**直接**接列表项/内容，
    没有 r.append("")。这里保持同样行为以保证字节级一致。
    emoji 为空字符串时不引入多余空格。
    """
    if emoji:
        return [f"#### {emoji} {title}"]
    return [f"#### {title}"]


def render_risk_table(emoji_n: str, rows: List[str]) -> List[str]:
    """风险评估表：### N️⃣ 风险评估 + 表头 + rows + 空行。

    emoji_n 是不带变音符号的数字字符串（"1"/"2"/"3"/"4"/"5"），本函数负责加 ️⃣。
    """
    return [
        f"### {emoji_n}️⃣ 风险评估",
        "",
        "| 风险维度 | 等级 | 说明 |",
        "|---------|------|------|",
        *rows,
        "",
    ]


def render_judgment_heading() -> List[str]:
    """综合研判章节标题：`### 🎯 综合研判` + 空行。"""
    return ["### 🎯 综合研判", ""]


def render_recommendations_heading() -> List[str]:
    """处置建议章节标题：`### 📋 处置建议` + 空行。"""
    return ["### 📋 处置建议", ""]


def render_ioc_intro() -> List[str]:
    """IOC 清单前的章节切换：`---` + 空行 + `### IOC 清单` + 空行。"""
    return ["---", "", "### IOC 清单", ""]


def render_footer(analysis_time: str) -> List[str]:
    """报告尾部（4 行）：来源 + 时间 + 空 + 免责声明。"""
    return [
        f"**报告来源**: cti-aggregator-mcp 威胁情报聚合系统  ",
        f"**分析时间**: {analysis_time}",
        "",
        "*⚠️ 免责声明：本报告基于公开威胁情报数据库和开源信息生成，分析结果反映截至报告生成时间的已知情报状态。*",
    ]
