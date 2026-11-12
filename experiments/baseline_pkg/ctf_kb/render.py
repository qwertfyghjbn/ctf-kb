"""人类可读输出。JSON 由 CLI 直接 dumps。"""

from __future__ import annotations

from typing import Any

from ctf_kb.quality import KIND_LABELS, STATUS_LABELS


def _line(key: str, value: Any) -> str:
    if value is None or value == "" or value == [] or value == {}:
        return f"{key}: -"
    return f"{key}: {value}"


def render_search(payload: dict[str, Any]) -> str:
    lines = [
        f"查询: {payload.get('query')}",
        f"产品过滤: {payload.get('product') or '-'}",
        f"CWE: {payload.get('cwe') or '-'}",
        f"版本提示: {payload.get('version') or '-'}",
        f"命中: {payload.get('count')}",
        "",
    ]
    for i, rec in enumerate(payload.get("results") or [], 1):
        ver = rec.get("verification") or {}
        lines.append(f"[{i}] {rec.get('cve_id')}  {rec.get('title') or ''}".rstrip())
        lines.append(
            "    "
            + " | ".join(
                [
                    f"CWE={rec.get('cwe') or '-'}",
                    f"CVSS={rec.get('cvss_score') or '-'}/{rec.get('cvss_severity') or '-'}",
                    f"产品={rec.get('products') or '-'}",
                    f"KEV={'yes' if rec.get('kev') else 'no'}",
                    f"验证={ver.get('label') or STATUS_LABELS.get(ver.get('status') or 'unverified')}",
                ]
            )
        )
        lines.append(f"    匹配依据: {rec.get('match_reason')}")
        if rec.get("precondition_hints"):
            lines.append("    利用前提: " + "；".join(rec["precondition_hints"][:4]))
        if rec.get("version_hints"):
            lines.append("    描述中的版本提示: " + ", ".join(rec["version_hints"][:6]))
        prev = rec.get("artifact_preview") or {}
        for kind in ("vulhub", "nuclei", "msf", "edb", "poc"):
            urls = prev.get(kind) or []
            if urls:
                lines.append(f"    {KIND_LABELS.get(kind, kind)}: {urls[0]}")
        desc = rec.get("description") or ""
        if desc:
            lines.append("    描述: " + desc.replace("\n", " ")[:220])
        lines.append("")
    lines.append("注意:")
    for d in payload.get("disclaimer") or []:
        lines.append(f"  - {d}")
    return "\n".join(lines)


def render_show(payload: dict[str, Any]) -> str:
    if payload.get("error"):
        return payload["error"]
    cvss = payload.get("cvss") or {}
    ver = payload.get("verification") or {}
    lines = [
        f"{payload.get('cve_id')}  {payload.get('title') or ''}".rstrip(),
        _line("描述", payload.get("description")),
        _line("厂商", payload.get("vendor")),
        _line("产品", payload.get("products")),
        _line("CWE", payload.get("cwe")),
        f"CVSS: {cvss.get('score')} {cvss.get('severity')} {cvss.get('vector')}",
        _line("发布/修改", f"{payload.get('published')} / {payload.get('modified')}"),
        f"KEV: {'yes' if payload.get('kev') else 'no'} ({payload.get('kev_date') or '-'})",
        f"EPSS: {payload.get('epss')} (p={payload.get('epss_percentile')})",
        f"验证状态: {ver.get('label')} [{ver.get('status')}]",
        _line("验证证据", ver.get("evidence")),
        _line("验证环境", ver.get("lab")),
        "",
        "利用前提 / 配置:",
    ]
    for h in payload.get("preconditions") or ["-"]:
        lines.append(f"  - {h}")
    if payload.get("version_hints_from_description"):
        lines.append(
            "描述中的版本提示（非精确 CPE）: "
            + ", ".join(payload["version_hints_from_description"])
        )
    local = payload.get("local_note") or {}
    if local:
        lines.append("")
        lines.append("本地精选:")
        for k in ("aliases", "affected_versions", "preconditions", "exploit_notes", "tags"):
            if local.get(k):
                lines.append(f"  {k}: {local[k]}")
    lines.append("")
    lines.append("资料位置:")
    totals = payload.get("artifact_totals") or {}
    truncated = payload.get("artifact_truncated") or {}
    arts = payload.get("artifacts") or {}
    for kind, label in KIND_LABELS.items():
        items = arts.get(kind) or []
        extra = truncated.get(kind) or 0
        head = f"  [{label}] 共 {totals.get(kind, 0)} 条"
        if extra:
            head += f"（仅展示 {len(items)}，省略 {extra}）"
        lines.append(head)
        for it in items:
            trust = "trusted" if it.get("trusted") else "untrusted"
            lines.append(f"    - ({trust}) {it.get('url')}")
    lines.append("")
    lines.append("不确定性:")
    for u in payload.get("uncertainty") or []:
        lines.append(f"  - {u}")
    return "\n".join(lines)


def render_stats(payload: dict[str, Any]) -> str:
    lines = [
        f"数据库: {payload.get('db')}",
        f"CVE 条数: {payload.get('cves')}",
        f"产品关联: {payload.get('products')}",
        f"产物总数: {payload.get('artifact_total')}",
        f"  明细: {payload.get('artifacts')}",
        f"含 PoC 链接的 CVE: {payload.get('with_poc')}",
        f"含 Nuclei 模板的 CVE: {payload.get('with_nuclei')}",
        f"含 Vulhub 环境的 CVE: {payload.get('with_vulhub')}",
        f"KEV: {payload.get('kev')}",
        f"本地精选: {payload.get('local_notes')}",
        f"本地验证: {payload.get('local_verifications')}",
        f"元信息: {payload.get('meta')}",
    ]
    return "\n".join(lines)
