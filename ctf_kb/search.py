"""本地检索。优先精确匹配，其次产品/CWE，再次 FTS5 关键词。"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from ctf_kb import config
from ctf_kb.extract import extract_preconditions, extract_version_hints
from ctf_kb.quality import KIND_LABELS, STATUS_LABELS, UNCERTAINTY_BASE

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,4}\b")


def connect(db_path=None) -> sqlite3.Connection:
    from ctf_kb.ingest import connect as _connect

    return _connect(db_path)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _fts_query(text: str) -> str:
    """把用户输入转成相对安全的 FTS5 MATCH 表达式。"""
    text = text.strip()
    if not text:
        return ""
    # 已是 CVE / CWE 时交给精确通道
    tokens = re.findall(r"[A-Za-z0-9_./+-]+", text)
    cleaned: list[str] = []
    for tok in tokens:
        tok = tok.replace('"', "")
        if not tok or tok in {"AND", "OR", "NOT", "NEAR"}:
            continue
        if any(ch in tok for ch in "*\"^"):
            continue
        cleaned.append(tok)
    if not cleaned:
        return ""
    # 短语优先：多词用 AND，保留原始短语
    if len(cleaned) == 1:
        return cleaned[0]
    quoted = " ".join(cleaned)
    and_expr = " AND ".join(cleaned)
    return f'("{quoted}") OR ({and_expr})'


def _limit(n: int | None) -> int:
    if n is None:
        return config.DEFAULT_LIMIT
    return max(1, min(int(n), config.MAX_LIMIT))


def lookup_cve(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    cve_id = cve_id.upper().strip()
    row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
    if not row:
        return None
    rec = _row_to_dict(row)
    rec["artifacts"] = _artifacts(conn, cve_id)
    rec["local"] = _local(conn, cve_id)
    rec["match_reason"] = f"精确匹配 {cve_id}"
    rec["uncertainty"] = _uncertainty(rec)
    rec["precondition_hints"] = _precondition_bundle(rec)
    rec["version_hints"] = extract_version_hints(
        " ".join(x for x in [rec.get("title"), rec.get("description")] if x)
    )
    rec["verification"] = _verification_view(rec)
    rec["exploitability"] = _exploitability(rec)
    return rec


def _artifacts(conn: sqlite3.Connection, cve_id: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {k: [] for k in KIND_LABELS}
    rows = conn.execute(
        """
        SELECT kind, url, title, extra, source, trusted
        FROM artifacts
        WHERE cve_id = ?
        ORDER BY trusted DESC, kind, id
        """,
        (cve_id,),
    ).fetchall()
    caps = {
        "poc": config.MAX_POC_LINKS,
        "nuclei": config.MAX_OTHER_LINKS,
        "msf": config.MAX_OTHER_LINKS,
        "edb": config.MAX_OTHER_LINKS,
        "vulhub": config.MAX_OTHER_LINKS,
        "collection": config.MAX_OTHER_LINKS,
        "advisory": config.MAX_OTHER_LINKS,
    }
    totals: dict[str, int] = {}
    for row in rows:
        kind = row["kind"]
        totals[kind] = totals.get(kind, 0) + 1
        bucket = grouped.setdefault(kind, [])
        if len(bucket) >= caps.get(kind, config.MAX_OTHER_LINKS):
            continue
        extra = None
        if row["extra"]:
            try:
                extra = json.loads(row["extra"])
            except json.JSONDecodeError:
                extra = {"raw": row["extra"]}
        bucket.append(
            {
                "url": row["url"],
                "title": row["title"],
                "source": row["source"],
                "trusted": bool(row["trusted"]),
                "kind_label": KIND_LABELS.get(kind, kind),
                "extra": extra,
            }
        )
    grouped["_totals"] = totals
    grouped["_truncated"] = {
        k: max(0, totals.get(k, 0) - len(grouped.get(k) or []))
        for k in KIND_LABELS
        if totals.get(k, 0) > len(grouped.get(k) or [])
    }
    return grouped


def _local(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any]:
    note = conn.execute("SELECT * FROM local_notes WHERE cve_id = ?", (cve_id,)).fetchone()
    ver = conn.execute(
        "SELECT * FROM local_verifications WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    return {
        "note": _row_to_dict(note) if note else None,
        "verification": _row_to_dict(ver) if ver else None,
    }


def _verification_view(rec: dict[str, Any]) -> dict[str, Any]:
    ver = (rec.get("local") or {}).get("verification")
    if ver:
        status = ver.get("status") or "unverified"
        return {
            "status": status,
            "label": STATUS_LABELS.get(status, status),
            "evidence": ver.get("evidence"),
            "lab": ver.get("lab"),
            "verified_at": ver.get("verified_at"),
            "reviewer": ver.get("reviewer"),
            "source": "local",
        }
    return {
        "status": "unverified",
        "label": STATUS_LABELS["unverified"],
        "evidence": None,
        "lab": None,
        "verified_at": None,
        "reviewer": None,
        "source": "default",
    }


def _precondition_bundle(rec: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    note = (rec.get("local") or {}).get("note") or {}
    if note.get("preconditions"):
        hints.append(note["preconditions"])
    if note.get("affected_versions"):
        hints.append(f"本地记录受影响版本：{note['affected_versions']}")
    auto = extract_preconditions(
        " ".join(x for x in [rec.get("title"), rec.get("description")] if x)
    )
    for h in auto:
        if h not in hints:
            hints.append(h)
    if rec.get("products"):
        hints.append(f"上游标记产品：{rec['products']}（不是精确 CPE 匹配）")
    return hints


def _exploitability(rec: dict[str, Any]) -> dict[str, Any]:
    arts = rec.get("artifacts") or {}
    totals = arts.get("_totals") or {}
    return {
        "has_poc_link": bool(totals.get("poc")),
        "has_nuclei": bool(totals.get("nuclei")),
        "has_msf": bool(totals.get("msf")),
        "has_edb": bool(totals.get("edb")),
        "has_vulhub": bool(totals.get("vulhub")),
        "kev": bool(rec.get("kev")),
        "verified": _verification_view(rec)["status"] == "verified_ok",
        "note": "链接存在 ≠ 可利用；验证状态见 verification.status",
    }


def _uncertainty(rec: dict[str, Any]) -> list[str]:
    items = list(UNCERTAINTY_BASE)
    ver = _verification_view(rec)
    if ver["status"] == "unverified":
        items.append("该条尚未本地验证。")
    elif ver["status"] == "verified_fail":
        items.append("本地验证失败，公开 PoC 可能已失效或环境不匹配。")
    elif ver["status"] == "static_review":
        items.append("仅完成静态审核，未在隔离环境实际复现。")
    if not rec.get("products"):
        items.append("缺少结构化产品字段，产品匹配依赖描述文本。")
    return items


def _summary(rec: dict[str, Any], match_reason: str | None = None) -> dict[str, Any]:
    arts = rec.get("artifacts") or {}
    totals = arts.get("_totals") or {}
    return {
        "cve_id": rec["cve_id"],
        "title": rec.get("title"),
        "description": (rec.get("description") or "")[:400],
        "vendor": rec.get("vendor"),
        "products": rec.get("products"),
        "cwe": rec.get("cwe"),
        "cvss_score": rec.get("cvss_score"),
        "cvss_severity": rec.get("cvss_severity"),
        "published": rec.get("published"),
        "kev": bool(rec.get("kev")),
        "epss": rec.get("epss"),
        "poc_count": rec.get("poc_count") or totals.get("poc") or 0,
        "nuclei_count": rec.get("nuclei_count") or totals.get("nuclei") or 0,
        "msf_count": rec.get("msf_count") or 0,
        "edb_count": rec.get("edb_count") or 0,
        "vulhub_count": rec.get("vulhub_count") or 0,
        "verification": _verification_view(rec),
        "match_reason": match_reason or rec.get("match_reason"),
        "precondition_hints": rec.get("precondition_hints")
        or extract_preconditions(
            " ".join(x for x in [rec.get("title"), rec.get("description")] if x)
        ),
        "version_hints": rec.get("version_hints")
        or extract_version_hints(
            " ".join(x for x in [rec.get("title"), rec.get("description")] if x)
        ),
        "artifact_preview": {
            k: [a["url"] for a in (arts.get(k) or [])[:3]]
            for k in ("poc", "nuclei", "msf", "edb", "vulhub")
            if arts.get(k)
        },
        "sources": rec.get("sources"),
    }


def search(
    conn: sqlite3.Connection,
    query: str,
    limit: int | None = None,
    product: str | None = None,
    cwe: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    limit_n = _limit(limit)
    query = (query or "").strip()
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(cve_id: str, reason: str, rank: float) -> None:
        if cve_id in seen:
            return
        rec = lookup_cve(conn, cve_id)
        if not rec:
            return
        seen.add(cve_id)
        rec["match_reason"] = reason
        rec["rank"] = rank
        hits.append(rec)

    # 1) 精确 CVE
    for m in CVE_RE.findall(query):
        add(m.upper(), f"查询包含 CVE ID {m.upper()}", 100)

    # 2) 显式 CWE
    cwe_q = cwe or None
    if not cwe_q:
        m = CWE_RE.search(query)
        if m:
            cwe_q = m.group(0).upper()
    if cwe_q:
        rows = conn.execute(
            """
            SELECT cve_id FROM cves
            WHERE cwe = ?
            ORDER BY kev DESC, epss DESC, poc_count DESC
            LIMIT ?
            """,
            (cwe_q.upper(), limit_n),
        ).fetchall()
        for i, row in enumerate(rows):
            add(row["cve_id"], f"CWE 精确匹配 {cwe_q.upper()}", 90 - i * 0.1)

    # 3) 产品名
    product_q = product
    if not product_q:
        # 用户可能输入 "Apache 2.4.50" / "PHP deserialization"
        product_q = _guess_product_query(query)
    version_q = version or _guess_version(query)

    if product_q:
        like = f"%{product_q}%"
        # 宽召回后再按“产品名贴合度 + 版本提示”重排，避免 vendor=Apache 把 Log4j 排到 httpd 前面
        rows = conn.execute(
            """
            SELECT p.cve_id, p.product, p.vendor, p.version_hint,
                   c.kev, c.epss, c.poc_count, c.title, c.description
            FROM products p
            JOIN cves c ON c.cve_id = p.cve_id
            WHERE p.product LIKE ? OR p.vendor LIKE ?
            """,
            (like, like),
        ).fetchall()
        scored: list[tuple[float, str, str]] = []
        for row in rows:
            prod = (row["product"] or "").lower()
            vend = (row["vendor"] or "").lower()
            hint = row["version_hint"] or ""
            blob = " ".join(
                x or "" for x in (row["title"], row["description"], hint, row["product"])
            )
            q = product_q.lower()
            rank = 55.0
            reason = f"产品字段匹配 {row['product']}"
            if q in prod:
                rank = 82.0
            elif q in vend:
                rank = 62.0
            if version_q and version_q in hint:
                rank += 18.0
                reason += f"；描述中出现版本提示 {version_q}（非精确判定）"
            elif version_q and version_q in blob:
                rank += 10.0
                reason += f"；文本中出现 {version_q}，需人工核对是否落在受影响范围"
            elif version_q:
                # 查询带版本但该 CVE 文本完全未提及，不当作产品命中
                # （仍可能被 FTS 捞到，避免 Apache 厂商下的 Log4j/Struts 挤掉 httpd）
                continue
            if row["kev"]:
                rank += 1.5
            rank += min(float(row["epss"] or 0), 1.0)
            scored.append((rank, row["cve_id"], reason))
        scored.sort(key=lambda x: x[0], reverse=True)
        for rank, cve_id, reason in scored[: limit_n * 3]:
            add(cve_id, reason, rank)

    # 4) FTS 关键词
    if query and not CVE_RE.fullmatch(query.strip()):
        fts = _fts_query(query)
        if fts:
            try:
                rows = conn.execute(
                    """
                    SELECT cves_fts.cve_id AS cve_id,
                           bm25(cves_fts) AS score
                    FROM cves_fts
                    WHERE cves_fts MATCH ?
                    ORDER BY score
                    LIMIT ?
                    """,
                    (fts, limit_n * 2),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
            for i, row in enumerate(rows):
                add(row["cve_id"], f"全文检索匹配 {query!r}", 50 - float(row["score"] or 0) - i * 0.01)

    # 若仍为空，退回 LIKE
    if not hits and query:
        like = f"%{query}%"
        rows = conn.execute(
            """
            SELECT cve_id FROM cves
            WHERE cve_id LIKE ? OR IFNULL(title,'') LIKE ?
               OR IFNULL(description,'') LIKE ? OR IFNULL(products,'') LIKE ?
            ORDER BY kev DESC, epss DESC, poc_count DESC
            LIMIT ?
            """,
            (like, like, like, like, limit_n),
        ).fetchall()
        for row in rows:
            add(row["cve_id"], f"LIKE 回退匹配 {query!r}", 10)

    hits.sort(key=lambda r: r.get("rank", 0), reverse=True)
    hits = hits[:limit_n]
    return {
        "query": query,
        "product": product_q,
        "cwe": cwe_q,
        "version": version_q,
        "count": len(hits),
        "results": [_summary(h) for h in hits],
        "disclaimer": UNCERTAINTY_BASE,
    }


def show(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any]:
    rec = lookup_cve(conn, cve_id)
    if not rec:
        return {"error": f"未找到 {cve_id}", "cve_id": cve_id.upper()}
    arts = rec["artifacts"]
    return {
        "cve_id": rec["cve_id"],
        "title": rec.get("title"),
        "description": rec.get("description"),
        "vendor": rec.get("vendor"),
        "products": rec.get("products"),
        "cwe": rec.get("cwe"),
        "cvss": {
            "score": rec.get("cvss_score"),
            "severity": rec.get("cvss_severity"),
            "vector": rec.get("cvss_vector"),
        },
        "published": rec.get("published"),
        "modified": rec.get("modified"),
        "kev": bool(rec.get("kev")),
        "kev_date": rec.get("kev_date"),
        "epss": rec.get("epss"),
        "epss_percentile": rec.get("epss_percentile"),
        "sources": rec.get("sources"),
        "updated_at": rec.get("updated_at"),
        "verification": rec["verification"],
        "local_note": (rec.get("local") or {}).get("note"),
        "affected_versions": ((rec.get("local") or {}).get("note") or {}).get("affected_versions"),
        "preconditions": rec["precondition_hints"],
        "version_hints_from_description": rec["version_hints"],
        "exploitability": rec["exploitability"],
        "artifacts": {
            k: arts.get(k) or []
            for k in KIND_LABELS
        },
        "artifact_totals": arts.get("_totals") or {},
        "artifact_truncated": arts.get("_truncated") or {},
        "uncertainty": rec["uncertainty"],
        "match_reason": rec.get("match_reason"),
    }


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    def one(sql: str) -> int:
        return int(conn.execute(sql).fetchone()[0])

    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    kind_counts = {
        r["kind"]: r["n"]
        for r in conn.execute("SELECT kind, COUNT(*) AS n FROM artifacts GROUP BY kind")
    }
    ver_counts = {
        r["status"]: r["n"]
        for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM local_verifications GROUP BY status"
        )
    }
    return {
        "db": str(config.DB_PATH),
        "cves": one("SELECT COUNT(*) FROM cves"),
        "products": one("SELECT COUNT(*) FROM products"),
        "artifacts": kind_counts,
        "artifact_total": one("SELECT COUNT(*) FROM artifacts"),
        "local_notes": one("SELECT COUNT(*) FROM local_notes"),
        "local_verifications": ver_counts,
        "kev": one("SELECT COUNT(*) FROM cves WHERE kev=1"),
        "with_poc": one("SELECT COUNT(*) FROM cves WHERE poc_count>0"),
        "with_nuclei": one("SELECT COUNT(*) FROM cves WHERE nuclei_count>0"),
        "with_vulhub": one("SELECT COUNT(*) FROM cves WHERE vulhub_count>0"),
        "meta": meta,
    }


def _guess_product_query(query: str) -> str | None:
    # 去掉版本号后再看是否像产品名
    stripped = VERSION_RE.sub(" ", query)
    stripped = CWE_RE.sub(" ", stripped)
    stripped = CVE_RE.sub(" ", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    if not stripped:
        return None
    # 太像漏洞类型描述则不当产品
    type_words = (
        "deserialization",
        "injection",
        "traversal",
        "overflow",
        "xss",
        "ssrf",
        "rce",
        "lfi",
        "sqli",
        "unserialize",
    )
    low = stripped.lower()
    if any(w in low for w in type_words) and len(stripped.split()) <= 4:
        return None
    # 单字母无意义
    if len(stripped) < 3:
        return None
    return stripped


def _guess_version(query: str) -> str | None:
    m = VERSION_RE.search(query)
    return m.group(0) if m else None
