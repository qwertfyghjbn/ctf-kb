"""本地检索。分阶段：精确 CVE → CWE → 产品/版本 → FTS5。

不把版本子串当成受影响证据；无可靠候选时允许空结果。
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from ctf_kb import config
from ctf_kb.extract import extract_preconditions, extract_version_hints
from ctf_kb.quality import KIND_LABELS, STATUS_LABELS, UNCERTAINTY_BASE
from ctf_kb.versioning import (
    VersionRange,
    evaluate_version,
    load_range_file,
    parse_affected_text,
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)
# 允许 1.0.1f / 8.5p1；禁止把 2.4.5 当成 2.4.50 的前缀
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,4}(?:[A-Za-z]+\d*)?\b")
_FTS_RESERVED = {"AND", "OR", "NOT", "NEAR"}

_RANGES_BY_CVE: dict[str, list[VersionRange]] | None = None
_ALL_RANGES: list[VersionRange] | None = None


def connect(db_path=None) -> sqlite3.Connection:
    from ctf_kb.ingest import connect as _connect

    return _connect(db_path)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _quote_fts_token(tok: str) -> str:
    return '"' + tok.replace('"', '""') + '"'


def _fts_query(text: str) -> str:
    """把用户输入转成安全的 FTS5 MATCH 表达式。

    每个 token 都加双引号，避免 '.' '-' '/' 被当成列过滤器或语法。
    失败时返回空串，由调用方决定是否报错。
    """
    text = (text or "").strip()
    if not text:
        return ""
    cleaned: list[str] = []
    for raw in re.split(r"\s+", text):
        raw = raw.replace('"', "").strip()
        if not raw or raw.upper() in _FTS_RESERVED:
            continue
        # nginx/1.18.0 → nginx + 1.18.0
        if "/" in raw:
            for part in raw.split("/"):
                part = part.strip()
                if not part or part.upper() in _FTS_RESERVED:
                    continue
                cleaned.append(_quote_fts_token(part))
            continue
        # foo-bar 整词丢弃，避免拆成 foo AND bar 误命中
        if "-" in raw and not re.match(r"^\d", raw):
            continue
        cleaned.append(_quote_fts_token(raw))
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    return " AND ".join(cleaned)


def _limit(n: int | None) -> int:
    if n is None:
        return config.DEFAULT_LIMIT
    return max(1, min(int(n), config.MAX_LIMIT))


def _cached_ranges() -> tuple[dict[str, list[VersionRange]], list[VersionRange]]:
    global _RANGES_BY_CVE, _ALL_RANGES
    if _ALL_RANGES is None:
        rows = load_range_file()
        by: dict[str, list[VersionRange]] = {}
        for rng in rows:
            by.setdefault(rng.cve_id, []).append(rng)
        _ALL_RANGES = rows
        _RANGES_BY_CVE = by
    return _RANGES_BY_CVE or {}, _ALL_RANGES or []


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


_VENDOR_TOKENS = {
    "apache",
    "gnu",
    "software",
    "foundation",
    "project",
    "inc",
    "the",
    "open",
    "source",
}


def reset_range_cache() -> None:
    """测试或更换 LOCAL_DIR 后清空范围缓存。"""
    global _RANGES_BY_CVE, _ALL_RANGES
    _RANGES_BY_CVE = None
    _ALL_RANGES = None


def _specific_product_tokens(name: str | None) -> set[str]:
    toks = re.findall(r"[a-z0-9]+", (name or "").lower())
    out: set[str] = set()
    for t in toks:
        if t in _VENDOR_TOKENS or len(t) <= 1:
            continue
        out.add(t)
        # log4j2 / struts2 与 log4j / struts 视为同一产品族
        stemmed = t.rstrip("0123456789")
        if stemmed and stemmed != t and len(stemmed) >= 4:
            out.add(stemmed)
    return out


def _ranges_for_record(rec: dict[str, Any]) -> list[VersionRange]:
    by_cve, _ = _cached_ranges()
    ranges = list(by_cve.get(rec["cve_id"], []))
    note = (rec.get("local") or {}).get("note") or {}
    av = note.get("affected_versions")
    if av:
        parsed = parse_affected_text(rec["cve_id"], av, "local_notes.affected_versions")
        if parsed:
            ranges.append(parsed)
    return ranges


def _version_belongs_to_query_product(
    product_q: str | None, rec: dict[str, Any], ranges: list[VersionRange]
) -> bool:
    """查询带具体产品名时，只对该产品相关的 CVE 使用版本范围。"""
    if not product_q:
        return True
    q_toks = _specific_product_tokens(product_q)
    if not q_toks:
        # 仅厂商名（如 Apache）不能套用 Log4j/Struts 等具体产品的版本范围
        return False
    p_toks = _specific_product_tokens(rec.get("products"))
    for rng in ranges:
        p_toks |= _specific_product_tokens(rng.product)
    if not p_toks:
        return True
    return bool(q_toks & p_toks)


def _apply_version(
    rec: dict[str, Any], version_q: str | None, product_q: str | None = None
) -> str:
    if not version_q:
        rec["version_status"] = "unknown"
        rec["version_evidence"] = None
        return "unknown"
    ranges = _ranges_for_record(rec)
    if not _version_belongs_to_query_product(product_q, rec, ranges):
        rec["version_status"] = "unknown"
        rec["version_evidence"] = None
        return "unknown"
    status, evidence = evaluate_version(version_q, ranges)
    rec["version_status"] = status
    rec["version_evidence"] = evidence
    return status


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
        "version_status": rec.get("version_status") or "unknown",
        "version_evidence": rec.get("version_evidence"),
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
    skipped_not_affected: list[str] = []
    fts_error: str | None = None

    cve_ids = [m.upper() for m in CVE_RE.findall(query)]
    product_q = product
    if not product_q and not cve_ids:
        product_q = _guess_product_query(query)
    version_q = version or (_guess_version(query) if not cve_ids else None)

    def add(cve_id: str, reason: str, rank: float) -> None:
        if cve_id in seen:
            return
        rec = lookup_cve(conn, cve_id)
        if not rec:
            return
        st = _apply_version(rec, version_q, product_q)
        seen.add(cve_id)
        if version_q and st == "not_affected":
            skipped_not_affected.append(cve_id)
            return
        rec["match_reason"] = reason
        if version_q:
            rec["match_reason"] = f"{reason}；版本适用性={st}"
        rec["rank"] = rank
        if st == "affected":
            rec["rank"] = rank + 12.0
        hits.append(rec)

    # 1) 精确 CVE：不再走全文 / 产品 / LIKE
    if cve_ids:
        for cid in cve_ids:
            add(cid, f"查询包含 CVE ID {cid}", 100)
        hits.sort(key=lambda r: r.get("rank", 0), reverse=True)
        hits = hits[:limit_n]
        return _pack(
            query, product_q, cwe, version_q, hits, skipped_not_affected, fts_error
        )

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
        if CWE_RE.fullmatch(query.strip()):
            hits.sort(key=lambda r: r.get("rank", 0), reverse=True)
            hits = hits[:limit_n]
            return _pack(
                query, product_q, cwe_q, version_q, hits, skipped_not_affected, fts_error
            )

    # 3) 产品名 + 结构化版本（unknown 保留，not_affected 过滤）
    # 仅厂商名（如单独的 Apache）走 FTS，避免 Log4j/Struts 抢位
    product_specific = bool(product_q and _specific_product_tokens(product_q))
    if product_q and product_specific:
        like = f"%{product_q}%"
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
        q = product_q.lower()
        for row in rows:
            prod = (row["product"] or "").lower()
            vend = (row["vendor"] or "").lower()
            rank = 55.0
            reason = f"产品字段匹配 {row['product']}"
            if q in prod:
                rank = 82.0
            elif q in vend:
                rank = 62.0
            else:
                continue
            if row["kev"]:
                rank += 1.5
            rank += min(float(row["epss"] or 0), 1.0)
            scored.append((rank, row["cve_id"], reason))
        scored.sort(key=lambda x: x[0], reverse=True)
        for rank, cve_id, reason in scored[: limit_n * 4]:
            add(cve_id, reason, rank)

        # 精选范围里的产品名，补 products 表缺失的条目（如部分 OpenSSL/Bash）
        _, all_ranges = _cached_ranges()
        for rng in all_ranges:
            if not rng.product:
                continue
            if q in rng.product.lower() or rng.product.lower() in q:
                add(
                    rng.cve_id,
                    f"精选版本范围匹配产品 {rng.product}",
                    80.0,
                )

    # 4) FTS：仅在精确通道不够时；语法错误不得伪装成 0 命中。
    # 已经按产品+版本查过且无候选时，不再全文凑 Top-k。
    pure_cwe = bool(cwe_q and CWE_RE.fullmatch(query.strip()))
    skip_fts = bool(product_specific and version_q and not hits)
    if query and not pure_cwe and not skip_fts and len(hits) < limit_n:
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
            except sqlite3.OperationalError as exc:
                fts_error = str(exc)
                rows = []
            for i, row in enumerate(rows):
                add(
                    row["cve_id"],
                    f"全文检索匹配 {query!r}",
                    50 - float(row["score"] or 0) - i * 0.01,
                )

    # 不再做 LIKE 回退：无可靠候选就空结果，避免凑 Top-k
    hits.sort(key=lambda r: r.get("rank", 0), reverse=True)
    hits = hits[:limit_n]
    return _pack(
        query, product_q, cwe_q, version_q, hits, skipped_not_affected, fts_error
    )


def _pack(
    query: str,
    product_q: str | None,
    cwe_q: str | None,
    version_q: str | None,
    hits: list[dict[str, Any]],
    skipped_not_affected: list[str],
    fts_error: str | None,
) -> dict[str, Any]:
    status = "ok"
    error = None
    if fts_error:
        status = "fts_error"
        error = fts_error
    elif not hits:
        status = "empty"
    return {
        "query": query,
        "product": product_q,
        "cwe": cwe_q,
        "version": version_q,
        "count": len(hits),
        "results": [_summary(h) for h in hits],
        "skipped_not_affected": skipped_not_affected[:20],
        "status": status,
        "error": error,
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
        "affected_versions": ((rec.get("local") or {}).get("note") or {}).get(
            "affected_versions"
        ),
        "preconditions": rec["precondition_hints"],
        "version_hints_from_description": rec["version_hints"],
        "exploitability": rec["exploitability"],
        "artifacts": {k: arts.get(k) or [] for k in KIND_LABELS},
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
    stripped = VERSION_RE.sub(" ", query)
    stripped = CWE_RE.sub(" ", stripped)
    stripped = CVE_RE.sub(" ", stripped)
    stripped = re.sub(r"[/]+", " ", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    if not stripped:
        return None
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
    if len(stripped) < 3:
        return None
    return stripped


def _guess_version(query: str) -> str | None:
    m = VERSION_RE.search(query)
    return m.group(0) if m else None
