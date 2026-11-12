"""从开源索引导入 SQLite。

上游数据整体替换 cves / artifacts / products / FTS。
local_notes 与 local_verifications 保留。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

from ctf_kb import config
from ctf_kb.extract import extract_preconditions, extract_version_hints, guess_cwe_from_text
from ctf_kb.quality import github_repo_key, is_trusted_url, prefer_official_nuclei
from ctf_kb.schema import init_db


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dirs() -> None:
    config.RAW_DIR.mkdir(parents=True, exist_ok=True)
    config.LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def download(url: str, dest: Path, timeout: int = 180) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = Request(url, headers={"User-Agent": config.USER_AGENT})
    with urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)


def fetch_raw(force: bool = False) -> dict[str, str]:
    """下载上游 JSON。已存在且非 force 时复用本地文件。"""
    ensure_dirs()
    status: dict[str, str] = {}
    for key, filename in config.RAW_FILES.items():
        dest = config.RAW_DIR / filename
        url = config.SOURCES[key]
        if dest.exists() and not force:
            status[key] = f"cached {dest} ({dest.stat().st_size} bytes)"
            continue
        try:
            download(url, dest)
            status[key] = f"downloaded {dest} ({dest.stat().st_size} bytes)"
        except (URLError, TimeoutError, OSError) as exc:
            if dest.exists():
                status[key] = f"failed ({exc}); using cached {dest}"
            else:
                status[key] = f"missing: {exc}"
    return status


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _as_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x]
    return [str(value)]


def _pick_cvss(meta_row: dict[str, Any] | None) -> tuple[float | None, str | None, str | None]:
    if not meta_row:
        return None, None, None
    rows = meta_row.get("cvss") or []
    preferred = None
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) < 4:
            continue
        version, score, severity, vector = row[0], row[1], row[2], row[3]
        source = row[4] if len(row) > 4 else ""
        kind = row[5] if len(row) > 5 else ""
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            continue
        item = (str(version), score_f, str(severity) if severity else None, str(vector) if vector else None)
        if preferred is None:
            preferred = item
        # 优先 NVD 的 3.x Primary
        if str(version).startswith("3") and "nvd" in str(source).lower() and str(kind).lower() == "primary":
            return item[1], item[2], item[3]
        if str(version).startswith("3") and preferred[0].startswith("2"):
            preferred = item
    if preferred is None:
        return None, None, None
    return preferred[1], preferred[2], preferred[3]


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _replace_upstream_tables(conn: sqlite3.Connection) -> None:
    # 不用 executescript：它会先 COMMIT，破坏外层事务。
    conn.execute("DELETE FROM artifacts")
    conn.execute("DELETE FROM products")
    conn.execute("DELETE FROM cves")


def ingest(conn: sqlite3.Connection, raw_dir: Path | None = None) -> dict[str, Any]:
    raw_dir = raw_dir or config.RAW_DIR
    cve_list = load_json(raw_dir / config.RAW_FILES["pocindex_cve_list"]) or []
    metadata = load_json(raw_dir / config.RAW_FILES["pocindex_metadata"]) or {}
    epss = load_json(raw_dir / config.RAW_FILES["pocindex_epss"]) or {}
    nuclei_meta = load_json(raw_dir / config.RAW_FILES["pocindex_nuclei"]) or {}
    kev = load_json(raw_dir / config.RAW_FILES["pocindex_kev"]) or {}
    repo_meta = load_json(raw_dir / config.RAW_FILES["pocindex_repo_meta"]) or {}
    cisa = load_json(raw_dir / config.RAW_FILES["cisa_kev"]) or {}
    nuclei_rows = load_ndjson(raw_dir / config.RAW_FILES["nuclei_cves"])

    cisa_set: set[str] = set()
    if isinstance(cisa, dict):
        for item in cisa.get("vulnerabilities") or []:
            cid = (item or {}).get("cveID")
            if cid:
                cisa_set.add(cid.upper())

    nuclei_by_cve: dict[str, dict[str, Any]] = {}
    for row in nuclei_rows:
        cid = (row.get("ID") or "").upper()
        if cid:
            nuclei_by_cve[cid] = row

    if not isinstance(cve_list, list) or not cve_list:
        return {
            "cves": 0,
            "artifacts": 0,
            "products": 0,
            "curated": 0,
            "skipped": "empty or missing CVE_list, database unchanged",
            "ingested_at": utc_now(),
        }

    now = utc_now()
    artifact_rows: list[tuple] = []
    product_rows: list[tuple] = []
    cve_rows: list[tuple] = []

    def add_artifacts(cve_id: str, kind: str, urls: Iterable[str], source: str) -> int:
        n = 0
        seen: set[str] = set()
        for url in urls:
            if not url or url in seen:
                continue
            seen.add(url)
            extra: dict[str, Any] = {}
            repo = github_repo_key(url)
            if repo and repo in repo_meta:
                stars, pushed = (repo_meta[repo] + [None, None])[:2] if isinstance(repo_meta[repo], list) else (None, None)
                extra["stars"] = stars
                extra["pushed"] = pushed
                extra["repo"] = repo
            trusted = 1 if is_trusted_url(url) else 0
            artifact_rows.append(
                (
                    cve_id,
                    kind,
                    url,
                    None,
                    json.dumps(extra, ensure_ascii=False) if extra else None,
                    source,
                    trusted,
                )
            )
            n += 1
        return n

    for rec in cve_list:
        if not isinstance(rec, dict):
            continue
        cve_id = (rec.get("cve") or "").upper().strip()
        if not cve_id.startswith("CVE-"):
            continue
        desc = rec.get("desc") or ""
        title = rec.get("title") or None
        vendors = _as_list(rec.get("vendor"))
        products = _as_list(rec.get("product"))
        vendor_s = ", ".join(vendors) if vendors else None
        products_s = ", ".join(products) if products else None

        nmeta = nuclei_meta.get(cve_id) or {}
        cwe = nmeta.get("cwe") or guess_cwe_from_text(" ".join(x for x in [title, desc] if x))
        meta_row = metadata.get(cve_id) if isinstance(metadata, dict) else None
        cvss_score, cvss_severity, cvss_vector = _pick_cvss(meta_row)
        if cvss_score is None and nmeta.get("cvss") is not None:
            try:
                cvss_score = float(nmeta["cvss"])
                cvss_severity = nmeta.get("severity")
                cvss_vector = nmeta.get("cvss_vector")
            except (TypeError, ValueError):
                pass

        kev_row = kev.get(cve_id) if isinstance(kev, dict) else None
        kev_flag = 0
        kev_date = None
        if isinstance(kev_row, list) and kev_row:
            kev_flag = 1
            kev_date = str(kev_row[0])
        if cve_id in cisa_set:
            kev_flag = 1

        epss_row = epss.get(cve_id) if isinstance(epss, dict) else None
        epss_v = epss_p = None
        if isinstance(epss_row, list) and epss_row:
            try:
                epss_v = float(epss_row[0])
                epss_p = float(epss_row[1]) if len(epss_row) > 1 else None
            except (TypeError, ValueError):
                pass

        poc_urls = _as_list(rec.get("poc"))
        nuclei_urls = _as_list(rec.get("nuclei"))
        msf_urls = _as_list(rec.get("msf"))
        edb_urls = _as_list(rec.get("edb"))
        vulhub_urls = _as_list(rec.get("vulhub"))
        collection_urls = _as_list(rec.get("collections"))
        advisories = []
        if isinstance(meta_row, dict):
            for adv in meta_row.get("advisories") or []:
                if isinstance(adv, (list, tuple)) and adv:
                    advisories.append(str(adv[0]))

        # 官方 nuclei 模板优先补全
        nd = nuclei_by_cve.get(cve_id)
        has_official = 0
        if nd and nd.get("file_path"):
            official = (
                "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
                + nd["file_path"]
            )
            if official not in nuclei_urls:
                nuclei_urls.insert(0, official)
            has_official = 1
        else:
            has_official = 1 if any(prefer_official_nuclei(u) for u in nuclei_urls) else 0

        poc_n = add_artifacts(cve_id, "poc", poc_urls, "pocindex")
        nuc_n = add_artifacts(cve_id, "nuclei", nuclei_urls, "pocindex+nuclei-templates")
        msf_n = add_artifacts(cve_id, "msf", msf_urls, "pocindex")
        edb_n = add_artifacts(cve_id, "edb", edb_urls, "pocindex")
        vul_n = add_artifacts(cve_id, "vulhub", vulhub_urls, "pocindex+vulhub")
        add_artifacts(cve_id, "collection", collection_urls, "pocindex")
        add_artifacts(cve_id, "advisory", advisories[:12], "pocindex-metadata")

        version_hints = extract_version_hints(" ".join(x for x in [title, desc] if x))
        version_hint_s = ", ".join(version_hints) if version_hints else None
        for prod in products or []:
            product_rows.append((cve_id, vendor_s, prod, version_hint_s))
        if not products:
            # 没有结构化产品名时，仍保留版本提示，便于 FTS
            pass

        sources = ["pocindex"]
        if nd:
            sources.append("nuclei-templates")
        if kev_flag:
            sources.append("cisa-kev")

        cve_rows.append(
            (
                cve_id,
                title,
                desc,
                vendor_s,
                products_s,
                cwe,
                cvss_score,
                cvss_severity,
                cvss_vector,
                rec.get("published"),
                rec.get("modified"),
                kev_flag,
                kev_date,
                epss_v,
                epss_p,
                poc_n,
                nuc_n,
                msf_n,
                edb_n,
                vul_n,
                has_official,
                ",".join(sources),
                now,
            )
        )

    if not cve_rows:
        return {
            "cves": 0,
            "artifacts": 0,
            "products": 0,
            "curated": 0,
            "skipped": "no valid CVE records, database unchanged",
            "ingested_at": now,
        }

    try:
        _replace_upstream_tables(conn)
        conn.executemany(
            """
            INSERT INTO cves (
                cve_id, title, description, vendor, products, cwe,
                cvss_score, cvss_severity, cvss_vector, published, modified,
                kev, kev_date, epss, epss_percentile,
                poc_count, nuclei_count, msf_count, edb_count, vulhub_count,
                has_official_nuclei, sources, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            cve_rows,
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO artifacts (cve_id, kind, url, title, extra, source, trusted)
            VALUES (?,?,?,?,?,?,?)
            """,
            artifact_rows,
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO products (cve_id, vendor, product, version_hint)
            VALUES (?,?,?,?)
            """,
            product_rows,
        )

        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            ("upstream_ingested_at", now),
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            ("upstream_cve_count", str(len(cve_rows))),
        )
        curated_n = apply_curated(conn, commit=False)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    # FTS 含 DROP/CREATE，SQLite DDL 会隐式提交；放在上游数据提交之后。
    rebuild_fts(conn)

    stats = {
        "cves": len(cve_rows),
        "artifacts": len(artifact_rows),
        "products": len(product_rows),
        "curated": curated_n,
        "ingested_at": now,
    }
    return stats


def apply_curated(
    conn: sqlite3.Connection, path: Path | None = None, commit: bool = True
) -> int:
    """导入本地精选记录。不删除已有人工记录，按 cve_id upsert。"""
    path = path or config.CURATED_PATH
    if not path.exists():
        return 0
    data = load_json(path) or []
    if isinstance(data, dict):
        data = data.get("records") or data.get("notes") or []
    n = 0
    now = utc_now()
    for rec in data:
        if not isinstance(rec, dict):
            continue
        cve_id = (rec.get("cve_id") or rec.get("cve") or "").upper().strip()
        if not cve_id.startswith("CVE-"):
            continue
        # 已有本地记录优先，避免 update 用 curated.json 覆盖人工补充
        conn.execute(
            """
            INSERT OR IGNORE INTO local_notes (
                cve_id, aliases, affected_versions, preconditions,
                exploit_notes, tags, extra, updated_at
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                cve_id,
                _join(rec.get("aliases")),
                _join(rec.get("affected_versions")),
                rec.get("preconditions"),
                rec.get("exploit_notes"),
                _join(rec.get("tags")),
                json.dumps(rec.get("extra"), ensure_ascii=False) if rec.get("extra") else None,
                rec.get("updated_at") or now,
            ),
        )
        status = rec.get("verification") or rec.get("status")
        if status:
            conn.execute(
                """
                INSERT OR IGNORE INTO local_verifications (
                    cve_id, status, evidence, lab, verified_at, reviewer
                ) VALUES (?,?,?,?,?,?)
                """,
                (
                    cve_id,
                    status,
                    rec.get("evidence"),
                    rec.get("lab"),
                    rec.get("verified_at"),
                    rec.get("reviewer"),
                ),
            )
        n += 1
    if commit:
        conn.commit()
    return n


def rebuild_fts(conn: sqlite3.Connection, commit: bool = True) -> None:
    conn.execute("DROP TABLE IF EXISTS cves_fts")
    conn.execute(
        """
        CREATE VIRTUAL TABLE cves_fts USING fts5(
            cve_id,
            title,
            description,
            vendor,
            products,
            cwe,
            preconditions,
            tags,
            aliases,
            tokenize='unicode61 remove_diacritics 2'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO cves_fts (
            cve_id, title, description, vendor, products, cwe, preconditions, tags, aliases
        )
        SELECT
            c.cve_id,
            COALESCE(c.title, ''),
            COALESCE(c.description, ''),
            COALESCE(c.vendor, ''),
            COALESCE(c.products, ''),
            COALESCE(c.cwe, ''),
            COALESCE(n.preconditions, ''),
            COALESCE(n.tags, ''),
            COALESCE(n.aliases, '')
        FROM cves c
        LEFT JOIN local_notes n ON n.cve_id = c.cve_id
        """
    )
    if commit:
        conn.commit()


def upsert_fts(conn: sqlite3.Connection, cve_id: str) -> None:
    """单条 note 变更后增量更新 FTS，避免全表重建。"""
    cve_id = cve_id.upper().strip()
    conn.execute("DELETE FROM cves_fts WHERE cve_id = ?", (cve_id,))
    conn.execute(
        """
        INSERT INTO cves_fts (
            cve_id, title, description, vendor, products, cwe, preconditions, tags, aliases
        )
        SELECT
            c.cve_id,
            COALESCE(c.title, ''),
            COALESCE(c.description, ''),
            COALESCE(c.vendor, ''),
            COALESCE(c.products, ''),
            COALESCE(c.cwe, ''),
            COALESCE(n.preconditions, ''),
            COALESCE(n.tags, ''),
            COALESCE(n.aliases, '')
        FROM cves c
        LEFT JOIN local_notes n ON n.cve_id = c.cve_id
        WHERE c.cve_id = ?
        """,
        (cve_id,),
    )
    conn.commit()


def _join(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(x) for x in value if x)
    s = str(value).strip()
    return s or None
