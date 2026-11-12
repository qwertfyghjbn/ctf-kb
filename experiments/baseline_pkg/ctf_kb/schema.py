"""SQLite schema。

设计要点：
- 上游索引写入 cves / artifacts / products，更新时可整体替换。
- 本地精选与验证写入 local_notes / local_verifications，update 不会覆盖。
- FTS5 做关键词检索；精确 CVE / 产品走普通索引。
"""

from __future__ import annotations

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id            TEXT PRIMARY KEY,
    title             TEXT,
    description       TEXT,
    vendor            TEXT,
    products          TEXT,
    cwe               TEXT,
    cvss_score        REAL,
    cvss_severity     TEXT,
    cvss_vector       TEXT,
    published         TEXT,
    modified          TEXT,
    kev               INTEGER NOT NULL DEFAULT 0,
    kev_date          TEXT,
    epss              REAL,
    epss_percentile   REAL,
    poc_count         INTEGER NOT NULL DEFAULT 0,
    nuclei_count      INTEGER NOT NULL DEFAULT 0,
    msf_count         INTEGER NOT NULL DEFAULT 0,
    edb_count         INTEGER NOT NULL DEFAULT 0,
    vulhub_count      INTEGER NOT NULL DEFAULT 0,
    has_official_nuclei INTEGER NOT NULL DEFAULT 0,
    sources           TEXT,
    updated_at        TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,   -- poc / nuclei / msf / edb / vulhub / collection / advisory
    url         TEXT NOT NULL,
    title       TEXT,
    extra       TEXT,            -- JSON：stars、path、tags 等
    source      TEXT NOT NULL,
    trusted     INTEGER NOT NULL DEFAULT 0, -- 1=官方/知名项目链接，0=社区 PoC
    UNIQUE(cve_id, kind, url)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_cve ON artifacts(cve_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_kind ON artifacts(kind);

CREATE TABLE IF NOT EXISTS products (
    cve_id   TEXT NOT NULL,
    vendor   TEXT,
    product  TEXT NOT NULL,
    version_hint TEXT,           -- 从描述中抽取的版本提示，非精确 CPE
    PRIMARY KEY (cve_id, product)
);

CREATE INDEX IF NOT EXISTS idx_products_product ON products(product);
CREATE INDEX IF NOT EXISTS idx_products_vendor ON products(vendor);
CREATE INDEX IF NOT EXISTS idx_cves_cwe ON cves(cwe);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev);

-- 本地精选：不会被上游 update 覆盖
CREATE TABLE IF NOT EXISTS local_notes (
    cve_id           TEXT PRIMARY KEY,
    aliases          TEXT,
    affected_versions TEXT,
    preconditions    TEXT,
    exploit_notes    TEXT,
    tags             TEXT,
    extra            TEXT,
    updated_at       TEXT
);

-- 本地验证状态：unverified / static_review / verified_ok / verified_fail
CREATE TABLE IF NOT EXISTS local_verifications (
    cve_id     TEXT PRIMARY KEY,
    status     TEXT NOT NULL DEFAULT 'unverified',
    evidence   TEXT,
    lab        TEXT,
    verified_at TEXT,
    reviewer   TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
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
);
"""


def init_db(conn) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()
