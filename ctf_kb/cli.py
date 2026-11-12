"""ctf-kb CLI。只负责检索与更新，不执行 PoC。"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from ctf_kb import config
from ctf_kb.ingest import connect, fetch_raw, ingest, upsert_fts
from ctf_kb.render import render_search, render_show, render_stats
from ctf_kb.search import lookup_cve, search, show, stats


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def cmd_update(args: argparse.Namespace) -> int:
    status = fetch_raw(force=not args.cached)
    conn = connect()
    result = ingest(conn)
    payload = {
        "fetch": status,
        "ingest": result,
        "curated_upserted": result.get("curated", 0),
        "db": str(config.DB_PATH),
    }
    if args.json:
        print(_dumps(payload))
    else:
        print("上游同步:")
        for k, v in status.items():
            print(f"  {k}: {v}")
        print(
            f"导入 CVE={result.get('cves')} artifacts={result.get('artifacts')} "
            f"products={result.get('products')}"
        )
        print(f"本地精选 upsert: {result.get('curated', 0)}")
        print(f"数据库: {config.DB_PATH}")
    conn.close()
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    conn = connect()
    payload = search(
        conn,
        args.query,
        limit=args.limit,
        product=args.product,
        cwe=args.cwe,
        version=args.version,
    )
    if args.json:
        print(_dumps(payload))
    else:
        print(render_search(payload))
    conn.close()
    return 0 if payload.get("count") else 1


def cmd_cve(args: argparse.Namespace) -> int:
    conn = connect()
    rec = lookup_cve(conn, args.cve_id)
    if args.json:
        if rec is None:
            print(_dumps({"error": f"未找到 {args.cve_id}", "cve_id": args.cve_id}))
            conn.close()
            return 1
        # 精简版，适合 Agent 先看摘要
        from ctf_kb.search import _summary

        print(_dumps(_summary(rec, rec.get("match_reason"))))
    else:
        if rec is None:
            print(f"未找到 {args.cve_id}")
            conn.close()
            return 1
        from ctf_kb.search import _summary
        from ctf_kb.render import render_search

        print(render_search({"query": args.cve_id, "count": 1, "results": [_summary(rec)], "disclaimer": rec.get("uncertainty")}))
    conn.close()
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    conn = connect()
    payload = show(conn, args.cve_id)
    if args.json:
        print(_dumps(payload))
    else:
        print(render_show(payload))
    conn.close()
    return 0 if not payload.get("error") else 1


def cmd_stats(args: argparse.Namespace) -> int:
    conn = connect()
    payload = stats(conn)
    if args.json:
        print(_dumps(payload))
    else:
        print(render_stats(payload))
    conn.close()
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    """新增/更新本地精选或验证状态，不会被 update 覆盖。"""
    conn = connect()
    cve_id = args.cve_id.upper().strip()
    if args.status:
        conn.execute(
            """
            INSERT INTO local_verifications (cve_id, status, evidence, lab, verified_at, reviewer)
            VALUES (?, ?, ?, ?, datetime('now'), ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                status=excluded.status,
                evidence=COALESCE(excluded.evidence, local_verifications.evidence),
                lab=COALESCE(excluded.lab, local_verifications.lab),
                verified_at=excluded.verified_at,
                reviewer=COALESCE(excluded.reviewer, local_verifications.reviewer)
            """,
            (cve_id, args.status, args.evidence, args.lab, args.reviewer),
        )
    if any([args.preconditions, args.versions, args.notes, args.tags, args.aliases]):
        conn.execute(
            """
            INSERT INTO local_notes (
                cve_id, aliases, affected_versions, preconditions, exploit_notes, tags, extra, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
                aliases=COALESCE(excluded.aliases, local_notes.aliases),
                affected_versions=COALESCE(excluded.affected_versions, local_notes.affected_versions),
                preconditions=COALESCE(excluded.preconditions, local_notes.preconditions),
                exploit_notes=COALESCE(excluded.exploit_notes, local_notes.exploit_notes),
                tags=COALESCE(excluded.tags, local_notes.tags),
                updated_at=excluded.updated_at
            """,
            (cve_id, args.aliases, args.versions, args.preconditions, args.notes, args.tags),
        )
    conn.commit()
    upsert_fts(conn, cve_id)
    payload = show(conn, cve_id)
    if args.json:
        print(_dumps({"ok": True, "cve_id": cve_id, "local_note": payload.get("local_note"), "verification": payload.get("verification")}))
    else:
        print(f"已写入本地记录: {cve_id}")
        print(render_show(payload) if not payload.get("error") else payload["error"])
    conn.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="JSON 输出，方便 Agent 解析")
    common.add_argument("--db", help="SQLite 路径，默认 data/ctf-kb.sqlite")
    p = argparse.ArgumentParser(
        prog="ctf-kb",
        description="面向 CTF Agent 的本地 CVE / PoC 知识库。只检索，不执行利用。",
        parents=[common],
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("update", parents=[common], help="同步上游索引并重建本地库（保留本地精选/验证）")
    sp.add_argument("--cached", action="store_true", help="不重新下载，只导入已有 raw JSON")
    sp.set_defaults(func=cmd_update)

    sp = sub.add_parser("search", parents=[common], help="关键词 / 产品 / 漏洞类型检索")
    sp.add_argument("query", help="如 'Apache 2.4.50' 或 'PHP deserialization'")
    sp.add_argument(
        "--limit",
        type=int,
        default=config.DEFAULT_LIMIT,
        help="默认 5，上限 30；无可靠候选时允许空结果",
    )
    sp.add_argument("--product", help="按产品名过滤")
    sp.add_argument("--cwe", help="按 CWE 过滤，如 CWE-502")
    sp.add_argument("--version", help="版本提示，仅作匹配依据而非判定")
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("cve", parents=[common], help="按 CVE ID 精确查询摘要")
    sp.add_argument("cve_id")
    sp.set_defaults(func=cmd_cve)

    sp = sub.add_parser("show", parents=[common], help="展示 CVE 详情、前提、PoC/检测资料")
    sp.add_argument("cve_id")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("stats", parents=[common], help="统计收录规模")
    sp.set_defaults(func=cmd_stats)

    sp = sub.add_parser("note", parents=[common], help="写入本地精选或验证状态（不会被 update 覆盖）")
    sp.add_argument("cve_id")
    sp.add_argument(
        "--status",
        choices=["unverified", "static_review", "verified_ok", "verified_fail"],
    )
    sp.add_argument("--evidence")
    sp.add_argument("--lab")
    sp.add_argument("--reviewer")
    sp.add_argument("--preconditions")
    sp.add_argument("--versions", help="受影响版本的人工记录")
    sp.add_argument("--notes")
    sp.add_argument("--tags")
    sp.add_argument("--aliases")
    sp.set_defaults(func=cmd_note)

    return p


def _flag_value(raw: list[str], flag: str) -> str | None:
    """子命令前后都能取到 --db 这类选项。argparse parents 会把前置选项冲掉。"""
    if flag not in raw:
        return None
    i = raw.index(flag)
    if i + 1 < len(raw) and not raw[i + 1].startswith("-"):
        return raw[i + 1]
    return None


def main(argv: list[str] | None = None) -> int:
    raw = list(argv) if argv is not None else sys.argv[1:]
    json_anywhere = "--json" in raw
    db_anywhere = _flag_value(raw, "--db")
    parser = build_parser()
    args = parser.parse_args(argv)
    if json_anywhere:
        args.json = True
    if db_anywhere:
        args.db = db_anywhere
    if args.db:
        config.DB_PATH = __import__("pathlib").Path(args.db).expanduser().resolve()
    try:
        return int(args.func(args) or 0)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
