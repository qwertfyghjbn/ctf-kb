#!/usr/bin/env python3
"""对照实验评测：同一 SQLite 快照、相同测试集。

用法：
  python3 experiments/eval_search.py --tag baseline --pkg experiments.baseline_pkg
  python3 experiments/eval_search.py --tag improved
"""

from __future__ import annotations

import argparse
import importlib
import json
import sqlite3
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REPEAT = 5
WARMUP = 1


def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    k = (len(ys) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(ys) - 1)
    if f == c:
        return ys[f]
    return ys[f] + (ys[c] - ys[f]) * (k - f)


def load_search(pkg: str | None):
    if pkg:
        mod = importlib.import_module(f"{pkg}.ctf_kb.search")
        ingest = importlib.import_module(f"{pkg}.ctf_kb.ingest")
    else:
        from ctf_kb import search as mod
        from ctf_kb import ingest

    return mod, ingest


def probe_fts(mod, conn, query: str) -> dict:
    """直接探测 FTS MATCH 是否语法错误。"""
    fn = getattr(mod, "_fts_query", None)
    if not fn:
        return {"fts_query": None, "fts_error": None, "fts_ok": None}
    expr = fn(query)
    if not expr:
        return {"fts_query": "", "fts_error": None, "fts_ok": True}
    try:
        conn.execute("SELECT cve_id FROM cves_fts WHERE cves_fts MATCH ? LIMIT 1", (expr,))
        return {"fts_query": expr, "fts_error": None, "fts_ok": True}
    except sqlite3.OperationalError as exc:
        return {"fts_query": expr, "fts_error": str(exc), "fts_ok": False}


def run_one(mod, conn, query: str, limit: int = 5) -> dict:
    t0 = time.perf_counter()
    payload = mod.search(conn, query, limit=limit)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    results = payload.get("results") or []
    ids = [r.get("cve_id") for r in results]
    json_bytes = len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
    fts = probe_fts(mod, conn, query)
    return {
        "query": query,
        "ids": ids,
        "count": payload.get("count"),
        "product": payload.get("product"),
        "version": payload.get("version"),
        "status": payload.get("status"),
        "error": payload.get("error"),
        "elapsed_ms": elapsed_ms,
        "json_bytes": json_bytes,
        "fts": fts,
        "match_reasons": [r.get("match_reason") for r in results],
        "version_status": [r.get("version_status") for r in results],
        "cwes": [r.get("cwe") for r in results],
    }


def metrics(cases: list[dict], rows: list[dict]) -> dict:
    scored = []
    mrr_vals = []
    recalls = []
    mismatch_n = 0
    mismatch_d = 0
    empty_ok = 0
    empty_fail = 0
    fts_err = 0
    for case, row in zip(cases, rows):
        if row["fts"].get("fts_ok") is False:
            fts_err += 1
        ids = row["ids"]
        if case.get("expect_empty"):
            if not ids:
                empty_ok += 1
            else:
                empty_fail += 1
        excluded = case.get("excluded_cves") or []
        if excluded:
            mismatch_d += 1
            if any(c in ids for c in excluded):
                mismatch_n += 1
        if not case.get("scored"):
            continue
        relevant = case.get("relevant_cves") or []
        if not relevant and case.get("expect_empty"):
            # 无结果查询：空结果记 recall=1, mrr=1
            hit = 1.0 if not ids else 0.0
            recalls.append(hit)
            mrr_vals.append(hit)
            scored.append(case["id"])
            continue
        if not relevant:
            continue
        hit = any(c in ids[:5] for c in relevant)
        recalls.append(1.0 if hit else 0.0)
        rank = None
        for i, cid in enumerate(ids, 1):
            if cid in relevant:
                rank = i
                break
        mrr_vals.append(0.0 if rank is None else 1.0 / rank)
        scored.append(case["id"])
    times = [r["elapsed_ms"] for r in rows]
    return {
        "n_queries": len(cases),
        "n_scored": len(scored),
        "recall_at_5": (sum(recalls) / len(recalls)) if recalls else None,
        "mrr": (sum(mrr_vals) / len(mrr_vals)) if mrr_vals else None,
        "mismatch_rate": (mismatch_n / mismatch_d) if mismatch_d else None,
        "mismatch_count": mismatch_n,
        "mismatch_denom": mismatch_d,
        "empty_ok": empty_ok,
        "empty_fail": empty_fail,
        "fts_errors": fts_err,
        "latency_ms": {
            "p50": percentile(times, 50),
            "p95": percentile(times, 95),
            "max": max(times) if times else 0,
            "mean": statistics.mean(times) if times else 0,
            "n": len(times),
        },
        "avg_json_bytes": statistics.mean([r["json_bytes"] for r in rows]) if rows else 0,
        "avg_result_count": statistics.mean([r["count"] or 0 for r in rows]) if rows else 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--pkg", default=None, help="baseline 包前缀，如 experiments.baseline_pkg")
    ap.add_argument("--db", default=str(ROOT / "data" / "ctf-kb.sqlite"))
    ap.add_argument("--testset", default=str(ROOT / "experiments" / "testset.json"))
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--repeat", type=int, default=REPEAT)
    args = ap.parse_args()

    mod, ingest = load_search(args.pkg)
    conn = ingest.connect(Path(args.db))
    testset = json.loads(Path(args.testset).read_text(encoding="utf-8"))
    cases = testset["queries"]

    # warmup
    for case in cases[:WARMUP]:
        run_one(mod, conn, case["query"], args.limit)

    timed: dict[str, list[float]] = {c["id"]: [] for c in cases}
    last_rows: list[dict] = []
    for i in range(args.repeat):
        rows = []
        for case in cases:
            row = run_one(mod, conn, case["query"], args.limit)
            timed[case["id"]].append(row["elapsed_ms"])
            rows.append(row)
        last_rows = rows

    # 用最后一轮结果做正确性，用全部重复做耗时
    for row, case in zip(last_rows, cases):
        row["elapsed_ms"] = statistics.median(timed[case["id"]])
        row["elapsed_all_ms"] = timed[case["id"]]
        row["case_id"] = case["id"]
        row["query_type"] = case["query_type"]
        row["relevant"] = case.get("relevant_cves") or []
        row["excluded"] = case.get("excluded_cves") or []
        row["scored"] = case.get("scored", True)
        row["expect_empty"] = bool(case.get("expect_empty"))
        hit_rank = None
        for i, cid in enumerate(row["ids"], 1):
            if cid in row["relevant"]:
                hit_rank = i
                break
        row["hit_rank"] = hit_rank
        row["mismatch"] = any(c in row["ids"] for c in row["excluded"])

    m = metrics(cases, last_rows)
    db_path = Path(args.db)
    out = {
        "tag": args.tag,
        "pkg": args.pkg,
        "db": str(db_path),
        "db_bytes": db_path.stat().st_size if db_path.exists() else None,
        "repeat": args.repeat,
        "warmup": WARMUP,
        "timing_note": "perf_counter，含 lookup_cve 详情组装；每查询重复 median",
        "metrics": m,
        "rows": last_rows,
    }
    dest = ROOT / "experiments" / "results" / f"{args.tag}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"tag": args.tag, "metrics": m, "out": str(dest)}, ensure_ascii=False, indent=2))
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
