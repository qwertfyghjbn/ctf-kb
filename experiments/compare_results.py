#!/usr/bin/env python3
"""对照 Baseline / Improved 的逐样本表。"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(tag: str) -> dict:
    p = ROOT / "experiments" / "results" / f"{tag}.json"
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> int:
    base = load("baseline")
    imp = load("improved")
    bm, im = base["metrics"], imp["metrics"]
    lines: list[str] = [
        "# 检索对照实验",
        "",
        "| 指标 | Baseline | Improved |",
        "|---|---:|---:|",
    ]
    for k in (
        "n_scored",
        "recall_at_5",
        "mrr",
        "mismatch_rate",
        "mismatch_count",
        "empty_ok",
        "empty_fail",
        "fts_errors",
    ):
        lines.append(f"| {k} | {bm.get(k)} | {im.get(k)} |")
    lines.append(
        f"| P50 ms | {bm['latency_ms']['p50']:.2f} | {im['latency_ms']['p50']:.2f} |"
    )
    lines.append(
        f"| P95 ms | {bm['latency_ms']['p95']:.2f} | {im['latency_ms']['p95']:.2f} |"
    )
    lines.extend(
        [
            "",
            "| id | query | B hit | I hit | B ids | I ids | B mismatch | I mismatch |",
            "|---|---|---:|---:|---|---|---|---|",
        ]
    )
    brow = {r["case_id"]: r for r in base["rows"]}
    irow = {r["case_id"]: r for r in imp["rows"]}
    for cid, br in brow.items():
        ir = irow[cid]
        lines.append(
            "| {id} | {q} | {bh} | {ih} | {bids} | {iids} | {bm} | {im} |".format(
                id=cid,
                q=br["query"].replace("|", "/"),
                bh=br.get("hit_rank") or "-",
                ih=ir.get("hit_rank") or "-",
                bids=",".join(br["ids"][:5]) or "-",
                iids=",".join(ir["ids"][:5]) or "-",
                bm=br.get("mismatch"),
                im=ir.get("mismatch"),
            )
        )
    text = "\n".join(lines) + "\n"
    dest = ROOT / "experiments" / "results" / "comparison.md"
    dest.write_text(text, encoding="utf-8")
    print(text)
    print(f"写入 {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
