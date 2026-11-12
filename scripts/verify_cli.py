#!/usr/bin/env python3
"""阶段 C 真实 CLI 验证（不执行任何 PoC）。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = [sys.executable, str(ROOT / "ctf-kb")]


def run(*args: str) -> tuple[int, str]:
    p = subprocess.run(BIN + list(args), cwd=ROOT, capture_output=True, text=True)
    out = p.stdout
    if p.returncode != 0 and not out:
        out = p.stderr
    return p.returncode, out


def jrun(*args: str) -> dict:
    code, out = run(*args, "--json")
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        print("JSON 解析失败", args, out[:500])
        raise
    return data


def main() -> int:
    results = []

    def ok(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        mark = "PASS" if cond else "FAIL"
        print(f"[{mark}] {name}  {detail}")

    stats = jrun("stats")
    ok("stats.cves", stats.get("cves", 0) > 80000, f"cves={stats.get('cves')}")
    ok("stats.poc_links", (stats.get("artifacts") or {}).get("poc", 0) > 0)

    s = jrun("search", "CVE-2021-42013")
    ids = [r["cve_id"] for r in s.get("results") or []]
    ok("1. CVE ID 精确检索", ids[:1] == ["CVE-2021-42013"], str(ids[:3]))

    s = jrun("search", "Apache 2.4.50", "--limit", "8")
    ids = [r["cve_id"] for r in s.get("results") or []]
    ok("2. 产品+版本能定位 42013", "CVE-2021-42013" in ids, f"top={ids}")
    ok("2b. 42013 排在前 3", "CVE-2021-42013" in ids[:3], f"top3={ids[:3]}")
    # 明显误匹配：纯 Log4j 不应压过 httpd 2.4.50
    log4j_first = ids and "44228" in ids[0]
    ok("2c. Log4j 不抢第一", not log4j_first, f"first={ids[:1]}")

    s = jrun("search", "PHP deserialization", "--limit", "8")
    cwes = [r.get("cwe") for r in s.get("results") or []]
    ok(
        "3. 漏洞类型检索",
        any(
            (r.get("cwe") == "CWE-502")
            or ("deserial" in ((r.get("title") or "") + (r.get("description") or "")).lower())
            for r in s.get("results") or []
        ),
        str(cwes),
    )

    s = jrun("search", "CWE-22", "--limit", "5")
    ok("3b. CWE-22", all(r.get("cwe") == "CWE-22" for r in s.get("results") or []) and s.get("count", 0) > 0, str([r["cve_id"] for r in s.get("results") or []]))

    rec = jrun("show", "CVE-2021-42013")
    arts = rec.get("artifacts") or {}
    ok("4. 返回 PoC 来源", bool(arts.get("poc")), f"poc={len(arts.get('poc') or [])}")
    ok("4b. nuclei", bool(arts.get("nuclei")))
    ok("4c. vulhub", bool(arts.get("vulhub")))
    ok("4d. 官方 nuclei trusted", any(a.get("trusted") for a in arts.get("nuclei") or []))

    v42013 = (rec.get("verification") or {}).get("status")
    rec2 = jrun("show", "CVE-2021-44228")
    v44228 = (rec2.get("verification") or {}).get("status")
    ok("5. 区分验证状态", v42013 == "static_review" and v44228 == "unverified", f"42013={v42013} 44228={v44228}")

    # 6. 本地记录不被 update --cached 覆盖：先 note，再 update --cached
    code, _ = run(
        "note",
        "CVE-2017-5638",
        "--status",
        "verified_fail",
        "--evidence",
        "verification-script-marker",
        "--preconditions",
        "verification-script-precondition",
    )
    ok("6a. note 写入", code == 0)
    code, _ = run("update", "--cached")
    ok("6b. update --cached", code == 0)
    rec3 = jrun("show", "CVE-2017-5638")
    ver = rec3.get("verification") or {}
    note = rec3.get("local_note") or {}
    ok(
        "6. update 保留本地记录",
        ver.get("status") == "verified_fail" and "verification-script-precondition" in (note.get("preconditions") or ""),
        f"status={ver.get('status')} pre={note.get('preconditions')}",
    )
    rec4 = jrun("show", "CVE-2021-42013")
    ok("6c. curated 仍在", (rec4.get("verification") or {}).get("status") == "static_review")

    s = jrun("search", "PHP deserialization", "--limit", "8")
    ids = [r["cve_id"] for r in s.get("results") or []]
    ok("7. PHP 反序列化不含 OpenSSL 无关洞", "CVE-2019-1234" not in ids, str(ids))

    s = jrun("search", "Apache HTTP Server 2.4.50", "--limit", "8")
    products = [r.get("products") for r in s.get("results") or []]
    ok("7b. HTTP Server 查询产品相关", any("HTTP Server" in (p or "") for p in products), str(products[:4]))

    code, out = run("cve", "CVE-2021-42013", "--json")
    ok("8. CLI JSON 可解析", code == 0 and json.loads(out).get("cve_id") == "CVE-2021-42013")

    failed = [n for n, c, _ in results if not c]
    print("\n==== 汇总 ====")
    print(f"通过 {sum(1 for _,c,_ in results if c)} / {len(results)}")
    if failed:
        print("失败:", failed)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
