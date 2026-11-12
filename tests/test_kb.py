"""基础自动化测试：用小型夹具库，不依赖完整上游下载。"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctf_kb import config  # noqa: E402
from ctf_kb.ingest import apply_curated, connect, ingest, rebuild_fts  # noqa: E402
from ctf_kb.search import lookup_cve, reset_range_cache, search, show, stats  # noqa: E402


FIXTURE_CVES = [
    {
        "cve": "CVE-2021-42013",
        "title": "Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49 and 2.4.50",
        "desc": "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration require all denied, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.",
        "vendor": ["Apache Software Foundation"],
        "product": ["Apache HTTP Server"],
        "poc": ["https://github.com/example/CVE-2021-42013"],
        "nuclei": [
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42013.yaml"
        ],
        "msf": [
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/apache_normalize_path_rce.rb"
        ],
        "edb": ["https://www.exploit-db.com/exploits/50406"],
        "vulhub": ["https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-42013"],
        "published": "2021-10-07",
        "modified": "2021-10-20",
    },
    {
        "cve": "CVE-2021-41773",
        "title": "Path traversal in Apache HTTP Server 2.4.49",
        "desc": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack. If CGI scripts are also enabled this could allow for remote code execution. This issue only affects Apache 2.4.49 and not earlier versions.",
        "vendor": ["Apache Software Foundation"],
        "product": ["Apache HTTP Server"],
        "poc": ["https://github.com/example/CVE-2021-41773"],
        "nuclei": [
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41773.yaml"
        ],
        "vulhub": ["https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-41773"],
        "published": "2021-10-05",
    },
    {
        "cve": "CVE-2017-5638",
        "title": "Apache Struts Jakarta Multipart parser RCE",
        "desc": "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 allows remote attackers to execute arbitrary commands via a crafted Content-Type header.",
        "vendor": ["Apache Software Foundation"],
        "product": ["Apache Struts"],
        "poc": ["https://github.com/example/CVE-2017-5638"],
        "published": "2017-03-10",
    },
    {
        "cve": "CVE-2018-9999",
        "title": "PHP deserialization gadget demo",
        "desc": "A PHP deserialization vulnerability in ExampleCMS allows object injection via unserialize() on user-controlled cookie data.",
        "vendor": ["Example"],
        "product": ["ExampleCMS"],
        "poc": ["https://github.com/example/php-unserialize-poc"],
        "published": "2018-01-01",
    },
    {
        "cve": "CVE-2019-1234",
        "title": "Unrelated OpenSSL buffer overflow",
        "desc": "OpenSSL 1.0.2 has a buffer overflow in an unrelated parser. No path traversal, no PHP.",
        "vendor": ["OpenSSL"],
        "product": ["OpenSSL"],
        "published": "2019-01-01",
    },
]


class KbTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.raw = self.root / "raw"
        self.raw.mkdir()
        self.db = self.root / "test.sqlite"
        config.DB_PATH = self.db
        config.RAW_DIR = self.raw
        config.CURATED_PATH = self.root / "curated.json"

        (self.raw / "CVE_list.json").write_text(json.dumps(FIXTURE_CVES), encoding="utf-8")
        (self.raw / "cve_metadata.json").write_text(
            json.dumps(
                {
                    "CVE-2021-42013": {
                        "cvss": [
                            [
                                "3.1",
                                9.8,
                                "CRITICAL",
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "nvd@nist.gov",
                                "Primary",
                            ]
                        ],
                        "advisories": [
                            ["https://httpd.apache.org/security/vulnerabilities_24.html", ["Vendor Advisory"]]
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )
        (self.raw / "epss.json").write_text(
            json.dumps({"CVE-2021-42013": [0.99, 0.99]}), encoding="utf-8"
        )
        (self.raw / "nuclei.json").write_text(
            json.dumps(
                {
                    "CVE-2021-42013": {
                        "severity": "critical",
                        "cvss": 9.8,
                        "cwe": "CWE-22",
                    },
                    "CVE-2021-41773": {"cwe": "CWE-22"},
                    "CVE-2018-9999": {"cwe": "CWE-502"},
                }
            ),
            encoding="utf-8",
        )
        (self.raw / "kev.json").write_text(
            json.dumps({"CVE-2021-42013": ["2021-11-03", 1]}), encoding="utf-8"
        )
        (self.raw / "repo_meta.json").write_text("{}", encoding="utf-8")
        (self.raw / "nuclei_cves.json").write_text(
            json.dumps(
                {
                    "ID": "CVE-2021-42013",
                    "Info": {
                        "Name": "Apache 2.4.49/2.4.50 - Path Traversal",
                        "Severity": "critical",
                        "Description": "path traversal",
                        "Classification": {"CVSSScore": "9.8"},
                    },
                    "file_path": "http/cves/2021/CVE-2021-42013.yaml",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        config.CURATED_PATH.write_text(
            json.dumps(
                [
                    {
                        "cve_id": "CVE-2021-42013",
                        "affected_versions": "2.4.49, 2.4.50",
                        "preconditions": "需要 Alias 且可能需要 CGI",
                        "verification": "static_review",
                        "evidence": "静态审核夹具",
                        "lab": "fixture",
                    }
                ]
            ),
            encoding="utf-8",
        )
        reset_range_cache()
        self.conn = connect(self.db)
        ingest(self.conn, self.raw)

    def tearDown(self) -> None:
        self.conn.close()
        self.tmp.cleanup()

    def test_cve_id_lookup(self) -> None:
        rec = lookup_cve(self.conn, "CVE-2021-42013")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["cve_id"], "CVE-2021-42013")
        self.assertEqual(rec["cwe"], "CWE-22")
        self.assertTrue(rec["kev"])
        payload = search(self.conn, "CVE-2021-42013")
        ids = [r["cve_id"] for r in payload["results"]]
        self.assertIn("CVE-2021-42013", ids)

    def test_product_version_search(self) -> None:
        payload = search(self.conn, "Apache HTTP Server 2.4.50")
        ids = [r["cve_id"] for r in payload["results"]]
        self.assertIn("CVE-2021-42013", ids)
        hit = next(r for r in payload["results"] if r["cve_id"] == "CVE-2021-42013")
        self.assertEqual(hit.get("version_status"), "affected")
        self.assertNotIn("CVE-2021-41773", ids)

    def test_version_substring_not_prefix(self) -> None:
        payload = search(self.conn, "Apache HTTP Server 2.4.5")
        ids = [r["cve_id"] for r in payload["results"]]
        self.assertNotIn("CVE-2021-42013", ids)
        self.assertNotIn("CVE-2021-41773", ids)

    def test_struts_range_without_literal_version(self) -> None:
        payload = search(self.conn, "Apache Struts 2.5.9")
        ids = [r["cve_id"] for r in payload["results"]]
        self.assertIn("CVE-2017-5638", ids)
        payload2 = search(self.conn, "Apache Struts 2.5.12")
        ids2 = [r["cve_id"] for r in payload2["results"]]
        self.assertNotIn("CVE-2017-5638", ids2)

    def test_fts_special_chars_do_not_error(self) -> None:
        from ctf_kb.search import _fts_query

        for q in ("Apache 2.4.50", "nginx/1.18.0", "OpenSSH 8.4"):
            expr = _fts_query(q)
            self.assertTrue(expr, q)
            self.conn.execute(
                "SELECT cve_id FROM cves_fts WHERE cves_fts MATCH ? LIMIT 1", (expr,)
            )
        self.assertEqual(_fts_query("foo-bar"), "")
        payload = search(self.conn, "foo-bar")
        self.assertIsNone(payload.get("error"))
        self.assertEqual(payload.get("count"), 0)

    def test_empty_ingest_does_not_wipe(self) -> None:
        before = self.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        self.assertGreater(before, 0)
        empty = self.root / "empty_raw"
        empty.mkdir()
        (empty / "CVE_list.json").write_text("[]", encoding="utf-8")
        stats = ingest(self.conn, empty)
        self.assertIn("skipped", stats)
        after = self.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        self.assertEqual(before, after)

    def test_vuln_type_search(self) -> None:
        by_cwe = search(self.conn, "CWE-502")
        ids = [r["cve_id"] for r in by_cwe["results"]]
        self.assertIn("CVE-2018-9999", ids)
        by_kw = search(self.conn, "PHP deserialization")
        ids2 = [r["cve_id"] for r in by_kw["results"]]
        self.assertIn("CVE-2018-9999", ids2)

    def test_poc_sources(self) -> None:
        rec = show(self.conn, "CVE-2021-42013")
        self.assertTrue(rec["artifacts"]["poc"])
        self.assertTrue(rec["artifacts"]["nuclei"])
        self.assertTrue(rec["artifacts"]["vulhub"])
        self.assertTrue(rec["artifacts"]["msf"])
        self.assertTrue(any("nuclei-templates" in a["url"] for a in rec["artifacts"]["nuclei"]))
        self.assertTrue(any(a["trusted"] for a in rec["artifacts"]["nuclei"]))
        self.assertFalse(all(a["trusted"] for a in rec["artifacts"]["poc"]))

    def test_verification_status_distinct(self) -> None:
        a = lookup_cve(self.conn, "CVE-2021-42013")
        b = lookup_cve(self.conn, "CVE-2017-5638")
        self.assertEqual(a["verification"]["status"], "static_review")
        self.assertEqual(b["verification"]["status"], "unverified")
        self.assertNotEqual(a["verification"]["status"], b["verification"]["status"])

    def test_update_preserves_local_notes(self) -> None:
        self.conn.execute(
            """
            INSERT INTO local_notes (cve_id, preconditions, updated_at)
            VALUES ('CVE-2017-5638', '人工补充：需要文件上传栈', datetime('now'))
            """
        )
        self.conn.execute(
            """
            INSERT INTO local_verifications (cve_id, status, evidence)
            VALUES ('CVE-2017-5638', 'verified_ok', '隔离环境复现成功（夹具）')
            """
        )
        self.conn.commit()
        ingest(self.conn, self.raw)
        rec = lookup_cve(self.conn, "CVE-2017-5638")
        self.assertEqual(rec["verification"]["status"], "verified_ok")
        self.assertIn("文件上传栈", rec["local"]["note"]["preconditions"])
        # 精选文件中的 42013 也应仍在
        rec2 = lookup_cve(self.conn, "CVE-2021-42013")
        self.assertEqual(rec2["verification"]["status"], "static_review")

    def test_no_obvious_mismatch(self) -> None:
        payload = search(self.conn, "PHP deserialization")
        ids = [r["cve_id"] for r in payload["results"]]
        self.assertNotIn("CVE-2019-1234", ids)
        payload2 = search(self.conn, "OpenSSL")
        ids2 = [r["cve_id"] for r in payload2["results"]]
        self.assertIn("CVE-2019-1234", ids2)
        self.assertNotIn("CVE-2018-9999", ids2)

    def test_poc_link_is_not_exploitable_flag(self) -> None:
        rec = lookup_cve(self.conn, "CVE-2021-42013")
        self.assertTrue(rec["exploitability"]["has_poc_link"])
        self.assertFalse(rec["exploitability"]["verified"])
        self.assertIn("可利用", rec["exploitability"]["note"])
        text = json.dumps(show(self.conn, "CVE-2021-42013"), ensure_ascii=False)
        self.assertIn("不可信", text)

    def test_stats(self) -> None:
        s = stats(self.conn)
        self.assertEqual(s["cves"], 5)
        self.assertGreaterEqual(s["with_poc"], 4)
        self.assertGreaterEqual(s["local_notes"], 1)


if __name__ == "__main__":
    unittest.main()
