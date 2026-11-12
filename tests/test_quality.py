"""URL 可信度与版本比较的单元测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctf_kb.quality import github_repo_key, is_trusted_url  # noqa: E402
from ctf_kb.versioning import (  # noqa: E402
    VersionConstraint,
    VersionRange,
    cmp_version,
    evaluate_version,
    load_range_file,
)


class UrlTrustTests(unittest.TestCase):
    def test_official_hosts(self) -> None:
        self.assertTrue(
            is_trusted_url(
                "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42013.yaml"
            )
        )
        self.assertTrue(
            is_trusted_url("https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-42013")
        )
        self.assertTrue(is_trusted_url("https://www.exploit-db.com/exploits/50406"))
        self.assertTrue(is_trusted_url("https://nvd.nist.gov/vuln/detail/CVE-2021-42013"))

    def test_substring_cannot_spoof_host(self) -> None:
        self.assertFalse(
            is_trusted_url("https://evil.example/github.com/projectdiscovery/nuclei-templates")
        )
        self.assertFalse(
            is_trusted_url("https://github.com.evil.example/projectdiscovery/nuclei-templates")
        )
        self.assertFalse(
            is_trusted_url("https://github.com/not-projectdiscovery/nuclei-templates/blob/main/x.yaml")
        )
        self.assertFalse(is_trusted_url("https://github.com/projectdiscovery/nuclei-templates-evil"))
        self.assertFalse(is_trusted_url("javascript:github.com/vulhub/vulhub"))
        self.assertFalse(is_trusted_url("https://example.com/?u=nvd.nist.gov"))

    def test_github_repo_key(self) -> None:
        self.assertEqual(
            github_repo_key("https://github.com/vulhub/vulhub/tree/master/httpd"),
            "vulhub/vulhub",
        )
        self.assertIsNone(github_repo_key("https://evil.com/github.com/vulhub/vulhub"))


class VersionTests(unittest.TestCase):
    def test_cmp_not_prefix(self) -> None:
        self.assertEqual(cmp_version("2.4.5", "2.4.50"), -1)
        self.assertEqual(cmp_version("2.4.50", "2.4.5"), 1)
        self.assertEqual(cmp_version("2.4.50", "2.4.50"), 0)
        self.assertLess(cmp_version("1.0.1f", "1.0.1g") or 0, 0)

    def test_httpd_exact(self) -> None:
        rng = VersionRange(
            cve_id="CVE-2021-42013",
            product="Apache HTTP Server",
            constraints=[
                VersionConstraint(exact="2.4.49"),
                VersionConstraint(exact="2.4.50"),
            ],
        )
        self.assertEqual(rng.evaluate("2.4.50"), "affected")
        self.assertEqual(rng.evaluate("2.4.49"), "affected")
        self.assertEqual(rng.evaluate("2.4.5"), "not_affected")
        self.assertEqual(rng.evaluate("2.4.51"), "not_affected")

    def test_struts_range(self) -> None:
        rng = VersionRange(
            cve_id="CVE-2017-5638",
            product="Apache Struts",
            constraints=[
                VersionConstraint(start_incl="2.3.0", end_excl="2.3.32"),
                VersionConstraint(start_incl="2.5.0", end_excl="2.5.10.1"),
            ],
        )
        self.assertEqual(rng.evaluate("2.5.9"), "affected")
        self.assertEqual(rng.evaluate("2.5.12"), "not_affected")
        self.assertEqual(rng.evaluate("2.3.31"), "affected")
        self.assertEqual(rng.evaluate("2.3.32"), "not_affected")

    def test_file_loaded(self) -> None:
        rows = load_range_file()
        ids = {r.cve_id for r in rows}
        self.assertIn("CVE-2021-42013", ids)
        st, _ = evaluate_version("2.4.5", [r for r in rows if r.cve_id == "CVE-2021-42013"])
        self.assertEqual(st, "not_affected")


if __name__ == "__main__":
    unittest.main()
