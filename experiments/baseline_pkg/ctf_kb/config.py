"""路径与运行时配置。"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("CTF_KB_HOME", ROOT / "data")).expanduser().resolve()
RAW_DIR = DATA_DIR / "raw"
LOCAL_DIR = DATA_DIR / "local"
DB_PATH = Path(os.environ.get("CTF_KB_DB", DATA_DIR / "ctf-kb.sqlite")).expanduser().resolve()
CURATED_PATH = Path(
    os.environ.get("CTF_KB_CURATED", LOCAL_DIR / "curated.json")
).expanduser().resolve()

USER_AGENT = os.environ.get("CTF_KB_UA", "ctf-kb/0.1 (+local CTF knowledge base)")

# 检索默认条数：避免低质量长尾污染 Agent 上下文
DEFAULT_LIMIT = 8
MAX_LIMIT = 30
MAX_POC_LINKS = 8
MAX_OTHER_LINKS = 6

SOURCES = {
    "pocindex_cve_list": "https://pocindex.io/CVE_list.json",
    "pocindex_metadata": "https://pocindex.io/cve_metadata.json",
    "pocindex_epss": "https://pocindex.io/epss.json",
    "pocindex_nuclei": "https://pocindex.io/nuclei.json",
    "pocindex_kev": "https://pocindex.io/kev.json",
    "pocindex_repo_meta": "https://pocindex.io/repo_meta.json",
    "nuclei_cves": (
        "https://raw.githubusercontent.com/projectdiscovery/"
        "nuclei-templates/main/cves.json"
    ),
    "cisa_kev": (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    ),
}

RAW_FILES = {
    "pocindex_cve_list": "CVE_list.json",
    "pocindex_metadata": "cve_metadata.json",
    "pocindex_epss": "epss.json",
    "pocindex_nuclei": "nuclei.json",
    "pocindex_kev": "kev.json",
    "pocindex_repo_meta": "repo_meta.json",
    "nuclei_cves": "nuclei_cves.json",
    "cisa_kev": "cisa_kev.json",
}
