"""从描述文本中抽取版本提示与利用前提。

这些规则是启发式的，结果一律视为“提示”而不是判定。
不得仅凭版本字符串认定目标一定存在漏洞。
"""

from __future__ import annotations

import re

VERSION_PATTERNS = [
    re.compile(
        r"(?:(?:through|before|prior to|upto|up to|<=|<)\s*)"
        r"(\d+(?:\.\d+){1,4}(?:[-._]?(?:beta|rc|alpha|p|patch)?\d*)?)",
        re.I,
    ),
    re.compile(
        r"(\d+(?:\.\d+){1,4})\s*(?:through|to|and|-|–)\s*"
        r"(\d+(?:\.\d+){1,4})",
        re.I,
    ),
    re.compile(
        r"(?:version|versions|v\.?)\s*"
        r"(\d+(?:\.\d+){1,4}(?:[-._]?(?:beta|rc|alpha)?\d*)?)",
        re.I,
    ),
    re.compile(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b"),
]

PRECONDITION_HINTS = [
    (re.compile(r"cgi", re.I), "可能需要开启 CGI / mod_cgi"),
    (re.compile(r"require all denied", re.I), "默认 require all denied 可能阻止利用"),
    (re.compile(r"mod_cgi|mod_cgid", re.I), "可能依赖 Apache mod_cgi / mod_cgid"),
    (re.compile(r"message lookup|jndi", re.I), "可能依赖 JNDI / message lookup"),
    (re.compile(r"WAR deployment|deployed as a Spring Boot", re.I), "利用可能依赖 WAR / 非可执行 jar 部署"),
    (re.compile(r"JDK 9\+", re.I), "可能要求 JDK 9+"),
    (re.compile(r"unserialize|deserialization|pickle", re.I), "可能需要可控反序列化输入"),
    (re.compile(r"authentication bypass|unauthenticated", re.I), "可能无需认证"),
    (re.compile(r"requires authentication|authenticated", re.I), "可能需要已认证会话"),
    (re.compile(r"debug(?:\s+mode)?", re.I), "可能需要开启 debug"),
    (re.compile(r"file upload", re.I), "可能依赖文件上传功能"),
    (re.compile(r"path traversal|directory traversal", re.I), "路径穿越类，受 Alias / DocumentRoot / 权限配置影响"),
]


def extract_version_hints(text: str | None, limit: int = 8) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for pat in VERSION_PATTERNS:
        for m in pat.finditer(text):
            token = " ".join(g for g in m.groups() if g)
            token = token.strip()
            if not token or token in seen:
                continue
            # 过滤年份和 CVE 编号碎片
            if re.fullmatch(r"20\d{2}", token):
                continue
            seen.add(token)
            found.append(token)
            if len(found) >= limit:
                return found
    return found


def extract_preconditions(text: str | None, limit: int = 6) -> list[str]:
    if not text:
        return []
    hints: list[str] = []
    seen: set[str] = set()
    for pat, msg in PRECONDITION_HINTS:
        if pat.search(text) and msg not in seen:
            seen.add(msg)
            hints.append(msg)
            if len(hints) >= limit:
                break
    return hints


def guess_cwe_from_text(text: str | None) -> str | None:
    """仅在上游没有 CWE 时做弱分类，供按类型检索。"""
    if not text:
        return None
    t = text.lower()
    mapping = [
        ("sql injection", "CWE-89"),
        ("command injection", "CWE-77"),
        ("os command", "CWE-78"),
        ("code injection", "CWE-94"),
        ("deserialization", "CWE-502"),
        ("unserialize", "CWE-502"),
        ("path traversal", "CWE-22"),
        ("directory traversal", "CWE-22"),
        ("xml external entity", "CWE-611"),
        ("xxe", "CWE-611"),
        ("ssrf", "CWE-918"),
        ("server-side request", "CWE-918"),
        ("cross-site scripting", "CWE-79"),
        ("cross site scripting", "CWE-79"),
        ("xss", "CWE-79"),
        ("csrf", "CWE-352"),
        ("buffer overflow", "CWE-120"),
        ("use after free", "CWE-416"),
        ("authentication bypass", "CWE-287"),
        ("privilege escalation", "CWE-269"),
        ("file inclusion", "CWE-98"),
        ("lfi", "CWE-98"),
        ("rfi", "CWE-98"),
        ("ssti", "CWE-1336"),
        ("template injection", "CWE-1336"),
        ("jndi", "CWE-917"),
        ("log4j", "CWE-917"),
        ("prototype pollution", "CWE-1321"),
        ("open redirect", "CWE-601"),
        ("insecure deserialization", "CWE-502"),
    ]
    for needle, cwe in mapping:
        if needle in t:
            return cwe
    return None
