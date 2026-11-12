"""版本比较与适用性判定。

结果只允许：affected / not_affected / unknown。
没有结构化范围时必须是 unknown，不得用描述里的子串当成受影响证据。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ctf_kb import config

_SPLIT = re.compile(r"[^0-9A-Za-z]+")
_VER = re.compile(
    r"\d+(?:\.[0-9A-Za-z]+)+",
)
_RANGE_BEFORE = re.compile(
    r"(?P<series>\d+(?:\.\d+){0,3})(?:\.x)?\s+before\s+(?P<end>\d+(?:\.[0-9A-Za-z]+)+)",
    re.I,
)
_RANGE_THROUGH = re.compile(
    r"(?:through|upto|up to|<=)\s+(?P<end>\d+(?:\.[0-9A-Za-z]+)+)",
    re.I,
)
_RANGE_SPAN = re.compile(
    r"(?P<start>\d+(?:\.[0-9A-Za-z]+)+)\s+(?:through|to)\s+(?P<end>\d+(?:\.[0-9A-Za-z]+)+)",
    re.I,
)
_ONLY_AFFECTS = re.compile(
    r"only affects[^\d]*((?:\d+(?:\.\d+){1,3}(?:\s+and\s+)?)+)",
    re.I,
)


def parse_version(text: str | None) -> tuple[tuple, str] | None:
    """把版本字符串变成可比较元组。无法解析则返回 None。"""
    if not text:
        return None
    raw = str(text).strip()
    raw = raw.lstrip("vV")
    if not raw:
        return None
    parts: list = []
    for tok in _SPLIT.split(raw):
        if not tok:
            continue
        m = re.match(r"(\d+)([A-Za-z]*)(\d*)", tok)
        if not m:
            parts.append(tok.lower())
            continue
        num = int(m.group(1))
        suf = m.group(2).lower()
        tail = int(m.group(3)) if m.group(3) else 0
        # 数字主段；字母后缀（1.0.1g / p2）作为后续分量
        parts.append(num)
        if suf:
            parts.append(suf)
            if m.group(3):
                parts.append(tail)
    if not parts:
        return None
    return tuple(parts), raw


def _pad(a: tuple, b: tuple) -> tuple[tuple, tuple]:
    n = max(len(a), len(b))

    def norm(t: tuple) -> tuple:
        out = []
        for i in range(n):
            if i < len(t):
                out.append(t[i])
            else:
                out.append(0 if (not out or isinstance(out[-1], int)) else "")
        return tuple(out)

    return norm(a), norm(b)


def cmp_version(a: str, b: str) -> int | None:
    pa, pb = parse_version(a), parse_version(b)
    if not pa or not pb:
        return None
    xa, xb = _pad(pa[0], pb[0])
    # 混类型：int 与 str 不能直接比，把 str 映射到负数区间之后
    def key(v):
        return (0, v) if isinstance(v, int) else (1, str(v))

    ka, kb = tuple(key(x) for x in xa), tuple(key(x) for x in xb)
    return (ka > kb) - (ka < kb)


def versions_equal(a: str, b: str) -> bool:
    c = cmp_version(a, b)
    if c is not None:
        return c == 0
    return a.strip().lower() == b.strip().lower()


@dataclass
class VersionConstraint:
    start_incl: str | None = None
    start_excl: str | None = None
    end_incl: str | None = None
    end_excl: str | None = None
    exact: str | None = None

    def covers(self, version: str) -> bool | None:
        if self.exact:
            eq = versions_equal(version, self.exact)
            return eq
        checks: list[bool | None] = []
        if self.start_incl:
            c = cmp_version(version, self.start_incl)
            checks.append(None if c is None else c >= 0)
        if self.start_excl:
            c = cmp_version(version, self.start_excl)
            checks.append(None if c is None else c > 0)
        if self.end_incl:
            c = cmp_version(version, self.end_incl)
            checks.append(None if c is None else c <= 0)
        if self.end_excl:
            c = cmp_version(version, self.end_excl)
            checks.append(None if c is None else c < 0)
        if not checks:
            return None
        if any(x is None for x in checks):
            return None
        return all(checks)


@dataclass
class VersionRange:
    cve_id: str
    product: str | None
    constraints: list[VersionConstraint] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    source: str = ""
    raw: str = ""

    def evaluate(self, version: str) -> str:
        if any(versions_equal(version, x) for x in self.exclusions):
            return "not_affected"
        hits: list[bool] = []
        unknown = False
        for cons in self.constraints:
            r = cons.covers(version)
            if r is None:
                unknown = True
            elif r:
                hits.append(True)
        if hits:
            return "affected"
        if unknown and not self.constraints:
            return "unknown"
        if self.constraints and not unknown:
            return "not_affected"
        return "unknown"


def _constraints_from_mapping(item: dict[str, Any]) -> list[VersionConstraint]:
    out: list[VersionConstraint] = []
    for c in item.get("constraints") or []:
        if not isinstance(c, dict):
            continue
        if c.get("exact"):
            out.append(VersionConstraint(exact=str(c["exact"])))
            continue
        out.append(
            VersionConstraint(
                start_incl=c.get("start_incl"),
                start_excl=c.get("start_excl"),
                end_incl=c.get("end_incl"),
                end_excl=c.get("end_excl"),
            )
        )
    return out


def load_range_file(path: Path | None = None) -> list[VersionRange]:
    path = path or (config.LOCAL_DIR / "version_ranges.json")
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("ranges") if isinstance(data, dict) else data
    out: list[VersionRange] = []
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        cve = (item.get("cve_id") or item.get("cve") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        out.append(
            VersionRange(
                cve_id=cve,
                product=item.get("product"),
                constraints=_constraints_from_mapping(item),
                exclusions=[str(x) for x in (item.get("exclusions") or [])],
                source=item.get("source") or str(path),
                raw=item.get("raw") or "",
            )
        )
    return out


def parse_affected_text(cve_id: str, text: str, source: str) -> VersionRange | None:
    """从人工精选/公告短句解析范围。只认明确的 before/through/only affects/列举。"""
    if not text:
        return None
    constraints: list[VersionConstraint] = []
    for m in _RANGE_BEFORE.finditer(text):
        series = m.group("series")
        end = m.group("end")
        # 2.5.x before 2.5.10.1 → 从 2.5.0 起（不含 end）
        start = series[:-2] if series.endswith(".x") else series
        if start.count(".") == 1:
            start_incl = start + ".0"
        else:
            start_incl = start
        constraints.append(VersionConstraint(start_incl=start_incl, end_excl=end))
    for m in _RANGE_SPAN.finditer(text):
        constraints.append(
            VersionConstraint(start_incl=m.group("start"), end_incl=m.group("end"))
        )
    if not any(c.start_incl and c.end_incl for c in constraints):
        m = _RANGE_THROUGH.search(text)
        if m:
            constraints.append(VersionConstraint(end_incl=m.group("end")))
    only = _ONLY_AFFECTS.search(text)
    if only:
        vers = re.findall(r"\d+(?:\.\d+){1,3}", only.group(1))
        for v in vers:
            constraints.append(VersionConstraint(exact=v))
    if not constraints:
        # 纯列举："2.4.49, 2.4.50" 且文本很短
        vers = re.findall(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b", text)
        if vers and len(text) < 120 and not re.search(r"before|through|prior", text, re.I):
            for v in vers:
                constraints.append(VersionConstraint(exact=v))
    if not constraints:
        return None
    return VersionRange(
        cve_id=cve_id.upper(),
        product=None,
        constraints=constraints,
        source=source,
        raw=text,
    )


def evaluate_version(
    version: str | None,
    ranges: Iterable[VersionRange],
) -> tuple[str, str | None]:
    """综合多条范围。有一条 affected 则 affected；全部可判定且均否定则 not_affected。"""
    if not version:
        return "unknown", None
    seen = False
    any_affected = False
    any_unknown = False
    evidence = None
    for rng in ranges:
        seen = True
        st = rng.evaluate(version)
        if st == "affected":
            any_affected = True
            evidence = rng.source or rng.raw
        elif st == "unknown":
            any_unknown = True
        elif st == "not_affected" and evidence is None:
            evidence = rng.source or rng.raw
    if not seen:
        return "unknown", None
    if any_affected:
        return "affected", evidence
    if any_unknown:
        return "unknown", evidence
    return "not_affected", evidence
