from __future__ import annotations

import re

from . import maven, pep440
from .inventory.shape import pypi_name, terraform_name

_V = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")
EVENTS = ("introduced", "fixed", "last_affected", "limit")
FLOATING = re.compile(r"^v?(\d+)(?:\.(\d+))?$")


def parse(v: str) -> tuple:
    m = _V.match(v.strip())
    if not m:
        raise ValueError(f"not a semantic version: {v!r}")
    pre = m[4]
    pre_key = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return (int(m[1]), int(m[2] or 0), int(m[3] or 0), 0 if pre else 1, pre_key)


ORDER = {"npm": parse, "crates.io": parse, "go": parse, "pypi": pep440.key, "maven": maven.key, "github actions": parse}


def order(ecosystem: str):
    return ORDER.get(ecosystem.lower())


def _sorted(events: list[dict], key) -> list[tuple[str, tuple]]:
    out = []
    for ev in events:
        kind = next((k for k in EVENTS if k in ev), None)
        if kind == "introduced" and ev[kind] == "0":
            out.append((kind, (0,)))
        elif kind is not None:
            out.append((kind, (1, key(ev[kind]))))
    return sorted(out, key=lambda e: e[1])


def in_range(version: str, events: list[dict], key=parse) -> bool | None:
    try:
        v = (1, key(version))
        affected = False
        ordered = _sorted(events, key)
        limits = [at for kind, at in ordered if kind == "limit"]
        if limits and v >= max(limits):
            return False
        for kind, at in ordered:
            if kind == "introduced" and v >= at:
                affected = True
            elif kind == "fixed" and v >= at:
                affected = False
            elif kind == "last_affected" and v > at:
                affected = False
        return affected
    except ValueError:
        return None


def floating(version: str, ecosystem: str) -> tuple[str, str] | None:
    m = FLOATING.match(version.strip()) if ecosystem.lower() == "github actions" else None
    if m is None:
        return None
    if m[2] is None:
        return f"{m[1]}.0.0", f"{int(m[1]) + 1}.0.0-0"
    return f"{m[1]}.{m[2]}.0", f"{m[1]}.{int(m[2]) + 1}.0-0"


def span_in_range(low: str, high: str, events: list[dict], key=parse) -> bool | None:
    try:
        lo, hi = (1, key(low)), (1, key(high))
        for kind, at in _sorted(events, key):
            if lo < at < hi or (kind == "last_affected" and lo <= at < hi):
                return None
    except ValueError:
        return None
    return in_range(low, events, key)


def same_package(ecosystem: str, name: str, pkg: dict) -> bool:
    if (pkg.get("ecosystem") or "").lower() != ecosystem.lower():
        return False
    if ecosystem.lower() == "pypi":
        return pypi_name(pkg.get("name") or "") == pypi_name(name)
    if ecosystem.lower() == "github actions":
        return (pkg.get("name") or "").lower() == name.lower()
    if ecosystem.lower() == "terraform":
        return terraform_name(pkg.get("name") or "") == terraform_name(name)
    return pkg.get("name") == name


def _verdict(version: str, ecosystem: str, r: dict) -> bool | None:
    key = parse if r.get("type") == "SEMVER" else order(ecosystem)
    if key is None:
        return None
    span = floating(version, ecosystem)
    if span is not None:
        return span_in_range(*span, r.get("events") or [], key)
    return in_range(version, r.get("events") or [], key)


def affects(version: str, ecosystem: str, name: str, affected: list[dict]) -> bool | None:
    verdicts = []
    for a in affected:
        if not same_package(ecosystem, name, a.get("package") or {}):
            continue
        if version in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                verdicts.append(_verdict(version, ecosystem, r))
    if any(v is True for v in verdicts):
        return True
    if verdicts and all(v is False for v in verdicts):
        return False
    return None
