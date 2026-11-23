from __future__ import annotations

import re

_V = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def parse(v: str) -> tuple:
    m = _V.match(v.strip())
    if not m:
        raise ValueError(f"not a semantic version: {v!r}")
    pre = m[4]
    pre_key = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return (int(m[1]), int(m[2] or 0), int(m[3] or 0), 0 if pre else 1, pre_key)


def in_range(version: str, events: list[dict]) -> bool | None:
    try:
        v = parse(version)
        affected = False
        for ev in events:
            if "introduced" in ev:
                if ev["introduced"] == "0" or v >= parse(ev["introduced"]):
                    affected = True
            elif "fixed" in ev:
                if affected and v >= parse(ev["fixed"]):
                    affected = False
            elif "last_affected" in ev:
                if affected and v > parse(ev["last_affected"]):
                    affected = False
        return affected
    except ValueError:
        return None


def affects(version: str, ecosystem: str, name: str, affected: list[dict]) -> bool | None:
    verdicts = []
    for a in affected:
        pkg = a.get("package") or {}
        if (pkg.get("ecosystem") or "").lower() != ecosystem.lower() or pkg.get("name") != name:
            continue
        if version in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                verdicts.append(in_range(version, r.get("events") or []))
    if any(v is True for v in verdicts):
        return True
    if verdicts and all(v is False for v in verdicts):
        return False
    return None
