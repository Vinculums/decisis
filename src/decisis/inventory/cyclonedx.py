from __future__ import annotations

import json

from .shape import Inventory, digest, from_purl, json_object, without_purl

FORMAT = "cyclonedx"
SIBLINGS: tuple[str, ...] = ()
VERSIONS = ("1.4", "1.5", "1.6")
ORPHAN = "listed in the SBOM with no dependency on it"


def detect(text: str, filename: str) -> bool:
    obj = json_object(text)
    return obj is not None and obj.get("bomFormat") == "CycloneDX"


def _components(items: list) -> list[dict]:
    out = []
    for c in items or []:
        if isinstance(c, dict):
            out.append(c)
            out += _components(c.get("components"))
    return out


def _license(c: dict) -> str:
    parts = []
    for entry in c.get("licenses") or []:
        if entry.get("expression"):
            parts.append(entry["expression"])
        elif (entry.get("license") or {}).get("id"):
            parts.append(entry["license"]["id"])
    return parts[0] if len(parts) == 1 else " AND ".join(f"({p})" if " " in p else p for p in parts)


def _full_name(c: dict) -> str:
    return f"{c['group']}/{c.get('name', '')}" if c.get("group") else c.get("name", "")


def _dev(c: dict) -> bool:
    flags = {p.get("name"): p.get("value") for p in c.get("properties") or [] if isinstance(p, dict)}
    return c.get("scope") == "excluded" or str(flags.get("cdx:npm:package:development", "")).lower() == "true"


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    bom = json.loads(text)
    if bom.get("specVersion") not in VERSIONS:
        raise ValueError(f"reads CycloneDX JSON {', '.join(VERSIONS)}; this file is CycloneDX {bom.get('specVersion')}")
    inv = Inventory(repo, "cyclonedx-sbom", digest(bom))
    root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if root:
        inv.root(root)
    for c in _components(bom.get("components")):
        if root and c.get("bom-ref") == root:
            continue
        pkg = from_purl(c.get("purl"), c.get("version") or "") or without_purl(_full_name(c), c.get("version") or "", c.get("cpe") or "")
        key = c.get("bom-ref") or c.get("purl") or pkg["id"]
        inv.add(key, pkg, f"{repo}:{filename}#{key}", _license(c), _dev(c))
    for d in bom.get("dependencies") or []:
        src = None if d.get("ref") == root else d.get("ref")
        for dst in d.get("dependsOn") or []:
            inv.depends(src, dst, f"{d.get('ref')} depends on {dst}")
    inv.adopt_orphans(ORPHAN)
    return inv.result()
