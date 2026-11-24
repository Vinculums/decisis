from __future__ import annotations

import json

from .shape import UNKNOWN_LICENSES, Inventory, digest, from_purl, json_object

FORMAT = "spdx"
SIBLINGS: tuple[str, ...] = ()
VERSIONS = ("SPDX-2.3",)
ORPHAN = "listed in the SBOM with no dependency on it"
FORWARD = {"DEPENDS_ON": False, "CONTAINS": False}
BACKWARD = {"DEPENDENCY_OF": False, "RUNTIME_DEPENDENCY_OF": False, "OPTIONAL_DEPENDENCY_OF": False, "PROVIDED_DEPENDENCY_OF": False,
            "CONTAINED_BY": False, "DEV_DEPENDENCY_OF": True, "TEST_DEPENDENCY_OF": True, "BUILD_DEPENDENCY_OF": True, "DEV_TOOL_OF": True}


def detect(text: str, filename: str) -> bool:
    obj = json_object(text)
    return obj is not None and str(obj.get("spdxVersion", "")).startswith("SPDX-")


def _purl(p: dict) -> str | None:
    return next((r.get("referenceLocator") for r in p.get("externalRefs") or [] if r.get("referenceType") == "purl"), None)


def _license(p: dict) -> str:
    for field in ("licenseConcluded", "licenseDeclared"):
        value = p.get(field)
        if isinstance(value, str) and value not in UNKNOWN_LICENSES:
            return value
    return ""


def _roots(doc: dict) -> set[str]:
    roots = set(doc.get("documentDescribes") or [])
    for r in doc.get("relationships") or []:
        if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == doc.get("SPDXID"):
            roots.add(r.get("relatedSpdxElement"))
        if r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == doc.get("SPDXID"):
            roots.add(r.get("spdxElementId"))
    return roots


def _link(inv: Inventory, roots: set[str], r: dict) -> None:
    kind, a, b = r.get("relationshipType"), r.get("spdxElementId"), r.get("relatedSpdxElement")
    if kind in FORWARD:
        src, dst, dev = a, b, FORWARD[kind]
    elif kind in BACKWARD:
        src, dst, dev = b, a, BACKWARD[kind]
    else:
        return
    inv.depends(None if src in roots else src, dst, f"{a} {kind} {b}", dev)


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = json.loads(text)
    if doc.get("spdxVersion") not in VERSIONS:
        raise ValueError(f"reads SPDX JSON 2.3; this file is {doc.get('spdxVersion')}")
    inv = Inventory(repo, "spdx-sbom", digest(doc))
    roots = _roots(doc)
    for key in roots:
        inv.root(key)
    for p in doc.get("packages") or []:
        pkg = None if p.get("SPDXID") in roots else from_purl(_purl(p), p.get("versionInfo") or "")
        if pkg is not None:
            inv.add(p["SPDXID"], pkg, f"{repo}:{filename}#{p['SPDXID']}", _license(p))
    for r in doc.get("relationships") or []:
        _link(inv, roots, r)
    inv.adopt_orphans(ORPHAN)
    return inv.result()
