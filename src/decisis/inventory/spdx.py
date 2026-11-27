from __future__ import annotations

import json

from .shape import UNKNOWN_LICENSES, Inventory, digest, from_purl, json_object, without_purl

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


def _dict_list(obj: dict, field: str, where: str) -> list[dict]:
    if field not in obj:
        return []
    items = obj[field]
    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        raise ValueError(f"SPDX {where} {field} must be a list of mappings")
    return items


def _opt_str(obj: dict, field: str, where: str) -> str:
    value = obj.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"SPDX {where} {field} must be a string")
    return value


def _refs(p: dict) -> list[dict]:
    refs = _dict_list(p, "externalRefs", "package")
    for r in refs:
        _opt_str(r, "referenceType", "externalRef")
        _opt_str(r, "referenceLocator", "externalRef")
    return refs


def _ref(refs: list[dict], *kinds: str) -> str | None:
    return next((r.get("referenceLocator") for r in refs if r.get("referenceType") in kinds), None)


def _package(p: dict, refs: list[dict]) -> dict:
    version = _opt_str(p, "versionInfo", "package")
    name = _opt_str(p, "name", "package") or _opt_str(p, "SPDXID", "package")
    return from_purl(_ref(refs, "purl"), version) or without_purl(name, version, _ref(refs, "cpe23Type", "cpe22Type") or "")


def _license(p: dict) -> str:
    for field in ("licenseConcluded", "licenseDeclared"):
        value = p.get(field)
        if isinstance(value, str) and value not in UNKNOWN_LICENSES:
            return value
    return ""


def _roots(doc: dict, rels: list[dict]) -> set[str]:
    if "documentDescribes" in doc:
        describes = doc["documentDescribes"]
        if not isinstance(describes, list) or not all(isinstance(x, str) for x in describes):
            raise ValueError("SPDX documentDescribes must be a list of strings")
        roots = set(describes)
    else:
        roots = set()
    doc_id = _opt_str(doc, "SPDXID", "document") or None
    for r in rels:
        kind = _opt_str(r, "relationshipType", "relationship")
        a = _opt_str(r, "spdxElementId", "relationship")
        b = _opt_str(r, "relatedSpdxElement", "relationship")
        if kind == "DESCRIBES" and a == doc_id and b:
            roots.add(b)
        if kind == "DESCRIBED_BY" and b == doc_id and a:
            roots.add(a)
    return roots


def _link(inv: Inventory, roots: set[str], r: dict) -> None:
    kind = _opt_str(r, "relationshipType", "relationship")
    a = _opt_str(r, "spdxElementId", "relationship") or None
    b = _opt_str(r, "relatedSpdxElement", "relationship") or None
    if kind in FORWARD:
        src, dst, dev = a, b, FORWARD[kind]
    elif kind in BACKWARD:
        src, dst, dev = b, a, BACKWARD[kind]
    else:
        return
    inv.depends(None if src in roots else src, dst, f"{a} {kind} {b}", dev)


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("SPDX SBOM must be a JSON object")
    version = doc.get("spdxVersion")
    if not isinstance(version, str) or version not in VERSIONS:
        raise ValueError(f"reads SPDX JSON 2.3; this file is {version}")
    rels = _dict_list(doc, "relationships", "document")
    pkgs = _dict_list(doc, "packages", "document")
    inv = Inventory(repo, "spdx-sbom", digest(doc))
    roots = _roots(doc, rels)
    for key in roots:
        inv.root(key)
    for p in pkgs:
        spdx_id = p.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id:
            raise ValueError("SPDX package must have a non-empty string SPDXID")
        refs = _refs(p)
        if spdx_id not in roots:
            inv.add(spdx_id, _package(p, refs), f"{repo}:{filename}#{spdx_id}", _license(p))
    for r in rels:
        _link(inv, roots, r)
    inv.adopt_orphans(ORPHAN)
    return inv.result()
