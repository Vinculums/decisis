from __future__ import annotations

import json

from .shape import Inventory, digest, from_purl, json_object, without_purl

FORMAT = "cyclonedx"
SIBLINGS: tuple[str, ...] = ()
VERSIONS = ("1.4", "1.5", "1.6")
ORPHAN = "listed in the SBOM with no dependency on it"
MAX_COMPONENT_DEPTH = 64


def detect(text: str, filename: str) -> bool:
    obj = json_object(text)
    return obj is not None and obj.get("bomFormat") == "CycloneDX"


def _dict_list(obj: dict, field: str, where: str) -> list[dict]:
    if field not in obj:
        return []
    items = obj[field]
    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        raise ValueError(f"CycloneDX {where} {field} must be a list of mappings")
    return items


def _opt_str(obj: dict, field: str, where: str) -> str:
    value = obj.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"CycloneDX {where} {field} must be a string")
    return value


def _components(parent: dict, where: str, depth: int = 0) -> list[dict]:
    if depth > MAX_COMPONENT_DEPTH:
        raise ValueError("CycloneDX components nesting too deep")
    out = []
    for c in _dict_list(parent, "components", where):
        out.append(c)
        out += _components(c, "component", depth + 1)
    return out


def _license(c: dict) -> str:
    parts = []
    for entry in _dict_list(c, "licenses", "component"):
        expr = _opt_str(entry, "expression", "license")
        if expr:
            parts.append(expr)
            continue
        lic = entry.get("license")
        if lic is not None and not isinstance(lic, dict):
            raise ValueError("CycloneDX license entry must be a mapping")
        lic_id = _opt_str(lic or {}, "id", "license")
        if lic_id:
            parts.append(lic_id)
    return parts[0] if len(parts) == 1 else " AND ".join(f"({p})" if " " in p else p for p in parts)


def _full_name(c: dict) -> str:
    group, name = _opt_str(c, "group", "component"), _opt_str(c, "name", "component")
    return f"{group}/{name}" if group else name


def _dev(c: dict) -> bool:
    flags = {}
    for p in _dict_list(c, "properties", "component"):
        name = _opt_str(p, "name", "property")
        if name:
            flags[name] = p.get("value")
    return c.get("scope") == "excluded" or str(flags.get("cdx:npm:package:development", "")).lower() == "true"


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    bom = json.loads(text)
    if not isinstance(bom, dict):
        raise ValueError("CycloneDX SBOM must be a JSON object")
    spec = bom.get("specVersion")
    if not isinstance(spec, str) or spec not in VERSIONS:
        raise ValueError(f"reads CycloneDX JSON {', '.join(VERSIONS)}; this file is CycloneDX {spec}")
    meta = bom.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        raise ValueError("CycloneDX metadata must be a mapping")
    comp = (meta or {}).get("component")
    if comp is not None and not isinstance(comp, dict):
        raise ValueError("CycloneDX metadata.component must be a mapping")
    root = _opt_str(comp or {}, "bom-ref", "metadata.component") or None
    inv = Inventory(repo, "cyclonedx-sbom", digest(bom))
    if root:
        inv.root(root)
    for c in _components(bom, "SBOM"):
        bom_ref = _opt_str(c, "bom-ref", "component")
        if root and bom_ref == root:
            _license(c)
            _dev(c)
            continue
        version = _opt_str(c, "version", "component")
        purl = _opt_str(c, "purl", "component")
        cpe = _opt_str(c, "cpe", "component")
        pkg = from_purl(purl, version) or without_purl(_full_name(c), version, cpe)
        key = bom_ref or purl or pkg["id"]
        inv.add(key, pkg, f"{repo}:{filename}#{key}", _license(c), _dev(c))
    for d in _dict_list(bom, "dependencies", "SBOM"):
        ref = _opt_str(d, "ref", "dependency") or None
        src = None if ref == root else ref
        if "dependsOn" in d:
            depends_on = d["dependsOn"]
            if not isinstance(depends_on, list) or not all(isinstance(dst, str) for dst in depends_on):
                raise ValueError("CycloneDX dependsOn must be a list of strings")
        else:
            depends_on = []
        for dst in depends_on:
            inv.depends(src, dst, f"{ref} depends on {dst}")
    inv.adopt_orphans(ORPHAN)
    return inv.result()
