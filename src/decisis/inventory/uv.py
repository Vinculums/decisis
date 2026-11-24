from __future__ import annotations

import tomllib

from .shape import Inventory, make_purl, package_id, pypi_name, text_digest

FORMAT = "uv"
SIBLINGS: tuple[str, ...] = ()
LOCAL_SOURCES = ("editable", "virtual", "directory", "path")


def detect(text: str, filename: str) -> bool:
    if filename == "uv.lock":
        return True
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    return "requires-python" in doc and isinstance(doc.get("package"), list)


def _local(p: dict) -> bool:
    return any(k in (p.get("source") or {}) for k in LOCAL_SOURCES)


def _pick(by_name: dict, dep: dict) -> tuple | None:
    found = by_name.get(pypi_name(dep.get("name", ""))) or []
    if "version" in dep:
        found = [p for p in found if p.get("version") == dep["version"]]
    if "source" in dep:
        found = [p for p in found if p.get("source") == dep["source"]] or found
    return (found[0]["name"], found[0].get("version")) if found else None


def _requirements(p: dict) -> list[tuple[dict, bool, str]]:
    out = [(d, False, "") for d in p.get("dependencies") or []]
    for extra, deps in sorted((p.get("optional-dependencies") or {}).items()):
        out += [(d, False, f" (extra {extra})") for d in deps]
    for group, deps in sorted((p.get("dev-dependencies") or {}).items()):
        out += [(d, True, f" (group {group})") for d in deps]
    return out


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = tomllib.loads(text)
    packages = [p for p in doc.get("package") or [] if isinstance(p, dict) and p.get("name")]
    inv = Inventory(repo, "uv-lockfile", text_digest(text))
    by_name: dict[str, list[dict]] = {}
    for p in packages:
        key = (p["name"], p.get("version"))
        by_name.setdefault(pypi_name(p["name"]), []).append(p)
        if _local(p):
            inv.root(key)
            continue
        name, version = pypi_name(p["name"]), p.get("version") or ""
        pkg = {"id": package_id("PyPI", name, version), "ecosystem": "PyPI", "name": name, "version": version,
               "purl": make_purl("pypi", name, version), "unresolved": "" if version else "the lockfile gives no version"}
        inv.add(key, pkg, f"{repo}:{filename}#{name}@{version}")
    for p in packages:
        key = (p["name"], p.get("version"))
        for dep, dev, note in _requirements(p):
            target = _pick(by_name, dep)
            if target is not None:
                marker = f"; {dep['marker']}" if dep.get("marker") else ""
                inv.depends(None if _local(p) else key, target, f"{p['name']} requires {dep['name']}{note}{marker}", dev)
    return inv.result()
