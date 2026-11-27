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
    if "source" not in p:
        return False
    source = p["source"]
    if not isinstance(source, dict):
        raise ValueError("uv.lock package source must be a table")
    return any(k in source for k in LOCAL_SOURCES)


def _dep_list(items, label: str) -> list[dict]:
    if not isinstance(items, list):
        raise ValueError(f"uv.lock {label} must be a list of tables")
    for d in items:
        if not isinstance(d, dict):
            raise ValueError(f"uv.lock {label} entries must be tables")
        if "name" in d and not isinstance(d["name"], str):
            raise ValueError(f"uv.lock {label} entry name must be a string")
        if "version" in d and not isinstance(d["version"], str):
            raise ValueError(f"uv.lock {label} entry version must be a string")
    return items


def _pick(by_name: dict, dep: dict) -> tuple | None:
    name = dep.get("name")
    if not name:
        return None
    found = by_name.get(pypi_name(name)) or []
    if "version" in dep:
        found = [p for p in found if p.get("version") == dep["version"]]
    if "source" in dep:
        found = [p for p in found if p.get("source") == dep["source"]] or found
    return (found[0]["name"], found[0].get("version")) if found else None


def _requirements(p: dict) -> list[tuple[dict, bool, str]]:
    out = [(d, False, "") for d in _dep_list(p["dependencies"], "dependencies")] if "dependencies" in p else []
    if "optional-dependencies" in p:
        opt = p["optional-dependencies"]
        if not isinstance(opt, dict):
            raise ValueError("uv.lock optional-dependencies must be a table")
        for extra, deps in sorted(opt.items()):
            out += [(d, False, f" (extra {extra})") for d in _dep_list(deps, f"optional-dependencies.{extra}")]
    if "dev-dependencies" in p:
        dev = p["dev-dependencies"]
        if not isinstance(dev, dict):
            raise ValueError("uv.lock dev-dependencies must be a table")
        for group, deps in sorted(dev.items()):
            out += [(d, True, f" (group {group})") for d in _dep_list(deps, f"dev-dependencies.{group}")]
    return out


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = tomllib.loads(text)
    if "package" in doc:
        raw_packages = doc["package"]
        if not isinstance(raw_packages, list):
            raise ValueError("uv.lock package must be a list of tables")
    else:
        raw_packages = []
    for p in raw_packages:
        if not isinstance(p, dict):
            raise ValueError("uv.lock package entries must be tables")
        if "name" in p and not isinstance(p["name"], str):
            raise ValueError("uv.lock package name must be a string")
        if "version" in p and not isinstance(p["version"], str):
            raise ValueError("uv.lock package version must be a string")
        _local(p)
        _requirements(p)
    packages = [p for p in raw_packages if p.get("name")]
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
