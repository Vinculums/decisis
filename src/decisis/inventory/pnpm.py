from __future__ import annotations

import posixpath
import re

from .js import NAME, ORPHAN, manifest_label, npm_package, split_spec, yaml_tree
from .shape import Inventory, text_digest

FORMAT = "pnpm"
SIBLINGS: tuple[str, ...] = ()
VERSIONS = ("6", "9")
IMPORTER_FIELDS = (("dependencies", "", False), ("optionalDependencies", " (optional)", False), ("devDependencies", " (dev)", True))
SNAPSHOT_FIELDS = (("dependencies", ""), ("optionalDependencies", " (optional)"))
DEV = {"true": True, "false": False}


def detect(text: str, filename: str) -> bool:
    return filename == "pnpm-lock.yaml" or re.match(r"""lockfileVersion: ['"]?\d""", text) is not None


def _key(ref: str) -> tuple[str, str]:
    return split_spec(ref.lstrip("/").split("(", 1)[0])


def _target(name: str, ref: str) -> tuple[str, str]:
    base = ref.split("(", 1)[0]
    alias = split_spec(base.lstrip("/"))[0]
    if base.startswith("/") or (alias != base and NAME.fullmatch(alias)):
        return _key(base)
    return name, base


def _importer_target(path: str, name: str, ref: str):
    if ref.startswith("link:"):
        return f"workspace:{posixpath.normpath(posixpath.join(path, ref[5:]))}"
    return _target(name, ref)


def _dict_field(obj: dict, field: str, where: str) -> dict:
    if field not in obj:
        return {}
    value = obj[field]
    if not isinstance(value, dict):
        raise ValueError(f"pnpm lockfile {where} {field} must be a mapping")
    return value


def _importer_ref(value) -> tuple[str, str]:
    if isinstance(value, dict):
        spec = value.get("specifier", value.get("version", ""))
        ver = value.get("version", "")
        if not isinstance(spec, str) or not isinstance(ver, str):
            raise ValueError("pnpm lockfile importer dependency version must be a string")
        return spec, ver
    if not isinstance(value, str):
        raise ValueError("pnpm lockfile importer dependency must be a string or mapping")
    return value, value


def _instances(doc: dict) -> dict[str, tuple[dict, dict]]:
    packages = _dict_field(doc, "packages", "top-level")
    for k, v in packages.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            raise ValueError("pnpm lockfile packages entries must be mappings")
    if "snapshots" in doc:
        snapshots = _dict_field(doc, "snapshots", "top-level")
        out = {}
        for k, v in snapshots.items():
            if not isinstance(k, str) or not isinstance(v, dict):
                raise ValueError("pnpm lockfile snapshots entries must be mappings")
            out[k] = (v, packages.get(k.split("(", 1)[0], {}))
        return out
    return {k: (v, v) for k, v in packages.items()}


def _check(doc: dict, filename: str) -> None:
    raw = doc.get("lockfileVersion")
    version = raw if isinstance(raw, str) else ""
    if version.split(".")[0] not in VERSIONS:
        raise ValueError(f"{filename} has lockfileVersion {version or 'none'}; audit reads pnpm lockfile versions 6 and 9")


def _importers(inv: Inventory, importers: dict, filename: str) -> None:
    for path in sorted(importers):
        if path == ".":
            inv.root("workspace:.")
        else:
            inv.workspace(f"workspace:{path}", path, "", f"{inv.repo}:{filename}#importers/{path}")


def _importer_edges(inv: Inventory, importers: dict) -> None:
    for path, imp in sorted(importers.items()):
        if not isinstance(imp, dict):
            raise ValueError(f"pnpm lockfile importer {path!r} must be a mapping")
        for field, note, dev in IMPORTER_FIELDS:
            for dep, value in sorted(_dict_field(imp, field, f"importer {path!r}").items()):
                if not isinstance(dep, str):
                    raise ValueError(f"pnpm lockfile importer {path!r} {field} key must be a string")
                spec, ref = _importer_ref(value)
                inv.depends(f"workspace:{path}", _importer_target(path, dep, ref), f"{manifest_label(path)} requires {dep} {spec}{note}", dev)


def _package_edges(inv: Inventory, instances: dict) -> None:
    for key, (snap, meta) in sorted(instances.items()):
        name, version = _key(key)
        peers = _dict_field(meta, "peerDependencies", f"package {key!r}")
        for field, note in SNAPSHOT_FIELDS:
            for dep, ref in sorted(_dict_field(snap, field, f"snapshot {key!r}").items()):
                if not isinstance(dep, str) or not isinstance(ref, str):
                    raise ValueError(f"pnpm lockfile snapshot {key!r} {field} entries must be strings")
                kind = " (peer)" if dep in peers else note
                inv.depends((name, version), _target(dep, ref), f"{name} {version} requires {dep} {ref.split('(', 1)[0]}{kind}")


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = yaml_tree(text, filename)
    _check(doc, filename)
    inv = Inventory(repo, "pnpm-lockfile", text_digest(text))
    instances = _instances(doc)
    for key, (_, meta) in sorted(instances.items()):
        name, version = _key(key)
        res = _dict_field(meta, "resolution", f"package {key!r}")
        pkg = npm_package(name, version, str(res.get("repo") or res.get("directory") or ""))
        inv.add((name, version), pkg, f"{repo}:{filename}#{name}@{version}", dev=DEV.get(str(meta.get("dev"))))
    importers = _dict_field(doc, "importers", "top-level") if "importers" in doc else {".": doc}
    if any(not isinstance(path, str) for path in importers):
        raise ValueError("pnpm lockfile importers keys must be strings")
    _importers(inv, importers, filename)
    _importer_edges(inv, importers)
    _package_edges(inv, instances)
    inv.adopt_orphans(ORPHAN)
    return inv.result()
