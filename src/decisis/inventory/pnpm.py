from __future__ import annotations

import posixpath
import re

from .js import NAME, ORPHAN, manifest_label, mapping, npm_package, split_spec, yaml_tree
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


def _importer_ref(value) -> tuple[str, str]:
    if isinstance(value, dict):
        return str(value.get("specifier", value.get("version", ""))), str(value.get("version", ""))
    return str(value), str(value)


def _instances(doc: dict) -> dict[str, tuple[dict, dict]]:
    packages = mapping(doc.get("packages"))
    if isinstance(doc.get("snapshots"), dict):
        return {k: (mapping(v), mapping(packages.get(k.split("(", 1)[0]))) for k, v in doc["snapshots"].items()}
    return {k: (mapping(v), mapping(v)) for k, v in packages.items()}


def _check(doc: dict, filename: str) -> None:
    version = str(doc.get("lockfileVersion", ""))
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
        for field, note, dev in IMPORTER_FIELDS:
            for dep, value in sorted(mapping(mapping(imp).get(field)).items()):
                spec, ref = _importer_ref(value)
                inv.depends(f"workspace:{path}", _importer_target(path, dep, ref), f"{manifest_label(path)} requires {dep} {spec}{note}", dev)


def _package_edges(inv: Inventory, instances: dict) -> None:
    for key, (snap, meta) in sorted(instances.items()):
        name, version = _key(key)
        peers = mapping(meta.get("peerDependencies"))
        for field, note in SNAPSHOT_FIELDS:
            for dep, ref in sorted(mapping(snap.get(field)).items()):
                kind = " (peer)" if dep in peers else note
                inv.depends((name, version), _target(dep, str(ref)), f"{name} {version} requires {dep} {str(ref).split('(', 1)[0]}{kind}")


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = yaml_tree(text, filename)
    _check(doc, filename)
    inv = Inventory(repo, "pnpm-lockfile", text_digest(text))
    instances = _instances(doc)
    for key, (_, meta) in sorted(instances.items()):
        name, version = _key(key)
        res = mapping(meta.get("resolution"))
        pkg = npm_package(name, version, str(res.get("repo") or res.get("directory") or ""))
        inv.add((name, version), pkg, f"{repo}:{filename}#{name}@{version}", dev=DEV.get(str(meta.get("dev"))))
    importers = mapping(doc.get("importers")) or {".": doc}
    _importers(inv, importers, filename)
    _importer_edges(inv, importers)
    _package_edges(inv, instances)
    inv.adopt_orphans(ORPHAN)
    return inv.result()
