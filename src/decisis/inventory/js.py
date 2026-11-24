from __future__ import annotations

import json
import re
from pathlib import Path

from .. import yamltext
from .shape import make_purl, package_id
from .siblings import clean

FIELDS = (("dependencies", "", False), ("optionalDependencies", " (optional)", False),
          ("peerDependencies", " (peer)", False), ("devDependencies", " (dev)", True))
ORPHAN = "listed in the lockfile with no dependency on it"
NAME = re.compile(r"(@[^/@:]+/)?[^/@:]+")
REGISTRY_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?")


def yaml_tree(text: str, filename: str) -> dict:
    doc = yamltext.load(text, filename)
    if not isinstance(doc, dict):
        raise ValueError(f"{filename} is not a YAML mapping")
    return doc


def mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def manifest_label(path: str) -> str:
    return "package.json" if path == "." else f"{path}/package.json"


def split_spec(spec: str) -> tuple[str, str]:
    cut = spec.find("@", 1)
    return (spec, "") if cut < 0 else (spec[:cut], spec[cut + 1:])


def npm_package(name: str, version: str, source: str = "") -> dict:
    unresolved = ""
    if source:
        unresolved = f"the lockfile resolves it from {source}, not the npm registry"
    elif not REGISTRY_VERSION.fullmatch(version):
        unresolved = f"{version or 'an empty version'} is not an npm registry version"
    return {"id": package_id("npm", name, version), "ecosystem": "npm", "name": name, "version": version,
            "purl": make_purl("npm", name, version), "unresolved": unresolved}


def requirements(manifest: dict) -> list[tuple[str, str, str, bool]]:
    out = []
    for field, note, dev in FIELDS:
        out += [(name, str(spec), note, dev) for name, spec in sorted(mapping(manifest.get(field)).items())]
    return out


def workspace_globs(manifest) -> list[str]:
    found = mapping(manifest).get("workspaces")
    if isinstance(found, dict):
        found = found.get("packages")
    if not isinstance(found, list):
        return []
    return [w for w in found if isinstance(w, str) and w and not w.startswith(("!", "/")) and ".." not in w.split("/")]


def _json(text: str, name: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"{name} is not valid JSON ({e.msg} at line {e.lineno})") from None


def _read(read, name: str) -> str | None:
    try:
        text = read(name)
    except ValueError:
        return None
    return None if text is None else clean(text)


def _folder(resolve) -> Path | None:
    try:
        return Path(resolve(".")) if resolve is not None else None
    except ValueError:
        return None


def manifest_names(read, resolve=None) -> tuple[str, ...]:
    root = _read(read, "package.json")
    if root is None:
        return ()
    names, folder = ["package.json"], _folder(resolve)
    for pattern in workspace_globs(_json(root, "package.json")) if folder is not None else []:
        for path in sorted(folder.glob(f"{pattern.rstrip('/')}/package.json")):
            rel = path.relative_to(folder)
            if "node_modules" not in rel.parts and rel.as_posix() not in names:
                names.append(rel.as_posix())
    return tuple(names)


def manifests(siblings: dict[str, str] | None) -> dict[str, dict]:
    out = {}
    for name, text in sorted((siblings or {}).items()):
        if name == "package.json" or name.endswith("/package.json"):
            out[name.rpartition("/")[0] or "."] = mapping(_json(text, name))
    return out
