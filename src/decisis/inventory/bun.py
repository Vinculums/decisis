from __future__ import annotations

import json
import re
from pathlib import Path

from .js import ORPHAN, manifest_label, mapping, npm_package, requirements, split_spec
from .shape import Inventory, text_digest

FORMAT = "bun"
SIBLINGS: tuple[str, ...] = ()
BINARY = "bun-lockfile-format"
MAGIC = BINARY.encode()
TRAILING_COMMA = re.compile(r'("(?:[^"\\]|\\.)*")|,(\s*[}\]])')
PACKAGE_FIELDS = (("dependencies", ""), ("optionalDependencies", " (optional)"), ("peerDependencies", " (peer)"))


def detect(text: str, filename: str) -> bool:
    if filename in ("bun.lock", "bun.lockb") or BINARY in text[:200]:
        return True
    doc = _loads(text) if text.lstrip().startswith("{") else None
    return isinstance(doc, dict) and "lockfileVersion" in doc and isinstance(doc.get("workspaces"), dict)


def _loads(text: str):
    try:
        return json.loads(TRAILING_COMMA.sub(lambda m: m.group(1) or m.group(2), text))
    except json.JSONDecodeError:
        return None


def refusal(filename: str) -> str:
    return (f"{filename} is Bun's binary lockfile, which audit cannot read; run `bun install --save-text-lockfile` "
            "to write bun.lock next to it and audit that file")


def _head(path: Path) -> bytes:
    if not path.is_file():
        return b""
    with path.open("rb") as f:
        return f.read(len(MAGIC) + 32)


def binary(path: Path) -> bool:
    return path.name.endswith(".lockb") or MAGIC in _head(path)


def refuse_binary(path: Path) -> None:
    if binary(path):
        raise ValueError(refusal(path.name))


def _parse(text: str, filename: str) -> dict:
    if filename.endswith(".lockb") or BINARY in text[:200]:
        raise ValueError(refusal(filename))
    doc = _loads(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("packages"), dict):
        raise ValueError(f"{filename} is not a Bun text lockfile (JSON with workspaces and packages)")
    return doc


def _segments(key: str) -> list[str]:
    out, parts = [], key.split("/")
    while parts:
        part = parts.pop(0)
        out.append(f"{part}/{parts.pop(0)}" if part.startswith("@") and parts else part)
    return out


def _lookup(packages: dict, parent: list[str], dep: str) -> str | None:
    for cut in range(len(parent), -1, -1):
        key = "/".join(parent[:cut] + [dep])
        if key in packages:
            return key
    return None


def _ident(entry) -> tuple[str, str]:
    return split_spec(str(entry[0])) if isinstance(entry, list) and entry else ("", "")


def _meta(entry) -> dict:
    return next((x for x in entry[1:] if isinstance(x, dict)), {}) if isinstance(entry, list) else {}


def _nodes(inv: Inventory, packages: dict, filename: str) -> dict[str, object]:
    keys: dict[str, object] = {}
    for key, entry in sorted(packages.items()):
        name, ref = _ident(entry)
        if ref.startswith("workspace:"):
            keys[key] = f"workspace:{ref[len('workspace:'):]}"
            continue
        source = "" if not ref or ref[0].isdigit() else ref
        keys[key] = (name, ref)
        inv.add(keys[key], npm_package(name, ref, source), f"{inv.repo}:{filename}#{key}")
    return keys


def _workspaces(inv: Inventory, workspaces: dict, filename: str) -> None:
    for path, ws in sorted(workspaces.items()):
        if path == "":
            inv.root("workspace:.")
        else:
            inv.workspace(f"workspace:{path}", path, str(mapping(ws).get("name") or ""), f"{inv.repo}:{filename}#workspaces/{path}")


def _edges(inv: Inventory, packages: dict, workspaces: dict, keys: dict) -> None:
    for path, ws in sorted(workspaces.items()):
        path, ws = path or ".", mapping(ws)
        parent = [str(ws["name"])] if ws.get("name") and path != "." else []
        for dep, spec, note, dev in requirements(ws):
            target = _lookup(packages, parent, dep)
            if target is not None:
                inv.depends(f"workspace:{path}", keys[target], f"{manifest_label(path)} requires {dep} {spec}{note}", dev)
    for key, entry in sorted(packages.items()):
        if isinstance(keys[key], str):
            continue
        name, version = keys[key]
        for field, note in PACKAGE_FIELDS:
            for dep, spec in sorted(mapping(_meta(entry).get(field)).items()):
                target = _lookup(packages, _segments(key), dep)
                if target is not None:
                    inv.depends(keys[key], keys[target], f"{name} {version} requires {dep} {spec}{note}")


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    doc = _parse(text, filename)
    packages, workspaces = doc["packages"], mapping(doc.get("workspaces"))
    inv = Inventory(repo, "bun-lockfile", text_digest(text))
    keys = _nodes(inv, packages, filename)
    _workspaces(inv, workspaces, filename)
    _edges(inv, packages, workspaces, keys)
    inv.adopt_orphans(ORPHAN)
    return inv.result()
