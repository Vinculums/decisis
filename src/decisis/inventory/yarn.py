from __future__ import annotations

import re
import shlex
from pathlib import Path

from .. import semver
from .js import ORPHAN, manifest_label, manifest_names, manifests, mapping, npm_package, requirements, split_spec, yaml_tree
from .shape import Inventory, text_digest

FORMAT = "yarn"
SIBLINGS: tuple[str, ...] = ("package.json",)
V1 = "# yarn lockfile v1"
REGISTRY_PROTOCOLS = ("npm", "patch")
V1_FOREIGN = re.compile(r"(file|link|portal|git\+|git:|github:|gitlab:|bitbucket:|https?:)")


def detect(text: str, filename: str) -> bool:
    return filename == "yarn.lock" or V1 in text[:300] or re.search(r"^__metadata:\s*$", text, re.M) is not None


def sibling_names(folder: Path) -> tuple[str, ...]:
    return manifest_names(folder)


def _pair(body: str, n: int, filename: str) -> tuple[str, str]:
    try:
        parts = shlex.split(body)
    except ValueError:
        parts = []
    if len(parts) != 2:
        raise ValueError(f"{filename} line {n}: expected a key and a value, got {body!r}")
    return parts[0], parts[1]


def _header(body: str, n: int, filename: str) -> list[str]:
    if not body.endswith(":"):
        raise ValueError(f"{filename} line {n}: expected an entry that ends with ':', got {body!r}")
    return [s.strip().strip('"') for s in body[:-1].split(",") if s.strip()]


def parse_v1(text: str, filename: str) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    entry, section = None, None
    for n, line in enumerate(text.splitlines(), 1):
        body = line.strip()
        if not body or body.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            entry, section = {}, None
            entries.update({spec: entry for spec in _header(body, n, filename)})
        elif indent == 2 and entry is not None and body.endswith(":"):
            section = entry.setdefault(body[:-1].strip('"'), {})
        elif indent == 2 and entry is not None:
            key, value = _pair(body, n, filename)
            entry[key], section = value, None
        elif indent == 4 and section is not None:
            key, value = _pair(body, n, filename)
            section[key] = value
        else:
            raise ValueError(f"{filename} line {n}: unexpected indentation")
    return entries


def _workspace_keys(inv: Inventory, found: dict[str, dict], filename: str) -> dict[str, str]:
    names = {}
    for path, manifest in sorted(found.items()):
        key = f"workspace:{path}"
        if path == ".":
            inv.root(key)
        else:
            inv.workspace(key, path, str(manifest.get("name") or ""), f"{inv.repo}:{manifest_label(path)}")
        if manifest.get("name"):
            names[str(manifest["name"])] = key
    return names


def _manifest_edges(inv: Inventory, found: dict[str, dict], resolve) -> None:
    for path, manifest in sorted(found.items()):
        for dep, spec, note, dev in requirements(manifest):
            target = resolve(dep, spec)
            if target is not None:
                inv.depends(f"workspace:{path}", target, f"{manifest_label(path)} requires {dep} {spec}{note}", dev)


def _read_v1(text: str, filename: str, repo: str, siblings: dict[str, str] | None):
    entries = parse_v1(text, filename)
    inv = Inventory(repo, "yarn-lockfile", text_digest(text))
    for spec, entry in sorted(entries.items()):
        name, wanted = split_spec(spec)
        source = str(entry.get("resolved", "")) if V1_FOREIGN.match(wanted) else ""
        inv.add((name, entry.get("version", "")), npm_package(name, str(entry.get("version", "")), source),
                f"{repo}:{filename}#{spec}")
    found = manifests(siblings)
    workspaces = _workspace_keys(inv, found, filename)

    def resolve(dep: str, spec: str):
        if dep in workspaces:
            return workspaces[dep]
        entry = entries.get(f"{dep}@{spec}")
        return None if entry is None else (dep, entry.get("version", ""))

    _manifest_edges(inv, found, resolve)
    for spec, entry in sorted(entries.items()):
        name = split_spec(spec)[0]
        for field, note in (("dependencies", ""), ("optionalDependencies", " (optional)")):
            for dep, wanted in sorted(mapping(entry.get(field)).items()):
                target = resolve(dep, wanted)
                if target is not None:
                    inv.depends((name, entry.get("version", "")), target, f"{name} {entry.get('version')} requires {dep} {wanted}{note}")
    inv.adopt_orphans(ORPHAN)
    return inv.result()


def _berry_entries(doc: dict) -> tuple[dict[str, dict], dict[str, str]]:
    entries, descriptors = {}, {}
    for key, entry in doc.items():
        if key == "__metadata" or not isinstance(entry, dict) or not entry.get("resolution"):
            continue
        entries[str(entry["resolution"])] = entry
        descriptors.update({d.strip(): str(entry["resolution"]) for d in str(key).split(",") if d.strip()})
    return entries, descriptors


def _protocol(resolution: str) -> tuple[str, str, str]:
    name, ref = split_spec(resolution)
    protocol, _, rest = ref.partition(":")
    return name, protocol, rest


def _berry_nodes(inv: Inventory, entries: dict, filename: str) -> dict[str, object]:
    keys: dict[str, object] = {}
    for resolution, entry in sorted(entries.items()):
        name, protocol, rest = _protocol(resolution)
        if protocol == "workspace":
            keys[resolution] = f"workspace:{rest}"
            if rest == ".":
                inv.root(keys[resolution])
            else:
                inv.workspace(keys[resolution], rest, name, f"{inv.repo}:{filename}#{resolution}")
            continue
        version = str(entry.get("version", ""))
        keys[resolution] = (name, version)
        source = "" if protocol in REGISTRY_PROTOCOLS else resolution[len(name) + 1:]
        inv.add(keys[resolution], npm_package(name, version, source), f"{inv.repo}:{filename}#{resolution}")
    return keys


def _peer(dep: str, wanted: str, descriptors: dict, keys: dict):
    exact = descriptors.get(f"{dep}@npm:{wanted}") or descriptors.get(f"{dep}@{wanted}")
    if exact:
        return keys[exact]
    found = [k for k in keys.values() if isinstance(k, tuple) and k[0] == dep]
    return max(found, key=lambda k: semver.parse(k[1])) if found else None


def _dev_only(manifest: dict | None, dep: str) -> bool:
    if not manifest:
        return False
    return dep in mapping(manifest.get("devDependencies")) and not any(
        dep in mapping(manifest.get(f)) for f in ("dependencies", "optionalDependencies"))


def _berry_edges(inv: Inventory, entries: dict, descriptors: dict, keys: dict, found: dict) -> None:
    for resolution, entry in sorted(entries.items()):
        name, protocol, rest = _protocol(resolution)
        manifest = found.get(rest) if protocol == "workspace" else None
        meta = mapping(entry.get("dependenciesMeta"))
        label = manifest_label(rest) if protocol == "workspace" else f"{name} {entry.get('version')}"
        for dep, wanted in sorted(mapping(entry.get("dependencies")).items()):
            target = descriptors.get(f"{dep}@{wanted}") or descriptors.get(f"{dep}@npm:{wanted}")
            dev = _dev_only(manifest, dep)
            note = " (optional)" if mapping(meta.get(dep)).get("optional") == "true" else " (dev)" if dev else ""
            if target is not None:
                inv.depends(keys[resolution], keys[target], f"{label} requires {dep} {wanted}{note}", dev)
        for dep, wanted in sorted(mapping(entry.get("peerDependencies")).items()):
            target = _peer(dep, str(wanted), descriptors, keys)
            if target is not None:
                inv.depends(keys[resolution], target, f"{label} requires {dep} {wanted} (peer)")


def _read_berry(text: str, filename: str, repo: str, siblings: dict[str, str] | None):
    doc = yaml_tree(text, filename)
    entries, descriptors = _berry_entries(doc)
    inv = Inventory(repo, "yarn-berry-lockfile", text_digest(text))
    found = manifests(siblings)
    keys = _berry_nodes(inv, entries, filename)
    _berry_edges(inv, entries, descriptors, keys, found)
    inv.adopt_orphans(ORPHAN)
    return inv.result()


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    if re.search(r"^__metadata:\s*$", text, re.M):
        return _read_berry(text, filename, repo, siblings)
    return _read_v1(text, filename, repo, siblings)
