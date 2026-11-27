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


def sibling_names(read, resolve=None, listing=None, filename: str = "") -> tuple[str, ...]:
    return manifest_names(read, resolve)


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


def _v1_name(spec: str) -> str:
    name, wanted = split_spec(spec)
    return split_spec(wanted[4:])[0] if wanted.startswith("npm:") else name


def _v1_str(entry: dict, field: str, spec: str) -> str:
    if field not in entry:
        return ""
    value = entry[field]
    if not isinstance(value, str):
        raise ValueError(f"yarn.lock entry {spec!r} {field} must be a string")
    return value


def _v1_deps(entry: dict, field: str, spec: str) -> dict[str, str]:
    if field not in entry:
        return {}
    value = entry[field]
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ValueError(f"yarn.lock entry {spec!r} {field} must be a mapping of strings")
    return value


def _read_v1(text: str, filename: str, repo: str, siblings: dict[str, str] | None):
    entries = parse_v1(text, filename)
    names = {spec: _v1_name(spec) for spec in entries}
    versions: dict[str, str] = {}
    inv = Inventory(repo, "yarn-lockfile", text_digest(text))
    for spec, entry in sorted(entries.items()):
        version = _v1_str(entry, "version", spec)
        versions[spec] = version
        wanted = split_spec(spec)[1]
        source = _v1_str(entry, "resolved", spec) if V1_FOREIGN.match(wanted) else ""
        inv.add((names[spec], version), npm_package(names[spec], version, source), f"{repo}:{filename}#{spec}")
    found = manifests(siblings)
    workspaces = _workspace_keys(inv, found, filename)

    def resolve(dep: str, spec: str):
        if dep in workspaces:
            return workspaces[dep]
        key = f"{dep}@{spec}"
        return None if key not in entries else (names[key], versions[key])

    _manifest_edges(inv, found, resolve)
    for spec, entry in sorted(entries.items()):
        name, version = names[spec], versions[spec]
        for field, note in (("dependencies", ""), ("optionalDependencies", " (optional)")):
            for dep, wanted in sorted(_v1_deps(entry, field, spec).items()):
                target = resolve(dep, wanted)
                if target is not None:
                    inv.depends((name, version), target, f"{name} {version} requires {dep} {wanted}{note}")
    inv.adopt_orphans(ORPHAN)
    return inv.result()


def _berry_dict(entry: dict, field: str, key: str) -> dict:
    if field not in entry:
        return {}
    value = entry[field]
    if not isinstance(value, dict):
        raise ValueError(f"yarn.lock entry {key!r} {field} must be a mapping")
    return value


def _berry_entries(doc: dict) -> tuple[dict[str, dict], dict[str, str]]:
    entries, descriptors = {}, {}
    for key, entry in doc.items():
        if key == "__metadata":
            if not isinstance(entry, dict):
                raise ValueError("yarn.lock __metadata must be a mapping")
            continue
        if not isinstance(entry, dict):
            raise ValueError(f"yarn.lock entry {key!r} must be a mapping")
        resolution = entry.get("resolution")
        if resolution is not None and not isinstance(resolution, str):
            raise ValueError(f"yarn.lock entry {key!r} resolution must be a string")
        if "version" in entry and not isinstance(entry["version"], str):
            raise ValueError(f"yarn.lock entry {key!r} version must be a string")
        for field in ("dependencies", "peerDependencies", "dependenciesMeta"):
            _berry_dict(entry, field, str(key))
        if not resolution:
            continue
        entries[resolution] = entry
        descriptors.update({d.strip(): resolution for d in str(key).split(",") if d.strip()})
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
        version = entry.get("version", "")
        keys[resolution] = (name, version)
        source = "" if protocol in REGISTRY_PROTOCOLS else resolution[len(name) + 1:]
        inv.add(keys[resolution], npm_package(name, version, source), f"{inv.repo}:{filename}#{resolution}")
    return keys


def _peer(dep: str, wanted: str, descriptors: dict, keys: dict):
    exact = descriptors.get(f"{dep}@npm:{wanted}") or descriptors.get(f"{dep}@{wanted}")
    if exact:
        return keys[exact]
    found = []
    for k in keys.values():
        if isinstance(k, tuple) and k[0] == dep:
            try:
                found.append((semver.parse(k[1]), k))
            except ValueError:
                continue
    return max(found, key=lambda item: item[0])[1] if found else None


def _dev_only(manifest: dict | None, dep: str) -> bool:
    if not manifest:
        return False
    return dep in mapping(manifest.get("devDependencies")) and not any(
        dep in mapping(manifest.get(f)) for f in ("dependencies", "optionalDependencies"))


def _berry_edges(inv: Inventory, entries: dict, descriptors: dict, keys: dict, found: dict) -> None:
    for resolution, entry in sorted(entries.items()):
        name, protocol, rest = _protocol(resolution)
        manifest = found.get(rest) if protocol == "workspace" else None
        meta = _berry_dict(entry, "dependenciesMeta", resolution)
        label = manifest_label(rest) if protocol == "workspace" else f"{name} {entry.get('version')}"
        for dep, wanted in sorted(_berry_dict(entry, "dependencies", resolution).items()):
            if not isinstance(dep, str) or not isinstance(wanted, str):
                raise ValueError(f"yarn.lock entry {resolution!r} dependencies must map strings to strings")
            target = descriptors.get(f"{dep}@{wanted}") or descriptors.get(f"{dep}@npm:{wanted}")
            dev = _dev_only(manifest, dep)
            dep_meta = meta.get(dep)
            if dep_meta is not None and not isinstance(dep_meta, dict):
                raise ValueError(f"yarn.lock entry {resolution!r} dependenciesMeta.{dep} must be a mapping")
            note = " (optional)" if (dep_meta or {}).get("optional") == "true" else " (dev)" if dev else ""
            if target is not None:
                inv.depends(keys[resolution], keys[target], f"{label} requires {dep} {wanted}{note}", dev)
        for dep, wanted in sorted(_berry_dict(entry, "peerDependencies", resolution).items()):
            if not isinstance(dep, str) or not isinstance(wanted, str):
                raise ValueError(f"yarn.lock entry {resolution!r} peerDependencies must map strings to strings")
            target = _peer(dep, wanted, descriptors, keys)
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
