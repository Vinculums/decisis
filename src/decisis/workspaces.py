"""Workspace packages: the packages of an npm, pnpm, Yarn or Bun workspace, found by name for `imports.py`.

A directory declares a workspace with `workspaces` in its `package.json` (a list, or an object with a
`packages` list) or with a `packages` list in a `pnpm-workspace.yaml` beside it. Each directory below it that
has a `package.json` with a `name`, and that a pattern of the list covers and no `!` pattern removes, is a
workspace package. A declaration that cannot be read, or that uses a pattern syntax this reader does not know,
widens to every named package below that directory, so a package is never lost to a pattern.

A bare specifier is the name of a workspace package, or that name and a subpath (`@shop/db`, `@shop/db/client`).
A dependency `"x": "workspace:*"` of the nearest `package.json` above the importing file that has it (or
`workspace:<name>@<range>`, or `workspace:../path`) links the name `x` to that package; a link to a package no
workspace has is `unresolved`, never external. Where several workspace packages have one name, each is followed.

The files a specifier names in the package are those its `exports` map gives for the subpath (every condition and
every array member, `*` patterns and trailing `/` folders included), or, with no `exports`, `main`, `module`,
`types`, `typings`, `browser` and `source` for the package itself, or the file below the package directory for a
subpath, read like a relative import. A subpath the `exports` do not list is `unresolved`. When none of the files
exists (a build output that is not in the checkout), the target is the package directory, given with a trailing
`/`, and the declared paths, with the `src/` files they would be built from, are the other files it names.
"""
from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field

from . import yamltext
from .imports import MAX_WALK, REPOSITORY, SKIPPED_DIRS, UNRESOLVED, clean, joined, read_json, read_small, script_file

PACKAGE_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
ENTRY_FIELDS = ("main", "module", "types", "typings", "browser", "source")
LINK = "workspace:"
NODE_CORE = frozenset("assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events fs http http2 https "
                      "inspector module net os path perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls trace_events "
                      "tty url util v8 vm wasi worker_threads zlib".split())
MAX_PATTERN = 200
MAX_DEPTH = 32
GLOB_SYNTAX = re.compile(r"[{}\[\]()+@]")


@dataclass(frozen=True)
class Package:
    name: str
    dir: str
    manifest: dict = field(compare=False, hash=False)


@dataclass
class Index:
    manifests: dict[str, dict] = field(default_factory=dict)
    by_name: dict[str, list[Package]] = field(default_factory=dict)
    by_dir: dict[str, Package] = field(default_factory=dict)
    roots: dict[str, set[str]] = field(default_factory=dict)
    truncated: bool = False


def mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def segment_regex(part: str) -> str:
    return "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in part)


def glob_regex(pattern: str) -> re.Pattern | None:
    parts = [p for p in pattern.strip("/").split("/") if p not in ("", ".")]
    parts = [p for i, p in enumerate(parts) if not (p == "**" and i and parts[i - 1] == "**")]
    if not parts or len(pattern) > MAX_PATTERN or any(p == ".." for p in parts) or GLOB_SYNTAX.search(pattern):
        return None
    out = ""
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part == "**":
            out += ".*" if last else "(?:.*/)?"
        else:
            out += segment_regex(part) + ("" if last else "/")
    return re.compile(out)


def patterns_of(value) -> list[str] | None:
    if isinstance(value, dict):
        value = value.get("packages")
    if not isinstance(value, list) or not all(isinstance(p, str) and p for p in value):
        return None
    return value


def declared(manifest: dict | None, yaml_text: str | None) -> list[str] | None | bool:
    if yaml_text is not None:
        try:
            return patterns_of(yamltext.load(yaml_text, "pnpm-workspace.yaml"))
        except ValueError:
            return None
    if manifest is not None and "workspaces" in manifest:
        return patterns_of(manifest["workspaces"])
    return False


def members(named: dict[str, Package], here: str, patterns: list[str] | None) -> list[Package]:
    below = [(d, p) for d, p in named.items() if d != here and (not here or d.startswith(here + "/"))]
    if patterns is None:
        return [p for _, p in below]
    positive, negative = [], []
    for pattern in patterns:
        negated = pattern.startswith("!")
        regex = glob_regex(pattern[1:] if negated else pattern)
        if regex is None:
            return [p for _, p in below]
        (negative if negated else positive).append(regex)
    out = []
    for d, p in below:
        local = d[len(here) + 1:] if here else d
        if any(r.fullmatch(local) for r in positive) and not any(r.fullmatch(local) for r in negative):
            out.append(p)
    return out


def build(repo) -> Index:
    index, yamls, seen = Index(), {}, 0
    for dirpath, dirnames, filenames in os.walk(repo.root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIPPED_DIRS)
        rel = os.path.relpath(dirpath, repo.root).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        if "package.json" in filenames and repo.is_file(joined(rel, "package.json")):
            data = read_json(repo, joined(rel, "package.json"))
            if isinstance(data, dict):
                index.manifests[rel] = data
        if "pnpm-workspace.yaml" in filenames and repo.is_file(joined(rel, "pnpm-workspace.yaml")):
            yamls[rel] = read_small(repo, joined(rel, "pnpm-workspace.yaml")) or ""
        seen += len(filenames)
        if seen > MAX_WALK:
            index.truncated = True
            break
    named = {d: Package(m["name"], d, m) for d, m in index.manifests.items() if isinstance(m.get("name"), str) and m["name"]}
    for here in sorted(set(index.manifests) | set(yamls)):
        found = declared(index.manifests.get(here), yamls.get(here))
        if found is not False:
            for pkg in members(named, here, found):
                index.by_dir[pkg.dir] = pkg
                index.roots.setdefault(pkg.dir, set()).add(here)
    for pkg in index.by_dir.values():
        index.by_name.setdefault(pkg.name, []).append(pkg)
    for packages in index.by_name.values():
        packages.sort(key=lambda p: p.dir)
    return index


def index_of(repo) -> Index:
    if repo.workspaces is None:
        repo.workspaces = build(repo)
    return repo.workspaces


def split_specifier(spec: str) -> tuple[str, str] | None:
    if spec.startswith("node:"):
        return None
    parts = spec.split("/")
    count = 2 if spec.startswith("@") else 1
    if len(parts) < count or not all(parts[:count]):
        return None
    rest = parts[count:]
    return "/".join(parts[:count]), "./" + "/".join(rest) if rest else "."


def ancestors(rel: str):
    here = posixpath.dirname(rel)
    while True:
        yield here
        if not here:
            return
        here = posixpath.dirname(here)


def within(root: str, rel: str) -> bool:
    return not root or rel.startswith(root + "/")


def nearest(index: Index, packages: list[Package], rel: str) -> list[Package]:
    near = [p for p in packages if any(within(root, rel) for root in index.roots.get(p.dir, ()))]
    return near or packages


def link_of(index: Index, rel: str, name: str) -> tuple[str, str] | None:
    for here in ancestors(rel):
        manifest = index.manifests.get(here)
        for key in PACKAGE_FIELDS:
            value = mapping(manifest).get(key)
            spec = mapping(value).get(name)
            if isinstance(spec, str) and spec.startswith(LINK):
                return here, spec
    return None


def linked(index: Index, here: str, name: str, spec: str) -> tuple[list[Package], str]:
    rest = spec[len(LINK):]
    if rest in (".", "..") or rest.startswith(("./", "../")):
        base = clean(posixpath.join(here, rest))
        found = index.by_dir.get(base) if base is not None else None
        return ([found], "") if found else ([], f"{spec} names {base if base is not None else rest}, which is not a workspace package")
    target = name
    at = rest.rfind("@")
    if at > 0:
        target = rest[:at]
    elif rest.startswith("@") and "/" in rest:
        target = rest
    found = index.by_name.get(target, [])
    return (found, "") if found else ([], f"{spec} links the workspace package {target}, which no workspace package of the repository is named")


def leaves(value, star: str = "", depth: int = 0) -> list[str]:
    if isinstance(value, str):
        return [value.replace("*", star) if star else value]
    if depth >= MAX_DEPTH:
        return []
    if isinstance(value, list):
        return [leaf for item in value for leaf in leaves(item, star, depth + 1)]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in leaves(item, star, depth + 1)]
    return []


def export_leaves(exports, sub: str) -> tuple[list[str], str]:
    table = exports if isinstance(exports, dict) and exports and any(k.startswith(".") for k in exports) else {".": exports}
    if not all(isinstance(k, str) and k.startswith(".") for k in table):
        return [], "its exports mix subpaths and conditions"
    if sub in table:
        found = leaves(table[sub])
    else:
        found = []
        best = None
        for key, value in table.items():
            if key.count("*") == 1:
                head, tail = key.split("*")
                if sub.startswith(head) and sub.endswith(tail) and len(sub) >= len(head) + len(tail) and (best is None or (len(head), len(key)) > best[3]):
                    best = (head, tail, value, (len(head), len(key)))
            elif key.endswith("/") and sub.startswith(key) and (best is None or (len(key), len(key)) > best[3]):
                best = (key, None, value, (len(key), len(key)))
        if best is not None:
            head, tail, value, _ = best
            if tail is None:
                found = [leaf + sub[len(head):] for leaf in leaves(value)]
            else:
                found = leaves(value, sub[len(head):len(sub) - len(tail)])
    inside = []
    for leaf in found:
        path = posixpath.normpath(leaf) if leaf.startswith("./") else None
        if path is not None and not path.startswith(("../", "/")) and path != "..":
            inside.append(path)
    if inside:
        return inside, ""
    return [], f"its exports do not name a file for {sub}"


def declared_paths(pkg: Package, sub: str) -> tuple[list[str], str]:
    manifest = pkg.manifest
    if manifest.get("exports") is not None:
        return export_leaves(manifest["exports"], sub)
    if sub != ".":
        return [sub[2:]], ""
    found = [manifest[k] for k in ENTRY_FIELDS if isinstance(manifest.get(k), str) and manifest[k]]
    paths = [posixpath.normpath(p) for p in found]
    return [p for p in paths if not p.startswith(("../", "/")) and p != ".."] or ["index"], ""


def sources_of(repo, pkg: Package, path: str) -> list[str]:
    parts = path.split("/")
    rest = "/".join(parts[1:]) if len(parts) > 1 else path
    base = clean(joined(pkg.dir, "src", rest))
    hit = script_file(repo, base) if base is not None and parts[0] != "src" else None
    return [hit] if hit else []


def place(repo, pkg: Package, sub: str) -> tuple[list[str], list[str], str]:
    paths, problem = declared_paths(pkg, sub)
    if problem:
        return [], [], problem
    existing, declared_here = [], []
    for path in paths:
        full = clean(joined(pkg.dir, path))
        if full is None:
            continue
        hit = script_file(repo, full)
        if hit:
            existing.append(hit)
        else:
            declared_here += [full, *sources_of(repo, pkg, path)]
    return existing, declared_here, ""


def resolve(repo, rel: str, spec: str) -> tuple | None:
    split = split_specifier(spec)
    if split is None:
        return None
    name, sub = split
    index = index_of(repo)
    link = link_of(index, rel, name)
    if link is not None:
        packages, problem = linked(index, link[0], name, link[1])
        if not packages:
            return UNRESOLVED, None, problem, ()
    else:
        packages = index.by_name.get(name, [])
        if not packages:
            if index.truncated and spec.split("/")[0] not in NODE_CORE:
                return UNRESOLVED, None, f"the repository has more than {MAX_WALK} files, so its workspace packages were not all searched", ()
            return None
    packages = nearest(index, packages, rel)
    files: list[str] = []
    declared_files: list[str] = []
    problems: list[str] = []
    for pkg in packages:
        existing, declared_here, problem = place(repo, pkg, sub)
        if problem:
            problems.append(f"{joined(pkg.dir, 'package.json')} of {pkg.name}: {problem}")
        files += existing
        declared_files += declared_here
    compat = "node_modules/" + spec
    files = list(dict.fromkeys(files))
    if files:
        return REPOSITORY, files[0], "", tuple(dict.fromkeys([*files[1:], *declared_files, compat]))
    if problems and len(problems) == len(packages):
        return UNRESOLVED, packages[0].dir + "/", "; ".join(problems), tuple(dict.fromkeys(p.dir + "/" for p in packages[1:]))
    dirs = [pkg.dir + "/" for pkg in packages]
    return REPOSITORY, dirs[0], "", tuple(dict.fromkeys([*dirs[1:], *declared_files, compat]))
