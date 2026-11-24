from __future__ import annotations

import re

from .shape import Inventory, make_purl, package_id, text_digest

FORMAT = "go"
SIBLINGS = ("go.sum",)
LOCAL = re.compile(r"^(\.{1,2}/|/|[A-Za-z]:\\)")


def detect(text: str, filename: str) -> bool:
    return filename == "go.mod" or bool(re.search(r"^module\s+\S+\s*$", text, re.M) and not text.lstrip().startswith("{"))


def _directives(text: str) -> list[tuple[str, str, bool]]:
    out, block = [], None
    for raw in text.splitlines():
        line, _, comment = raw.partition("//")
        line, indirect = line.strip(), comment.strip() == "indirect"
        if block and line == ")":
            block = None
        elif block:
            if line:
                out.append((block, line, indirect))
        elif line.endswith("("):
            block = line[:-1].strip()
        elif line:
            verb, _, rest = line.partition(" ")
            out.append((verb, rest.strip(), indirect))
    return out


def _replacements(directives: list) -> dict:
    out = {}
    for verb, rest, _ in directives:
        if verb == "replace" and "=>" in rest:
            old, new = (part.split() for part in rest.split("=>", 1))
            out[tuple(old)] = tuple(new)
    return out


def _resolve(module: str, version: str, replaced: dict) -> tuple[str, str] | None:
    new = replaced.get((module, version)) or replaced.get((module,))
    if new is None:
        return module, version
    if LOCAL.match(new[0]) or len(new) < 2:
        return None
    return new[0], new[1]


def _sums(text: str) -> set[tuple[str, str]]:
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            out.add((parts[0], parts[1].removesuffix("/go.mod")))
    return out


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    sums = (siblings or {}).get("go.sum")
    if sums is None:
        raise ValueError("a go.mod is read with the go.sum next to it, and there is none")
    directives = _directives(text)
    replaced, known = _replacements(directives), _sums(sums)
    inv = Inventory(repo, "go-modules", text_digest(text, sums))
    for verb, rest, indirect in directives:
        parts = rest.split()
        target = _resolve(parts[0], parts[1], replaced) if verb == "require" and len(parts) >= 2 else None
        if target is None:
            continue
        module, version = target
        if (module, version) not in known:
            raise ValueError(f"go.sum has no line for {module} {version}; run go mod tidy and read both files again")
        bare = version.removeprefix("v")
        pkg = {"id": package_id("Go", module, bare), "ecosystem": "Go", "name": module, "version": bare,
               "purl": make_purl("golang", module, version), "unresolved": ""}
        inv.add((module, version), pkg, f"{repo}:{filename}#{module}@{version}")
        note = " // indirect" if indirect else ""
        via = "" if module == parts[0] else f" (replaced by {module} {version})"
        inv.depends(None, (module, version), f"go.mod requires {parts[0]} {parts[1]}{via}{note}")
    return inv.result()
