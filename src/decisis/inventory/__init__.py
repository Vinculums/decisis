from __future__ import annotations

from pathlib import Path
from types import ModuleType

from . import actions, bun, cargo, cyclonedx, gomod, gradle, npm, pnpm, poetry, pom, requirements, spdx, terraform, uv, yarn
from .siblings import Lister, Reader, Resolver, Siblings, clean, directory_lister, directory_reader, directory_resolver

READERS: dict[str, ModuleType] = {m.FORMAT: m for m in (npm, cyclonedx, spdx, uv, cargo, gomod, gradle, pom, poetry, actions, terraform,
                                                         requirements, pnpm, yarn, bun)}
FORMATS = ("an npm package-lock.json, CycloneDX JSON 1.4 to 1.6, SPDX JSON 2.3, uv.lock, Cargo.lock, go.mod with go.sum next to it, "
           "gradle.lockfile, a Maven pom.xml, poetry.lock, a pip requirements file, pnpm-lock.yaml, yarn.lock, bun.lock, "
           "a GitHub Actions workflow or action.yml, or .terraform.lock.hcl")


def detect(text: str, filename: str) -> str:
    base, text = Path(filename).name, clean(text)
    for name, reader in READERS.items():
        if reader.detect(text, base):
            return name
    raise ValueError(f"cannot tell what {base or 'this file'} is; audit reads {FORMATS}")


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    text = clean(text)
    name = detect(text, filename)
    nodes, edges = READERS[name].read(text, Path(filename).name, repo, siblings)
    if not any(n["kind"] == "Package" for n in nodes):
        raise ValueError(f"{Path(filename).name or 'the inventory'} ({name}) lists no packages, so there is nothing to audit")
    unread_notes(nodes, Path(filename).name, siblings)
    return nodes, edges


def unread_notes(nodes: list[dict], filename: str, siblings: dict[str, str] | None) -> None:
    shown = {n["props"].get("name") for n in nodes if n["kind"] == "Package" and n["props"].get("unresolved")}
    notes = [f"{name}, beside {filename}, was not read: {reason}"
             for name, reason in sorted((getattr(siblings, "unread", None) or {}).items()) if name not in shown]
    repo = next((n for n in nodes if n["kind"] == "Repository"), None)
    if notes and repo is not None:
        kept = repo["props"].setdefault("inventory_notes", [])
        kept += [n for n in notes if n not in kept]


def notes(text: str, filename: str) -> list[str]:
    return list(getattr(READERS[detect(text, filename)], "NOTES", ()))


def advisories(text: str, filename: str) -> bool:
    return getattr(READERS[detect(text, filename)], "ADVISORIES", True)


def gather(text: str, filename: str, reader: Reader, resolve: Resolver | None = None, listing: Lister | None = None) -> Siblings:
    out = Siblings(reader=reader, resolve=resolve)
    base = Path(filename).name
    module = READERS[detect(text, base)]
    names = module.sibling_names(reader, resolve, listing, base) if hasattr(module, "sibling_names") else module.SIBLINGS
    for name in names:
        try:
            found = reader(name)
        except ValueError as e:
            out.unread[name] = " ".join(str(e).split())
            continue
        if found is not None:
            out[name] = clean(found)
    return out


def load(path: Path, reader: Reader | None = None, root: Path | None = None) -> tuple[str, Siblings]:
    bun.refuse_binary(path)
    text = clean(path.read_text(encoding="utf-8"))
    if reader is not None:
        return text, gather(text, path.name, reader)
    return text, gather(text, path.name, directory_reader(path.parent, root), directory_resolver(path.parent, root),
                        directory_lister(path.parent, root))
