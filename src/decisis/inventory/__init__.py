from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import ModuleType

from . import bun, cargo, cyclonedx, gomod, gradle, npm, pnpm, pom, spdx, uv, yarn

READERS: dict[str, ModuleType] = {m.FORMAT: m for m in (npm, cyclonedx, spdx, uv, cargo, gomod, gradle, pom, pnpm, yarn, bun)}
FORMATS = ("an npm package-lock.json, CycloneDX JSON 1.4 to 1.6, SPDX JSON 2.3, uv.lock, Cargo.lock, go.mod with go.sum next to it, "
           "gradle.lockfile, a Maven pom.xml, pnpm-lock.yaml, yarn.lock, or bun.lock")


def detect(text: str, filename: str) -> str:
    base = Path(filename).name
    for name, reader in READERS.items():
        if reader.detect(text, base):
            return name
    raise ValueError(f"cannot tell what {base or 'this file'} is; audit reads {FORMATS}")


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    name = detect(text, filename)
    nodes, edges = READERS[name].read(text, Path(filename).name, repo, siblings)
    if not any(n["kind"] == "Package" for n in nodes):
        raise ValueError(f"{Path(filename).name or 'the inventory'} ({name}) lists no packages, so there is nothing to audit")
    return nodes, edges


def notes(text: str, filename: str) -> list[str]:
    return list(getattr(READERS[detect(text, filename)], "NOTES", ()))


def siblings(text: str, filename: str, folder: Path, read: Callable[[str], str | None]) -> dict[str, str]:
    reader = READERS[detect(text, filename)]
    names = reader.sibling_names(folder, read) if hasattr(reader, "sibling_names") else reader.SIBLINGS
    found = {n: read(n) for n in names}
    return {n: t for n, t in found.items() if t is not None}


def read_beside(folder: Path) -> Callable[[str], str | None]:
    def read(name: str) -> str | None:
        path = folder / name
        return path.read_text(encoding="utf-8") if path.is_file() else None
    return read


def load(path: Path) -> tuple[str, dict[str, str]]:
    bun.refuse_binary(path)
    text = path.read_text(encoding="utf-8")
    return text, siblings(text, path.name, path.parent, read_beside(path.parent))
