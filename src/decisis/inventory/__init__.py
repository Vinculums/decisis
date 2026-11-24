from __future__ import annotations

from pathlib import Path
from types import ModuleType

from . import cargo, cyclonedx, gomod, npm, spdx, uv

READERS: dict[str, ModuleType] = {m.FORMAT: m for m in (npm, cyclonedx, spdx, uv, cargo, gomod)}
FORMATS = "an npm package-lock.json, CycloneDX JSON 1.4 to 1.6, SPDX JSON 2.3, uv.lock, Cargo.lock, or go.mod with go.sum next to it"


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


def load(path: Path) -> tuple[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    reader = READERS[detect(text, path.name)]
    siblings = {n: (path.parent / n).read_text(encoding="utf-8") for n in reader.SIBLINGS if (path.parent / n).is_file()}
    return text, siblings
