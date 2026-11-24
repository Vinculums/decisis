from __future__ import annotations

from pathlib import Path
from types import ModuleType

from . import cargo, cyclonedx, gomod, gradle, npm, poetry, pom, requirements, spdx, uv
from .siblings import Reader, Resolver, Siblings, clean, directory_reader, directory_resolver

READERS: dict[str, ModuleType] = {m.FORMAT: m for m in (npm, cyclonedx, spdx, uv, cargo, gomod, gradle, pom, poetry, requirements)}
FORMATS = ("an npm package-lock.json, CycloneDX JSON 1.4 to 1.6, SPDX JSON 2.3, uv.lock, Cargo.lock, go.mod with go.sum next to it, "
           "gradle.lockfile, a Maven pom.xml, poetry.lock, or a pip requirements file")


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
    return nodes, edges


def notes(text: str, filename: str) -> list[str]:
    return list(getattr(READERS[detect(text, filename)], "NOTES", ()))


def gather(text: str, filename: str, reader: Reader, resolve: Resolver | None = None) -> Siblings:
    out = Siblings(reader=reader, resolve=resolve)
    for name in READERS[detect(text, Path(filename).name)].SIBLINGS:
        try:
            found = reader(name)
        except ValueError:
            continue
        if found is not None:
            out[name] = clean(found)
    return out


def load(path: Path, reader: Reader | None = None, root: Path | None = None) -> tuple[str, Siblings]:
    text = clean(path.read_text(encoding="utf-8"))
    if reader is not None:
        return text, gather(text, path.name, reader)
    return text, gather(text, path.name, directory_reader(path.parent, root), directory_resolver(path.parent, root))
