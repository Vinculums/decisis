from __future__ import annotations

import os
import posixpath
from collections.abc import Callable
from pathlib import Path, PurePosixPath, PureWindowsPath

Reader = Callable[[str], "str | None"]
Resolver = Callable[[str], str]
Lister = Callable[[str], "list[str]"]
BOM = "﻿"


class Siblings(dict):
    def __init__(self, texts: dict[str, str] | None = None, reader: Reader | None = None, resolve: Resolver | None = None):
        super().__init__(texts or {})
        self.reader = reader
        self.resolve = resolve


def clean(text: str) -> str:
    return text.removeprefix(BOM)


def absolute(name: str) -> bool:
    win = PureWindowsPath(name)
    return PurePosixPath(name).is_absolute() or win.is_absolute() or bool(win.drive) or "\\" in name


def repository_root(start: Path) -> Path:
    start = start.resolve()
    return next((d for d in (start, *start.parents) if os.path.lexists(d / ".git")), start)


def bounded(base: Path, root: Path | None = None) -> tuple[Path, Path]:
    base = base.resolve()
    root = (root or repository_root(base)).resolve()
    if not base.is_relative_to(root):
        raise ValueError(f"the inventory's directory {base} is not under the root {root}")
    return base, root


def directory_resolver(base: Path, root: Path | None = None) -> Resolver:
    base, root = bounded(base, root)

    def resolve(name: str) -> str:
        if not name or absolute(name):
            raise ValueError(f"{name!r} is not a relative path")
        real = (base / name).resolve()
        if not real.is_relative_to(root):
            raise ValueError(f"{name!r} leads outside {root}")
        return str(real)

    return resolve


def directory_lister(base: Path, root: Path | None = None) -> Lister:
    resolve = directory_resolver(base, root)

    def listing(name: str) -> list[str]:
        real = Path(resolve(name))
        return sorted(p.name for p in real.iterdir() if p.is_file()) if real.is_dir() else []

    return listing


def directory_reader(base: Path, root: Path | None = None) -> Reader:
    resolve = directory_resolver(base, root)

    def read(name: str) -> str | None:
        real = Path(resolve(name))
        return clean(real.read_text(encoding="utf-8")) if real.is_file() else None

    return read


def relative(current: str, target: str) -> str | None:
    if absolute(target):
        return None
    return posixpath.normpath(posixpath.join(posixpath.dirname(current), target))


def identity(siblings: dict[str, str] | None, name: str) -> str:
    resolve = getattr(siblings, "resolve", None)
    return resolve(name) if resolve is not None else name


def fetch(siblings: dict[str, str] | None, name: str) -> str | None:
    if siblings and name in siblings:
        return clean(siblings[name])
    reader = getattr(siblings, "reader", None)
    if reader is None:
        raise ValueError("the caller gave no way to read other files")
    text = reader(name)
    return None if text is None else clean(text)
