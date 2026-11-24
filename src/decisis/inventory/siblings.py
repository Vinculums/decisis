from __future__ import annotations

import posixpath
from collections.abc import Callable
from pathlib import Path, PurePosixPath, PureWindowsPath

Reader = Callable[[str], "str | None"]


class Siblings(dict):
    def __init__(self, texts: dict[str, str] | None = None, reader: Reader | None = None):
        super().__init__(texts or {})
        self.reader = reader


def absolute(name: str) -> bool:
    win = PureWindowsPath(name)
    return PurePosixPath(name).is_absolute() or win.is_absolute() or bool(win.drive) or "\\" in name


def inside(name: str) -> bool:
    return not absolute(name) and ".." not in PurePosixPath(name).parts


def directory_reader(base: Path) -> Reader:
    root = base.resolve()

    def read(name: str) -> str | None:
        if not name or not inside(name):
            raise ValueError(f"{name!r} is not a path under the inventory's directory")
        real = (root / name).resolve()
        if not real.is_relative_to(root):
            raise ValueError(f"{name!r} leads outside the inventory's directory")
        return real.read_text(encoding="utf-8") if real.is_file() else None

    return read


def relative(current: str, target: str) -> str | None:
    if absolute(target):
        return None
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(current), target))
    return joined if inside(joined) else None


def fetch(siblings: dict[str, str] | None, name: str) -> str | None:
    if siblings and name in siblings:
        return siblings[name]
    reader = getattr(siblings, "reader", None)
    if reader is None:
        raise ValueError("the caller gave no way to read other files")
    return reader(name)
