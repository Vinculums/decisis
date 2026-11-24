from __future__ import annotations

import re
from dataclasses import dataclass

from .. import pep440
from .shape import Inventory, make_purl, package_id, pypi_name, text_digest
from .siblings import fetch, identity, relative

FORMAT = "requirements"
SIBLINGS: tuple[str, ...] = ()
FILE_NAME = re.compile(r"^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$", re.I)
COMMENT = re.compile(r"(^|\s)#.*$")
HASH = re.compile(r"\s+--hash(?:=|\s+)\S+")
INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s*=\s*|\s+|(?=[^\s-]))(\S+)$")
CONSTRAINT = re.compile(r"^(?:-c|--constraint)(?:\s*=\s*|\s+|(?=[^\s-]))(\S+)$")
EDITABLE = re.compile(r"^(?:-e|--editable)(?:\s*=\s*|\s+)(\S+)$")
REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[(?P<extras>[^\]]*)\])?\s*(?P<rest>.*)$")
SPECIFIER = re.compile(r"^\s*(~=|===|==|!=|<=|>=|<|>)\s*([^\s,;()]+)\s*$")
EGG = re.compile(r"#egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
MAX_DEPTH = 64


@dataclass
class Line:
    file: str
    number: int
    text: str
    name: str = ""
    version: str = ""
    reason: str = ""
    named: bool = True


def detect(text: str, filename: str) -> bool:
    if FILE_NAME.match(filename):
        return True
    if text.lstrip().startswith(("{", "[", "<")):
        return False
    lines = [t for _, t in logical_lines(text)]
    return bool(lines) and all(t.startswith("-") or shape(t) is not None for t in lines) and \
        any(not t.startswith("-") and (shape(t) or ("", ""))[1] for t in lines)


def logical_lines(text: str) -> list[tuple[int, str]]:
    out, start, parts = [], 0, []
    for number, raw in enumerate(text.splitlines(), 1):
        if not parts:
            start = number
        if raw.endswith("\\") and not COMMENT.search(raw):
            parts.append(raw[:-1])
            continue
        parts.append(raw)
        line = COMMENT.sub("", " ".join(parts)).strip()
        parts = []
        if line:
            out.append((start, line))
    return out


def shape(text: str) -> tuple[str, str] | None:
    req = HASH.sub("", text).split(";", 1)[0].strip()
    m = REQUIREMENT.match(req)
    if m is None:
        return None
    rest = m["rest"].strip()
    if rest.startswith("@"):
        return m["name"], rest
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1]
    specs = [SPECIFIER.match(s) for s in rest.split(",")] if rest else []
    if not all(specs):
        return None
    return m["name"], rest


def pinned(rest: str) -> str:
    pins = {m[2] for m in (SPECIFIER.match(s) for s in rest.split(",")) if m and m[1] == "=="} if rest else set()
    if len(pins) != 1 or "*" in next(iter(pins)):
        return ""
    version = next(iter(pins))
    try:
        pep440.key(version)
    except ValueError:
        return ""
    return version


def direct_reference(text: str) -> str:
    target = EDITABLE.match(text)
    return target[1] if target else text.split(";", 1)[0].strip()


def local(target: str) -> bool:
    return target.startswith((".", "/", "~")) or target.startswith("file:") or bool(re.match(r"^[A-Za-z]:[\\/]", target))


USERINFO = re.compile(r"(://)[^/@\s]+@")
REFERENCE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*@\s*)?(?:[a-z]+\+)?[a-z][a-z0-9+.-]*://\S+|#egg=", re.I)


def redact(text: str) -> str:
    return USERINFO.sub(r"\1***@", text)


def reference(text: str) -> bool:
    return bool(REFERENCE.search(direct_reference(text)))


def requirement(file: str, number: int, text: str) -> Line:
    text = redact(text)
    line = Line(file, number, HASH.sub("", text).strip())
    found = None if EDITABLE.match(text) else shape(text)
    if found is None:
        target = direct_reference(text)
        egg = EGG.search(target)
        line.name, line.named = (pypi_name(egg[1]), True) if egg else (target, False)
        line.reason = f"{file} line {number} installs {target} directly, not a PyPI release"
        return line
    name, rest = found
    line.name = pypi_name(name)
    line.version = pinned(rest)
    if rest.startswith("@"):
        line.reason = f"{file} line {number} installs {name} from a URL, not a PyPI release"
    elif not line.version:
        line.reason = f"{file} line {number} gives {rest or 'no version'}, not a pinned version; audit does not guess one"
    return line


class Reader:
    def __init__(self, siblings: dict[str, str] | None):
        self.siblings = siblings
        self.seen: set[str] = set()
        self.texts: list[str] = []
        self.lines: list[Line] = []
        self.notes: list[str] = []

    def file(self, name: str, text: str, key: str, depth: int = 0) -> None:
        self.seen.add(key)
        self.texts.append(text)
        for number, line in logical_lines(text):
            self.line(name, number, line, depth)

    def line(self, name: str, number: int, text: str, depth: int) -> None:
        include, constraint, editable = INCLUDE.match(text), CONSTRAINT.match(text), EDITABLE.match(text)
        if include:
            self.include(name, number, include[1], depth + 1)
        elif constraint:
            self.notes.append(f"{name} line {number} names the constraints file {redact(constraint[1])}; constraints files are not read")
        elif editable and local(editable[1]) or not editable and local(text):
            self.notes.append(f"{name} line {number} installs the local project {redact(direct_reference(text))}; "
                              "its own dependencies are not listed here and were not seen")
        elif not editable and not text.startswith("-") and shape(text) is None and not reference(text):
            self.notes.append(f"{name} line {number} is not a requirement line, so it was skipped and is not shown")
        elif editable or not text.startswith("-"):
            self.lines.append(requirement(name, number, text))

    def include(self, name: str, number: int, target: str, depth: int) -> None:
        path = None if "://" in target or target.startswith("file:") else relative(name, target)
        if path is None:
            self.notes.append(f"{name} line {number} includes {redact(target)}, which was not followed: "
                              "audit reads includes only by a relative path inside the repository")
            return
        if depth > MAX_DEPTH:
            self.notes.append(f"{name} line {number} includes {target}, which was not followed: "
                              f"includes are followed {MAX_DEPTH} levels deep")
            return
        try:
            key = identity(self.siblings, path)
            text = None if key in self.seen else fetch(self.siblings, path)
        except ValueError as e:
            self.notes.append(f"{name} line {number} includes {target}, which was not followed: {e}")
            return
        if key in self.seen:
            return
        if text is None:
            self.notes.append(f"{name} line {number} includes {target}, which does not exist")
            return
        self.file(path, text, key, depth)


def pkg(line: Line) -> dict:
    if not line.named:
        return {"id": f"pkg:unknown/{line.name}@", "ecosystem": "", "name": line.name, "version": "", "purl": "", "unresolved": line.reason}
    return {"id": package_id("PyPI", line.name, line.version), "ecosystem": "PyPI", "name": line.name, "version": line.version,
            "purl": make_purl("pypi", line.name, line.version), "unresolved": line.reason}


def build(reader: Reader, filename: str, repo: str) -> Inventory:
    inv = Inventory(repo, "pip-requirements", text_digest(*reader.texts))
    pins: dict[str, list[Line]] = {}
    for line in reader.lines:
        if not line.reason:
            pins.setdefault(line.name, []).append(line)
            inv.add((line.name, line.version), pkg(line), f"{repo}:{line.file}#{line.name}@{line.version}")
            inv.depends(None, (line.name, line.version), f"{line.file} line {line.number}: {line.text}")
    for line in reader.lines:
        if line.reason and line.name in pins:
            for pin in pins[line.name]:
                inv.depends(None, (pin.name, pin.version),
                            f"{line.file} line {line.number}: {line.text} (pinned by {pin.file} line {pin.number})")
        elif line.reason:
            inv.add((line.name, ""), pkg(line), f"{repo}:{line.file}#{line.name}")
            inv.depends(None, (line.name, ""), f"{line.file} line {line.number}: {line.text}")
    for note in reader.notes:
        inv.note(note)
    inv.note(f"{filename} lists direct dependencies only, so the packages they depend on were not seen and a vulnerable "
             "transitive dependency is not reported; audit a lockfile (poetry.lock, uv.lock) or an SBOM to cover them")
    return inv


def top_key(siblings: dict[str, str] | None, filename: str) -> str:
    try:
        return identity(siblings, filename)
    except ValueError:
        return filename


def read(text: str, filename: str, repo: str, siblings: dict[str, str] | None = None) -> tuple[list[dict], list[dict]]:
    reader = Reader(siblings)
    reader.file(filename, text, top_key(siblings, filename))
    return build(reader, filename, repo).result()
