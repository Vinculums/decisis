"""Code refs suggested from the paths an ADR's own text names, for `init --suggest-refs`.

A candidate is a backticked token, a word with a `/` or a file extension, or a Markdown link target (relative
to the ADR, or a GitHub file URL); in a fenced code block only words with a `/` count. A bare word must be a path
from the repository root; a word with a `/` or an extension may also match every path that ends with it. Paths in
the ADR's own directory are records, not code, and are never suggested. A candidate that matches more than
`MAX_MATCHES` paths, or that is only a bare common name, is skipped and returned with the reason. Each suggestion
keeps the first sentence that named it.
"""
from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from . import codeowners as owners

MAX_MATCHES = 5
COMMON = frozenset({"src", "test", "readme", "docs", "lib", "main"})
SKIP_DIRS = frozenset({".git", "node_modules", "vendor"})
BACKTICK = re.compile(r"`([^`\n]+)`")
LINK = re.compile(r"(!?)\[([^\]\n]*)\]\(\s*<?([^)\s>]+)>?[^)\n]*\)")
GLOB = set("*?{[")
EXTENSION = re.compile(r"[^/.]\.[A-Za-z][A-Za-z0-9]{0,7}$")
GITHUB_FILE = re.compile(r"https?://github\.com/[^/\s]+/[^/\s]+/(?:blob|tree)/[^/\s]+/(\S+)$")
LINE_SUFFIX = re.compile(r":\d+(?:[:-]\d+)?$")
NOT_PATH = set("*?$<>{}[]|\\~=,;:\"'`()")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\[(`*_\"'])")
BLOCK = re.compile(r"\s*(?:[-*+]|\d+[.)]|>)\s+")
FENCE = ("```", "~~~")
LEADING = "([{<'\"*_"
TRAILING = ".,;:!?)]}>'\"*_"


class TooLarge(ValueError):
    pass


@dataclass
class Index:
    paths: set[str] = field(default_factory=set)
    dirs: set[str] = field(default_factory=set)
    ending: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def of(cls, files: list[str]) -> "Index":
        index = cls()
        for f in files:
            parts = f.split("/")
            index.add(f)
            for i in range(1, len(parts)):
                d = "/".join(parts[:i])
                index.dirs.add(d)
                index.add(d)
        return index

    def add(self, path: str) -> None:
        if path in self.paths:
            return
        self.paths.add(path)
        parts = path.split("/")
        for i in range(len(parts)):
            self.ending.setdefault("/".join(parts[i:]), set()).add(path)

    def lookup(self, token: str, ending: bool = True) -> list[str]:
        if token in self.paths:
            return [token]
        return sorted(self.ending.get(token, ())) if ending else []

    def ref(self, path: str) -> str:
        return path + "/" if path in self.dirs else path


@dataclass
class Suggested:
    refs: dict[str, str] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)


def repository_files(root: Path) -> tuple[list[str], list[tuple[str, str]]]:
    notes: list[tuple[str, str]] = []
    files = owners.git_files(root)
    if files is None:
        files = walk(root, ignored(root, notes))
    files = [f for f in files if not SKIP_DIRS.intersection(f.split("/")[:-1])]
    odd = sum(not utf8(f) for f in files)
    if odd:
        notes.append((".", f"{count(odd, 'file name')} {'is' if odd == 1 else 'are'} not UTF-8; --suggest-refs never suggests them"))
    if len(files) > owners.MAX_FILES:
        raise TooLarge(f"the repository has {len(files)} files, more than the {owners.MAX_FILES} --suggest-refs searches")
    return files, notes


def utf8(name: str) -> bool:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def ignored(root: Path, notes: list[tuple[str, str]]) -> list[re.Pattern]:
    path = root / ".gitignore"
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        return []
    patterns = []
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").split("\n"), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(owners.compile_pattern(line))
        except owners.Unsupported:
            notes.append((".gitignore", f"line {n}: {line} uses negation, a range or an escape, which --suggest-refs does not read"))
    return patterns


def walk(root: Path, patterns: list[re.Pattern]) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath).relative_to(root).as_posix()
        here = "" if here == "." else here + "/"
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not any(p.fullmatch(here + d) or p.fullmatch(here + d + "/")
                                                                                 for p in patterns))
        out += [here + f for f in filenames if not any(p.fullmatch(here + f) for p in patterns)]
    return sorted(out)


def sentences(body: str) -> list[tuple[str, bool]]:
    blocks: list[tuple[list[str], bool]] = [([], False)]
    fence = False
    for line in body.split("\n"):
        text = line.strip()
        if text.startswith(FENCE):
            fence = not fence
            blocks.append(([], False))
        elif fence or not text or text.startswith(("#", "|")):
            blocks += [([text] if text else [], fence), ([], False)]
        elif m := BLOCK.match(line):
            blocks.append(([line[m.end():].strip()], False))
        else:
            blocks[-1][0].append(text)
    out = []
    for lines, code in blocks:
        if lines:
            out += [(s, code) for s in ([" ".join(lines)] if code else SENTENCE_END.split(" ".join(lines))) if s.strip()]
    return out


def clean(word: str) -> str:
    word = word.strip().lstrip(LEADING).rstrip(TRAILING)
    return LINE_SUFFIX.sub("", word.split("#", 1)[0])


def inside(path: str) -> str | None:
    path = posixpath.normpath(path) if path else ""
    if not path or path == "." or path == ".." or path.startswith("../") or NOT_PATH.intersection(path):
        return None
    return path


def link_target(target: str, base: str) -> str | None:
    if m := GITHUB_FILE.match(target):
        return inside(unquote(m.group(1).split("?", 1)[0].split("#", 1)[0]))
    if "://" in target or target.lower().startswith("mailto:") or target.startswith("#"):
        return None
    path = unquote(target.split("?", 1)[0].split("#", 1)[0])
    return inside(path.lstrip("/") if path.startswith("/") else posixpath.join(base, path))


def word_path(word: str, bare: bool) -> tuple[str, bool] | None:
    word = clean(word)
    if m := GITHUB_FILE.match(word):
        found = inside(unquote(m.group(1)))
        return (found, False) if found else None
    if "://" in word or word.lower().startswith("mailto:") or any(c.isspace() for c in word):
        return None
    pathlike = "/" in word or bool(EXTENSION.search(word.rstrip("/")))
    if not (bare or pathlike):
        return None
    rooted = word.startswith("/")
    while word.startswith("./"):
        word = word[2:]
    parts = [p for p in word.split("/") if p]
    if any(GLOB.intersection(p) for p in parts):
        parts = parts[:next(i for i, p in enumerate(parts) if GLOB.intersection(p))]
        pathlike = len(parts) > 1
    if ".." in parts:
        return None
    found = inside("/".join(parts))
    return (found, pathlike and not rooted) if found else None


def candidates(sentence: str, base: str = "", code: bool = False) -> list[tuple[str, bool]]:
    found: list[tuple[str, bool]] = []
    if not code:
        for m in LINK.finditer(sentence):
            if not m.group(1) and (target := link_target(m.group(3), base)):
                found.append((target, False))
        sentence = LINK.sub(lambda m: " " if m.group(1) else f" {m.group(2)} ", sentence)
    words: list[tuple[str, bool]] = []
    for m in BACKTICK.finditer(sentence):
        inner = m.group(1).strip()
        if inner and not any(c.isspace() for c in inner):
            words.append((inner, True))
        else:
            words += [(w, False) for w in inner.split()]
    words += [(w, False) for w in BACKTICK.sub(" ", sentence).split()]
    for word, bare in words:
        if (c := word_path(word, bare and not code)) is not None and (not code or "/" in c[0]):
            found.append(c)
    out: list[tuple[str, bool]] = []
    for c in found:
        if c not in out:
            out.append(c)
    return out


def suggest(index: Index, body: str, base: str = "") -> Suggested:
    found = Suggested()
    for sentence, code in sentences(body):
        for token, ending in candidates(sentence, base, code):
            paths = [p for p in index.lookup(token, ending) if not base or (p != base and not p.startswith(base + "/"))]
            if not paths:
                continue
            if "/" not in token and token.lower() in COMMON:
                found.skipped.setdefault(token, f"`{token}` is a bare common name; it matches {count(paths)}")
                continue
            if len(paths) > MAX_MATCHES:
                found.skipped.setdefault(token, f"`{token}` matches {count(paths)}, more than {MAX_MATCHES}")
                continue
            for p in paths:
                if utf8(p):
                    found.refs.setdefault(index.ref(p), sentence)
    return found


def count(paths: list[str] | int, noun: str = "path") -> str:
    n = paths if isinstance(paths, int) else len(paths)
    return f"1 {noun}" if n == 1 else f"{n} {noun}s"
