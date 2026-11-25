"""GitHub CODEOWNERS: which line owns each file, and the fewest paths that cover each owner set.

Patterns follow GitHub's rules: a leading or middle `/` anchors the pattern at the repository root, otherwise it
matches at any depth; a trailing `/` matches a directory and everything below it; `*` and `?` stay within one
path segment; `**` spans segments. A pattern whose last segment is literal also owns everything below a
directory of that name; one whose last segment has a wildcard matches files only (`docs/*` owns
`docs/a.md` but not `docs/b/c.md`). The last matching line owns a file.

`git` runs git on the repository whose `.git` is in the given directory or the nearest one above it, named with
`--git-dir` and `--work-tree`, so a directory the checkout holds cannot pose as a bare repository. Replace refs,
hooks, fsmonitor, lazy fetches and pagers are off, and an implicit bare repository is refused.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_FILES = 100_000
NOT_SUPPORTED = {"\\": "escaping with a backslash", "[": "character ranges", "]": "character ranges"}


class Unsupported(ValueError):
    pass


class TooLarge(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    line: int
    pattern: str
    owners: tuple[str, ...]
    regex: re.Pattern


def glob_segment(segment: str) -> str:
    return "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in segment)


def compile_pattern(pattern: str) -> re.Pattern:
    if pattern.startswith("!"):
        raise Unsupported(f"the pattern {pattern} negates with !, which GitHub does not support")
    for ch, what in NOT_SUPPORTED.items():
        if ch in pattern:
            raise Unsupported(f"the pattern {pattern} uses {what} ({ch}), which GitHub does not support")
    directory = pattern.endswith("/")
    trimmed = pattern.rstrip("/")
    segments = trimmed.lstrip("/").split("/")
    if not trimmed or any(s in ("", ".", "..") for s in segments):
        raise Unsupported(f"the pattern {pattern} names no path below the root")
    body = "".join(segment_regex(s, i == len(segments) - 1) for i, s in enumerate(segments))
    prefix = "" if "/" in trimmed else "(?:.*/)?"
    return re.compile(prefix + body + tail(segments[-1], directory))


def segment_regex(segment: str, last: bool) -> str:
    if segment == "**":
        return ".*" if last else "(?:.*/)?"
    return glob_segment(segment) + ("" if last else "/")


def tail(last: str, directory: bool) -> str:
    if directory:
        return "/.*"
    if last == "**" or "*" in last or "?" in last:
        return ""
    return "(?:/.*)?"


def repository_files(root: Path) -> tuple[list[str], str]:
    files = git_files(root)
    source = "git" if files is not None else "walk"
    return bounded(files if files is not None else walk_files(root)), source


def bounded(files: list[str]) -> list[str]:
    if len(files) > MAX_FILES:
        raise TooLarge(f"the repository has {len(files)} files, more than the {MAX_FILES} init resolves owners for")
    return files


GIT_SAFE = ("-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null",
            "-c", "core.pager=cat", "-c", "safe.bareRepository=explicit")


def repository(root: Path) -> Path | None:
    here = Path(os.path.abspath(root))
    return next((d for d in (here, *here.parents) if os.path.lexists(d / ".git")), None)


def git(root: Path, *args: str, timeout: int) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1")
    top = repository(root)
    where = ["--git-dir", str(top / ".git"), "--work-tree", str(top)] if top is not None else []
    return subprocess.run(["git", *GIT_SAFE, *where, "-C", str(os.path.abspath(root)), *args], capture_output=True, timeout=timeout,
                          env=env, stdin=subprocess.DEVNULL)


def git_files(root: Path) -> list[str] | None:
    try:
        inside = git(root, "rev-parse", "--is-inside-work-tree", timeout=60)
        if inside.returncode != 0 or inside.stdout.decode("utf-8", "replace").strip() != "true":
            return None
        listed = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if listed.returncode != 0:
        return None
    return sorted({p for p in listed.stdout.decode("utf-8", "surrogateescape").split("\0") if p})


def walk_files(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        here = Path(dirpath).relative_to(root)
        out += [(here / f).as_posix() for f in filenames]
    return sorted(out)


def owning_rules(rules: list[Rule], files: list[str]) -> dict[str, Rule]:
    out = {}
    for f in files:
        rule = next((r for r in reversed(rules) if r.regex.fullmatch(f)), None)
        if rule is not None and rule.owners:
            out[f] = rule
    return out


def cover(files: list[str], owners_of: dict[str, tuple[str, ...]]) -> dict[tuple[str, ...], list[str]]:
    below: dict[str, set] = {}
    for f in files:
        for d in parents(f):
            below.setdefault(d, set()).add(owners_of.get(f))
    out: dict[tuple[str, ...], set[str]] = {}
    for f in files:
        owners = owners_of.get(f)
        if owners is None:
            continue
        whole = next((d + "/" for d in parents(f) if below[d] == {owners}), f)
        out.setdefault(owners, set()).add(whole)
    return {k: sorted(v) for k, v in out.items()}


def parents(path: str) -> list[str]:
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]
