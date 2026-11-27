from __future__ import annotations

import functools
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_FILES = 100_000
NOT_SUPPORTED = {"\\": "escaping with a backslash", "[": "character ranges", "]": "character ranges"}
ANY = "*"
SPAN = "**"


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


def split_pattern(pattern: str) -> tuple[list[str], bool, bool]:
    directory = pattern.endswith("/")
    trimmed = pattern.rstrip("/")
    segments = trimmed.lstrip("/").split("/")
    if not trimmed or any(s in ("", ".", "..") for s in segments):
        raise Unsupported(f"the pattern {pattern} names no path below the root")
    return segments, directory, "/" in trimmed


def compile_pattern(pattern: str) -> re.Pattern:
    if pattern.startswith("!"):
        raise Unsupported(f"the pattern {pattern} negates with !, which GitHub does not support")
    for ch, what in NOT_SUPPORTED.items():
        if ch in pattern:
            raise Unsupported(f"the pattern {pattern} uses {what} ({ch}), which GitHub does not support")
    segments, directory, anchored = split_pattern(pattern)
    body = "".join(segment_regex(s, i == len(segments) - 1) for i, s in enumerate(segments))
    return re.compile(("" if anchored else "(?:.*/)?") + body + tail(segments[-1], directory))


def segment_regex(segment: str, last: bool) -> str:
    if segment == "**":
        return ".*" if last else "(?:.*/)?"
    return glob_segment(segment) + ("" if last else "/")


def plain_name(last: str) -> bool:
    return last != SPAN and "*" not in last and "?" not in last


def tail(last: str, directory: bool) -> str:
    if directory:
        return "/.*"
    return "(?:/.*)?" if plain_name(last) else ""


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


def pattern_steps(pattern: str) -> tuple[str, ...]:
    segments, directory, anchored = split_pattern(pattern)
    steps = [] if anchored else [SPAN]
    for i, segment in enumerate(segments):
        if segment != SPAN:
            steps.append(segment)
        elif i < len(segments) - 1:
            steps.append(SPAN)
        else:
            steps += [ANY, SPAN]
    if directory:
        steps += [ANY, SPAN]
    elif plain_name(segments[-1]):
        steps.append(SPAN)
    return tuple(steps)


@functools.lru_cache(maxsize=4096)
def segment_pattern(step: str) -> re.Pattern:
    return re.compile(glob_segment(step))


State = tuple[int, bool]


def settle(steps: tuple[str, ...], states: set[State]) -> frozenset[State]:
    out = set()
    for i, named in states:
        out.add((i, named))
        while i < len(steps) and steps[i] == SPAN:
            i += 1
            out.add((i, named))
    return frozenset(out)


def advance(steps: tuple[str, ...], states: frozenset[State], segment: str) -> frozenset[State]:
    moved = set()
    for i, named in states:
        if i == len(steps):
            continue
        if steps[i] == SPAN:
            moved.add((i, named))
        elif segment_pattern(steps[i]).fullmatch(segment):
            moved.add((i + 1, True))
    return settle(steps, moved)


def matches_everything(steps: tuple[str, ...], at: int) -> bool:
    rest = steps[at:]
    return SPAN in rest and rest.count(ANY) <= 1 and all(s in (SPAN, ANY) for s in rest)


class Ownership:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self.steps = [pattern_steps(r.pattern) for r in rules]
        self.reach: dict[str, dict[int, frozenset[State]]] = {"": {i: settle(s, {(0, False)}) for i, s in enumerate(self.steps)}}
        self.settled: dict[str, bool] = {}

    def reaching(self, directory: str) -> dict[int, frozenset[State]]:
        chain = []
        here = directory
        while here not in self.reach:
            chain.append(here)
            here = here.rpartition("/")[0]
        for d in reversed(chain):
            parent, _, name = d.rpartition("/")
            moved = {i: advance(self.steps[i], states, name) for i, states in self.reach[parent].items()}
            self.reach[d] = {i: states for i, states in moved.items() if states}
        return self.reach[directory]

    def owns(self, directory: str, owners: tuple[str, ...]) -> bool:
        if directory not in self.settled:
            self.settled[directory] = self.decide(directory, owners)
        return self.settled[directory]

    def decide(self, directory: str, owners: tuple[str, ...]) -> bool:
        reaching = self.reaching(directory)
        for i in sorted(reaching, reverse=True):
            steps = self.steps[i]
            below = [(s, named) for s, named in reaching[i] if s < len(steps)]
            if any(matches_everything(steps, s) for s, _ in below):
                return self.rules[i].owners == owners
            if self.rules[i].owners != owners and any(named for _, named in below):
                return False
        return False


def cover(files: list[str], owners_of: dict[str, tuple[str, ...]], rules: list[Rule]) -> dict[tuple[str, ...], list[str]]:
    below: dict[str, set] = {}
    for f in files:
        for d in parents(f):
            below.setdefault(d, set()).add(owners_of.get(f))
    ownership = Ownership(rules)
    out: dict[tuple[str, ...], set[str]] = {}
    for f in files:
        owners = owners_of.get(f)
        if owners is None:
            continue
        whole = next((d + "/" for d in parents(f) if below[d] == {owners} and ownership.owns(d, owners)), f)
        out.setdefault(owners, set()).add(whole)
    return {k: sorted(v) for k, v in out.items()}


def parents(path: str) -> list[str]:
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]
