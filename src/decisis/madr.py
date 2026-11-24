"""Write a new MADR file with `status: proposed`, the code refs and the rule given, for `decisis new-adr`.

The rule is read with `rules.parse`, the reader `audit` and `check` use, and the whole file is read back with
`init`'s front matter reader before anything is written, so `init` reads it into a decision with the same code
refs and rule. The file is the next number in the ADR directory and is never overwritten.
"""
from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path

from . import init, rules

WIDTH = 4
NAME_CHARS = 60
SECTIONS = ("Context and Problem Statement", "Considered Options", "Decision Outcome")


def directory(root: Path, adr_dir: str | None) -> Path:
    if adr_dir is None:
        found = init.Tree(root).located(None, init.ADR_DIRS)
        if not found:
            raise ValueError(f"no ADR directory: looked in {', '.join(init.ADR_DIRS)}; name one with --adr-dir")
        return found[0]
    path = Path(os.path.normpath(root / adr_dir))
    if not path.is_relative_to(root) or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"--adr-dir {adr_dir} is outside the repository directory {root}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"--adr-dir {adr_dir} is not a directory")
    return path


def next_name(path: Path, title: str) -> str:
    numbered = []
    if path.is_dir():
        for p in path.iterdir():
            if p.suffix.lower() == ".md" and (m := init.LEADING_NUMBER.match(p.name)):
                numbered.append((int(m.group(1)), len(m.group(1))))
    number, width = max(numbered) if numbered else (0, WIDTH)
    words = re.sub(r"[\W_]+", "-", title.lower()).strip("-")
    if len(words) > NAME_CHARS:
        words = words[:NAME_CHARS].rsplit("-", 1)[0] or words[:NAME_CHARS]
    return f"{number + 1:0{width}d}" + (f"-{words}" if words else "") + ".md"


def checked_title(title: str) -> str:
    title = title.strip()
    if not title or any(ord(c) < 32 or ord(c) == 127 for c in title):
        raise ValueError("the title must be one line of text")
    return title


def checked_rule(text: str | None) -> dict | None:
    if text is None:
        return None
    try:
        rule = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"--rule is not valid JSON ({e.msg})") from None
    if not isinstance(rule, dict):
        raise ValueError("--rule must be one JSON object, the form ADR front matter holds")
    parsed = rules.parse(rule)
    if parsed.problems:
        raise ValueError("--rule: " + "; ".join(p.reason for p in parsed.problems))
    return rule


def checked_date(text: str | None) -> str:
    if text is None:
        return datetime.date.today().isoformat()
    try:
        return datetime.date.fromisoformat(text).isoformat()
    except ValueError:
        raise ValueError(f"--date {text!r} is not a date such as 2026-01-31") from None


def text_of(title: str, date: str, code_refs: list[str], rule: dict | None) -> str:
    lines = ["---", "status: proposed", f"date: {date}"]
    if code_refs:
        lines.append("code_ref: " + json.dumps(code_refs, ensure_ascii=False))
    if rule is not None:
        lines.append("rule: " + json.dumps(rule, ensure_ascii=False))
    lines += ["---", "", f"# {title}", ""]
    for section in SECTIONS:
        lines += [f"## {section}", ""]
    return "\n".join(lines)


def read_back(root: Path, text: str) -> dict:
    lines, _ = init.split_front_matter(text)
    fm = init.typed(init.front_matter(lines or []))
    init.code_refs(init.Tree(root), fm)
    return fm


def write(repo_dir: str | Path, title: str, adr_dir: str | None = None, code_refs: list[str] | tuple[str, ...] = (),
          rule: str | None = None, date: str | None = None) -> Path:
    root = Path(os.path.abspath(repo_dir))
    if not root.is_dir():
        raise ValueError(f"--repo-dir {repo_dir} is not a directory")
    title, stated, refs, day = checked_title(title), checked_rule(rule), [r.strip() for r in code_refs], checked_date(date)
    text = text_of(title, day, refs, stated)
    try:
        fm = read_back(root, text)
    except init.Malformed as e:
        raise ValueError(f"the new ADR would not read back: {e}") from None
    if fm.get("code_ref", []) != refs or fm.get("rule") != stated:
        raise ValueError("the new ADR would not read back with the same code refs and rule")
    folder = directory(root, adr_dir)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / next_name(folder, title)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as f:
            f.write(text)
    except FileExistsError:
        raise ValueError(f"{path.relative_to(root).as_posix()} already exists; nothing was written") from None
    return path
