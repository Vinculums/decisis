#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import subprocess
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BASELINE_NAME = "scripts/comments-baseline.json"

PRAGMA = re.compile(
    r"#\s*(noqa\b|type:|pragma\b|pyright:|pylint:|mypy:|isort:|ruff:|fmt:\s*(off|on|skip)\b|yaml-language-server:)"
)
CODING = re.compile(r"#\s*(-\*-\s*)?coding[:=]")
PIN_LABEL = re.compile(r"\buses:\s*\S+@[0-9a-f]{40}\s+#\s*v?\d[\w.+-]*\s*$")

FIXED_BYTES = re.compile(r"(^|/)(fixtures?|golden)/")
PY = {".py"}
HASH = {".yml", ".yaml", ".toml"}
YAML = {".yml", ".yaml"}
C_LIKE = {".cypher"}
EXTS = PY | HASH | C_LIKE


def wanted(rel: str) -> bool:
    if FIXED_BYTES.search(rel):
        return False
    return os.path.splitext(rel)[1].lower() in EXTS


def _add(out: dict[int, str], line: int, text: str) -> None:
    out[line] = (out.get(line, "") + " " + text).strip()


def comments_hash(src: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for n, line in enumerate(src.splitlines(), 1):
        quote = ""
        for i, c in enumerate(line):
            if quote:
                if c == quote:
                    quote = ""
            elif c in "'\"":
                quote = c
            elif c == "#" and (i == 0 or line[i - 1] in " \t"):
                _add(out, n, line[i:])
                break
    return out


def comments_python(src: str) -> dict[int, str]:
    try:
        tree = ast.parse(src)
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (SyntaxError, ValueError, tokenize.TokenError):
        return comments_hash(src)
    out: dict[int, str] = {}
    for t in toks:
        if t.type == tokenize.COMMENT:
            _add(out, t.start[0], t.string)
    lines = src.split("\n")
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for ln in range(node.lineno, node.end_lineno + 1):
                _add(out, ln, lines[ln - 1].strip())
    return out


def comments_c_like(src: str) -> dict[int, str]:
    out: dict[int, str] = {}
    n = len(src)
    i, line = 0, 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in "'\"`":
            j = i + 1
            while j < n and src[j] not in (c, "\n"):
                if src[j] == "\\":
                    line += src.count("\n", j + 1, j + 2)
                    j += 2
                else:
                    j += 1
            i = j + 1 if j < n and src[j] == c else j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            _add(out, line, src[i:j])
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k, part in enumerate(src[i:j].split("\n")):
                _add(out, line + k, part)
            line += src.count("\n", i, j)
            i = j
        else:
            i += 1
    return out


def comment_lines(rel: str, src: str) -> dict[int, str]:
    ext = os.path.splitext(rel)[1].lower()
    if ext in PY:
        return comments_python(src)
    if ext in C_LIKE:
        return comments_c_like(src)
    return comments_hash(src)


def exempt(rel: str, ln: int, text: str, source_line: str) -> bool:
    if ln == 1 and text.startswith("#!"):
        return True
    if ln <= 2 and CODING.match(text):
        return True
    if PRAGMA.match(text):
        return True
    return os.path.splitext(rel)[1].lower() in YAML and bool(PIN_LABEL.search(source_line))


def counted(rel: str, src: str) -> list[tuple[int, str]]:
    lines = src.split("\n")
    return [(ln, txt) for ln, txt in sorted(comment_lines(rel, src).items()) if not exempt(rel, ln, txt, lines[ln - 1])]


def tracked(root: Path) -> list[str]:
    res = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [p for p in res.stdout.decode("utf-8").split("\0") if p]


def scan(root: Path) -> dict[str, list[tuple[int, str]]]:
    out: dict[str, list[tuple[int, str]]] = {}
    for rel in tracked(root):
        if not wanted(rel):
            continue
        p = root / rel
        if not p.is_file():
            continue
        hits = counted(rel, p.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n"))
        if hits:
            out[rel] = hits
    return out


def load_baseline(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    return dict(json.loads(path.read_text(encoding="utf-8")).get("files", {}))


def write_baseline(path: Path, found: dict[str, list[tuple[int, str]]]) -> None:
    data = {
        "_meta": {
            "what": "files -> comment lines that are not machine pragmas, counted by scripts/gate_comments.py",
            "regenerate": "python -X utf8 scripts/gate_comments.py --write-baseline",
            "rule": "the count only goes down; a new file starts at zero",
            "total": sum(len(v) for v in found.values()),
        },
        "files": {k: len(found[k]) for k in sorted(found)},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def compare(found: dict[str, list[tuple[int, str]]], base: dict[str, int]):
    over = [(rel, len(h), base.get(rel, 0)) for rel, h in sorted(found.items()) if len(h) > base.get(rel, 0)]
    lower = [(rel, len(found.get(rel, ())), lim) for rel, lim in sorted(base.items()) if len(found.get(rel, ())) < lim]
    return over, lower


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="no comments beyond machine pragmas; the per-file count only goes down")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--write-baseline", action="store_true", help="lower the baseline to the current counts; it never raises one")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    bpath = Path(a.baseline) if a.baseline else root / BASELINE_NAME
    try:
        found = scan(root)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"[gate_comments] internal error: {e}", file=sys.stderr)
        return 3
    total = sum(len(v) for v in found.values())
    base = load_baseline(bpath)
    if a.write_baseline and not bpath.exists():
        base = {rel: len(h) for rel, h in found.items()}
    over, lower = compare(found, base)
    if over:
        print(f"[gate_comments] BLOCK: {len(over)} files have more comment lines than their baseline")
        for rel, now, limit in over:
            print(f"\n  {rel}: {now} > {'baseline' if rel in base else 'new file allowance'} {limit}")
            for ln, txt in found[rel]:
                print(f"    {rel}:{ln}  {txt.strip()[:160]}")
        print(
            "\nCode carries no comments and no docstrings, only machine pragmas. Put the reason in the commit"
            " message or in the pull request description."
        )
        return 1
    if a.write_baseline:
        write_baseline(bpath, found)
        print(f"[gate_comments] baseline written: {total} comment lines in {len(found)} files -> {bpath}")
        return 0
    print(f"[gate_comments] PASS: {total} comment lines (baseline {sum(base.values())}, {len(found)} files)")
    if lower:
        print(f"  {len(lower)} files went down; lock it with --write-baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
