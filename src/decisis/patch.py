"""The code refs `init --suggest-refs` suggests, written as one unified diff over the ADRs, for `init --patch FILE`.

Each ADR whose snapshot entry has `code_ref_source: suggested` gets one hunk: a `code_ref` list added before the closing
`---` of its front matter, a new front matter block above the first line when it has none, or, when a `code_ref` key is
there and empty, that line replaced. A comment line above each run of refs names the sentence they came from; `init`
skips comment lines in front matter, so the refs read back exactly as they were suggested, now stated. An ADR that
states a code path is never touched. The diff is made from the snapshot and the bytes `init` read: an ADR that changed
since is left out with a note. The tokens `--suggest-refs` skipped are listed in the header, which `git apply` ignores.
No ADR is written. `write` creates FILE and never replaces a file, and `target` refuses a FILE inside an ADR directory.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import init, suggest

CONTEXT = 3
COMMENT_WIDTH = 300
BOM = "\ufeff"
PLAIN = re.compile(r"[\w.][\w.+/-]*")
BARE = re.compile(r"[^\x00-\x20\"\\\x7f]+")
YAML_UNREADABLE = re.compile("[^\t\n\r\u0020-\u007e\u00a0-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]|[\u2028\u2029]")
ESCAPES = {ord('"'): '\\"', ord("\\"): "\\\\", 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r"}


class Unpatchable(ValueError):
    pass


@dataclass
class Patch:
    text: str = ""
    adrs: list[str] = field(default_factory=list)
    refs: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)
    left_out: list[tuple[str, str]] = field(default_factory=list)


def real(path: str | Path) -> Path:
    return Path(os.path.realpath(path))


def target(root: Path, given: str, adr_dir: str | None, out: str) -> Path:
    path = Path(given)
    if os.path.lexists(path):
        raise ValueError(f"--patch {given} already exists; decisis never overwrites a file")
    if not path.parent.is_dir():
        raise ValueError(f"--patch {given}: {path.parent} is not a directory")
    here = real(path)
    if here == real(out):
        raise ValueError("--patch and --out must be two different files")
    for d in (*init.ADR_DIRS, *([adr_dir] if adr_dir else [])):
        top = real(os.path.normpath(root / d))
        if here == top or here.is_relative_to(top):
            raise ValueError(f"--patch {given} is inside the ADR directory {d}; write it outside the ADR directories")
    return path


def quoted(name: str) -> str:
    if BARE.fullmatch(name) and suggest.utf8(name):
        return name
    out = ['"']
    for b in os.fsencode(name):
        out.append(ESCAPES.get(b) or (chr(b) if 0x20 <= b < 0x7F else f"\\{b:03o}"))
    return "".join(out) + '"'


def oneline(text: str) -> str:
    return " ".join("".join(c if c.isprintable() else " " for c in text).split())


def comment(sentence: str) -> str:
    text = oneline(sentence)
    if len(text) > COMMENT_WIDTH:
        cut = text[:COMMENT_WIDTH - 3]
        text = (cut.rsplit(" ", 1)[0] if " " in cut else cut) + "..."
    return "suggested from: " + text


def item(ref: str) -> str:
    if PLAIN.fullmatch(ref):
        return ref
    return YAML_UNREADABLE.sub(lambda m: f"\\u{ord(m.group()):04x}", json.dumps(ref, ensure_ascii=False))


def plain(ref: str, repo: str | None) -> str:
    return ref[len(repo) + 1:] if repo and ref.startswith(repo + ":") else ref


def block(refs: list[tuple[str, str]], eol: str) -> list[str]:
    out, last = ["code_ref:"], None
    for ref, sentence in refs:
        if sentence and sentence != last:
            out.append("  # " + comment(sentence))
        last = sentence
        out.append("  - " + item(ref))
    return [line + eol for line in out]


def lines_of(text: str) -> list[str]:
    parts = text.split("\n")
    return [p + "\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def row(tag: str, line: str) -> str:
    return tag + line + ("" if line.endswith("\n") else "\n\\ No newline at end of file\n")


def hunk(lines: list[str], at: int, drop: int, add: list[str]) -> str:
    start = max(0, at - CONTEXT)
    before, gone, after = lines[start:at], lines[at:at + drop], lines[at + drop:at + drop + CONTEXT]
    old, new = len(before) + len(gone) + len(after), len(before) + len(add) + len(after)
    body = [row(" ", s) for s in before] + [row("-", s) for s in gone] + [row("+", s) for s in add] + [row(" ", s) for s in after]
    return f"@@ -{start + 1},{old} +{start + 1},{new} @@\n" + "".join(body)


def line_ending(lines: list[str]) -> str:
    crlf = sum(line.endswith("\r\n") for line in lines)
    lf = sum(line.endswith("\n") and not line.endswith("\r\n") for line in lines)
    if crlf != lf:
        return "\r\n" if crlf > lf else "\n"
    return "\r\n" if lines[0].endswith("\r\n") else "\n"


def empty_key(line: str) -> bool:
    m = None if line[:1].isspace() else init.KEY_LINE.match(line.rstrip())
    return bool(m) and m.group(1) == "code_ref"


def edit(text: str, refs: list[tuple[str, str]]) -> str:
    lines = lines_of(text)
    eol = line_ending(lines)
    body = block(refs, eol)
    front, _ = init.split_front_matter(text.lstrip(BOM).replace("\r\n", "\n"))
    if front is None:
        framed = ["---" + eol, *body, "---" + eol]
        if lines[0].startswith(BOM):
            return hunk(lines, 0, 1, [BOM + framed[0], *framed[1:], lines[0][1:]])
        return hunk(lines, 0, 0, framed)
    key = next((n for n, line in enumerate(front) if empty_key(line)), None)
    return hunk(lines, len(front) + 1, 0, body) if key is None else hunk(lines, key + 1, 1, body)


def adr_diff(root: Path, props: dict, repo: str | None) -> tuple[str, int]:
    name = props["source_file"]
    path = root / name
    try:
        if path.is_symlink() or not real(path).is_relative_to(real(root)):
            raise Unpatchable("it is a symbolic link or leaves the repository")
        data = path.read_bytes()
    except OSError as e:
        raise Unpatchable(f"cannot read it: {e.strerror or e}") from None
    if init.content_hash(data) != props.get("content_hash"):
        raise Unpatchable("it changed after init read it; run init again")
    evidence = {e["code_ref"]: e["sentence"] for e in props.get("code_ref_evidence", [])}
    refs = [(plain(r, repo), evidence.get(r, "")) for r in props["code_ref"]]
    try:
        changed = edit(data.decode("utf-8"), refs)
    except (init.Malformed, UnicodeDecodeError, IndexError):
        raise Unpatchable("its front matter could not be read again") from None
    a, b = quoted("a/" + name), quoted("b/" + name)
    return f"diff --git {a} {b}\n--- {a}\n+++ {b}\n{changed}", len(refs)


def header(found: Patch) -> str:
    n = len(found.adrs)
    lines = ["decisis init --suggest-refs --patch",
             f"Adds {found.refs} suggested code refs to {n} ADR{'' if n == 1 else 's'} that state none. Each ref is a guess from the ADR's text: read it before you apply it.",
             "Its paths are relative to the --repo-dir init read: apply it from that directory with git apply, or from the git root with git apply --directory=<that directory>, after git apply --check accepts it."]
    for title, rows in (("Skipped, not applied:", found.skipped), ("Left out of this patch:", found.left_out)):
        if rows:
            lines += [title, *(f"  {quoted(file)}: {oneline(reason)}" for file, reason in rows)]
    return "".join(f"# {line}\n" for line in lines)


def build(root: Path, snapshot: dict) -> Patch:
    meta = snapshot["meta"]
    found = Patch(skipped=sorted({(p["file"], p["reason"]) for p in meta["problems"] if p["action"] == init.NOT_SUGGESTED}))
    diffs = []
    adrs = [n["props"] for n in snapshot["nodes"] if n["kind"] == init.DECISION and (n.get("props") or {}).get("code_ref_source") == "suggested"
            and "source_file" in n["props"]]
    for props in sorted(adrs, key=lambda p: p["source_file"]):
        try:
            diff, count = adr_diff(root, props, meta.get("repo"))
        except Unpatchable as e:
            found.left_out.append((props["source_file"], str(e)))
            continue
        diffs.append(diff)
        found.adrs.append(props["source_file"])
        found.refs += count
    found.text = header(found) + "".join(diffs) if diffs else ""
    return found


def write(path: Path, found: Patch) -> None:
    try:
        f = path.open("xb")
    except FileExistsError:
        raise ValueError(f"--patch {path} already exists; decisis never overwrites a file") from None
    except OSError as e:
        raise ValueError(f"cannot write --patch {path}: {e.strerror or e}") from None
    try:
        with f:
            f.write(found.text.encode("utf-8"))
    except OSError as e:
        path.unlink(missing_ok=True)
        raise ValueError(f"cannot write --patch {path}: {e.strerror or e}; nothing was kept") from None
