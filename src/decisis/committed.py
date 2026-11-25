"""Read the decisions a commit holds without checking the commit out or running anything from it.

`built` copies the files `decisis init` reads (the ADR and postmortem records and the CODEOWNERS file) from the
commit's tree into a private temporary directory, through the hardened git helper, and runs `init.build` there.
Only regular files are copied. What lies in an ADR directory is judged by `init.Survey`, the rule `init` applies to
a working tree, so links, submodules and files in subfolders are listed the same way and the caps stop at the same entry.
`stored` reads a snapshot file from the commit's tree and returns `None` when the commit has no file at the path.
`changes` names the decisions and waivers that one snapshot adds, changes or removes against another. `supersession` names
what that change does to supersession: each `SUPERSEDES` edge between decisions that one snapshot adds or removes against
the other, the decisions that become superseded or return to force, and each `SUPERSEDES` cycle added or removed. A cycle
of the old snapshot is removed when its members no longer lie together in one cycle of the new one, so a cycle that
only grows is not removed.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import checkout as co
from . import codeowners, cycles, impact, init
from .sandbox import Subgraph

GIT_SECONDS = 120
MAX_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
REGULAR = ("100644", "100755")
LINK = "120000"
GITLINK = "160000"
TREE = "040000"
KINDS = {**{m: init.FILE for m in REGULAR}, LINK: init.LINK_ENTRY, GITLINK: init.MODULE}
WAIVER_KEYS = ("path", "to", "package", "advisory", "rule")
UNCOMPARED = ("waivers", "content_hash")


@dataclass(frozen=True)
class Entry:
    mode: str
    oid: str
    size: int | None
    path: str


@dataclass(frozen=True)
class Supersession:
    edges: tuple[dict, ...] = ()
    superseded: tuple[dict, ...] = ()
    restored: tuple[dict, ...] = ()
    added: tuple[cycles.Cycle, ...] = ()
    removed: tuple[cycles.Cycle, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.edges or self.superseded or self.restored or self.added or self.removed)


def git(root: Path, *args: str) -> bytes:
    try:
        done = codeowners.git(root, *args, timeout=GIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError(f"git {args[0]} could not run in {root}: {e}") from None
    if done.returncode != 0:
        why = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ValueError(f"git {args[0]} failed in {root}: {why[0] if why else 'exit ' + str(done.returncode)}")
    return done.stdout


def commit_name(commit: str) -> str:
    if not commit or commit.startswith("-") or any(c.isspace() for c in commit):
        raise ValueError(f"{commit!r} does not name a commit")
    return commit


def entries(root: Path, commit: str, *paths: str, deep: bool = False) -> list[Entry]:
    out = []
    for item in git(root, "ls-tree", "-l", "-z", *(["-r"] if deep else []), commit_name(commit), "--", *paths).split(b"\0"):
        if not item:
            continue
        info, _, name = item.partition(b"\t")
        mode, _, oid, size = info.decode("ascii").split()
        out.append(Entry(mode, oid, None if size == "-" else int(size), name.decode("utf-8", "surrogateescape")))
    return out


def names(root: Path, commit: str) -> list[str]:
    listed = git(root, "ls-tree", "-r", "-z", "--name-only", commit_name(commit))
    return sorted({p for p in listed.decode("utf-8", "surrogateescape").split("\0") if p})


def inside(root: Path, path: str) -> str:
    rel = os.path.relpath(os.path.normpath(os.path.abspath(path)), os.path.normpath(os.path.abspath(root)))
    if rel == "." or rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        raise ValueError(f"the snapshot {path} is not inside working-directory {root}, so it cannot be read from the base commit; "
                         "commit it to the repository or set decisions-from: head")
    return Path(rel).as_posix()


def blob(root: Path, entry: Entry, limit: int) -> bytes:
    if entry.size is not None and entry.size > limit:
        raise ValueError(f"{entry.path} is {entry.size} bytes, more than the {limit} decisis reads from a commit")
    return git(root, "cat-file", "blob", entry.oid)


def problem(path: str, reason: str, action: str = init.SKIPPED) -> dict:
    kind = {"kind": init.DECISION} if init.adr_dir_of(path) else {}
    return {"file": path, "reason": reason, "action": action, **kind}


def copy(root: Path, commit: str, into: Path) -> list[dict]:
    problems: list[dict] = []
    report = lambda path, reason, action: problems.append(problem(path, reason, action))
    tops = {e.path: e for e in entries(root, commit, *init.ADR_DIRS)}
    picked = []
    for top in init.ADR_DIRS:
        entry = tops.get(top)
        if entry is None or entry.mode not in (TREE, LINK, GITLINK):
            continue
        if entry.mode != TREE:
            report(top, init.DIR_LINKED if entry.mode == LINK else init.DIR_SUBMODULE, init.NOT_READ)
            continue
        into.joinpath(*top.split("/")).mkdir(parents=True, exist_ok=True, mode=0o700)
        survey, below = init.Survey(top, report), {}
        for e in entries(root, commit, top + "/", deep=True):
            if e.mode in KINDS:
                survey.add(e.path, KINDS[e.mode])
                below[e.path] = e
        picked += [below[path] for path in survey.read]
    init.capped(len(picked), "ADR")
    rest = [e for e in entries(root, commit, *(d + "/" for d in init.POSTMORTEM_DIRS), *init.CODEOWNERS_FILES) if init.source(e.path)]
    for folder in sorted({e.path.rpartition("/")[0] for e in rest} & set(init.POSTMORTEM_DIRS)):
        into.joinpath(*folder.split("/")).mkdir(parents=True, exist_ok=True, mode=0o700)
    init.capped(sum(1 for e in rest if e.mode in REGULAR and e.path.rpartition("/")[0] in init.POSTMORTEM_DIRS), "postmortem")
    for e in picked + rest:
        if e.mode == LINK:
            problems.append(problem(e.path, "it is a symbolic link in the commit, and decisions are read only from regular files"))
            continue
        if e.mode not in REGULAR:
            continue
        try:
            data = blob(root, e, MAX_BYTES)
        except ValueError as err:
            problems.append(problem(e.path, str(err)))
            continue
        target = into.joinpath(*e.path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    return problems


def built(root: Path, commit: str, repo: str | None, files: list[str], also: list[str] = ()) -> Subgraph:
    with tempfile.TemporaryDirectory(prefix="decisis-decisions-") as tmp:
        problems = copy(root, commit, Path(tmp))
        snapshot = init.build(tmp, repo, files=files, also=also, problems=problems)
    return co.load(init.dump(snapshot))


def stored(root: Path, commit: str, path: str) -> Subgraph | None:
    found = [e for e in entries(root, commit, path) if e.path == path]
    if not found:
        return None
    if found[0].mode not in REGULAR:
        raise ValueError(f"the snapshot {path} is not a regular file in the commit {commit[:12]}")
    data = blob(root, found[0], MAX_SNAPSHOT_BYTES)
    try:
        return co.load(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise ValueError(f"the snapshot {path} in the commit {commit[:12]} is not UTF-8 text") from None


def has_decisions(graph: Subgraph | None) -> bool:
    return graph is not None and (any(n.get("kind") == "decision" for n in graph.nodes) or bool(init.unread_decisions(graph.meta)))


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def decisions(graph: Subgraph) -> dict[str, dict]:
    return {n["id"]: n for n in graph.nodes if n.get("kind") == "decision"}


def waiver_list(node: dict | None) -> list:
    raw = ((node or {}).get("props") or {}).get("waivers")
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return [raw]
    return raw if isinstance(raw, list) else [raw]


def waiver_key(w) -> str:
    return canonical([w.get(k) for k in WAIVER_KEYS]) if isinstance(w, dict) else canonical(w)


def waiver_label(w) -> str:
    if not isinstance(w, dict):
        return "a waiver that cannot be read"
    named = [f"{k} {w[k] if isinstance(w[k], str) else canonical(w[k])}" for k in WAIVER_KEYS if k in w]
    return ", ".join(named) or "a waiver that names nothing"


def waiver_changes(old: list, new: list) -> list[tuple[str, object]]:
    rest_old, rest_new = list(old), []
    for w in new:
        same = next((i for i, o in enumerate(rest_old) if canonical(o) == canonical(w)), None)
        if same is None:
            rest_new.append(w)
        else:
            rest_old.pop(same)
    out = []
    for w in rest_new:
        paired = next((i for i, o in enumerate(rest_old) if waiver_key(o) == waiver_key(w)), None)
        out.append(("added", w) if paired is None else ("changed", w))
        if paired is not None:
            rest_old.pop(paired)
    return out + [("removed", w) for w in rest_old]


def body(node: dict) -> str:
    props = {k: v for k, v in (node.get("props") or {}).items() if k not in UNCOMPARED}
    return canonical({**node, "props": props})


def changes(old: Subgraph, new: Subgraph) -> list[dict]:
    before, after = decisions(old), decisions(new)
    out = []
    for nid in sorted(set(before) | set(after)):
        a, b = before.get(nid), after.get(nid)
        if a is None or b is None:
            out.append({"decision": nid, "waiver": None, "change": "added" if a is None else "removed"})
        elif body(a) != body(b):
            out.append({"decision": nid, "waiver": None, "change": "changed"})
        for change, w in waiver_changes(waiver_list(a), waiver_list(b)):
            out.append({"decision": nid, "waiver": waiver_label(w), "change": change})
    return out


def supersedes(graph: Subgraph) -> set[tuple[str, str]]:
    return {(e["source"], e["target"]) for e in graph.edges if e["type"] == cycles.SUPERSEDES}


def standing(graph: Subgraph) -> dict[str, list[str]]:
    kept = decisions(graph)
    return {nid: by for nid, by in impact.superseded_by(graph).items() if nid in kept}


def supersession(old: Subgraph, new: Subgraph) -> Supersession:
    kinds = {n["id"]: n["kind"] for n in old.nodes + new.nodes}
    before, after = supersedes(old), supersedes(new)
    moved = [(s, t, "added") for s, t in after - before] + [(s, t, "removed") for s, t in before - after]
    edges = [{"source": s, "target": t, "change": change} for s, t, change in sorted(moved)
             if cycles.DECISION in (kinds.get(s), kinds.get(t))]
    was, now = standing(old), standing(new)
    kept_old, kept_new = decisions(old), decisions(new)
    superseded = [{"decision": d, "by": now[d]} for d in sorted(now) if d not in was and d in kept_old]
    restored = [{"decision": d, "by": was[d]} for d in sorted(was) if d not in now and d in kept_new]
    loops_old, loops_new = cycles.find(old.nodes, old.edges), cycles.find(new.nodes, new.edges)
    members_old, together = {c.members for c in loops_old}, [set(c.members) for c in loops_new]
    return Supersession(tuple(edges), tuple(superseded), tuple(restored), tuple(c for c in loops_new if c.members not in members_old),
                        tuple(c for c in loops_old if not any(set(c.members) <= held for held in together)))


def source_files(changed: list[str], snapshot: str | None) -> list[str]:
    if snapshot:
        return [f for f in changed if f == snapshot]
    return [f for f in changed if init.source(f)]
