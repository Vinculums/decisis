from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from pathlib import Path

import relate

from .sandbox import (RESERVED_PROPS, Limits, LoadMismatch, Subgraph, _flat, _label, _runs, apply_schema, check_size,
                      check_ids, prop_ids, unloadable)

SAFE = re.compile(r"[^A-Za-z0-9._-]+")
MAX_NAME = 80
MARKER = ".decisis-vault"
FILE_KEY = "decisis_file"
NOTE_KEY = "decisis_note"
OWN_KEYS = (FILE_KEY, NOTE_KEY)


def safe_name(nid: str, taken: set[str]) -> str:
    tail = nid.split(":", 1)[1] if ":" in nid else nid
    stem = SAFE.sub("-", tail).strip("-._")
    if not stem:
        stem = "node"
    if len(stem) > MAX_NAME:
        stem = stem[:MAX_NAME].rstrip("-._") or "node"
    digest = hashlib.sha256(nid.encode("utf-8")).hexdigest()[:8]
    candidate = stem if stem.lower() not in ("index", "log") else f"{stem}-{digest}"
    if candidate.lower() in taken:
        candidate = f"{stem[:MAX_NAME - 9].rstrip('-._') or 'node'}-{digest}"
    n = 2
    while candidate.lower() in taken:
        candidate = f"{stem[:MAX_NAME - 12].rstrip('-._') or 'node'}-{digest}-{n}"
        n += 1
    taken.add(candidate.lower())
    return candidate


def body_of(node: dict) -> str:
    props = node.get("props") or {}
    parts = []
    title = node.get("title") or ""
    if title:
        parts.append(f"# {title}")
    for key in ("statement", "advisory_summary", "summary", "body"):
        val = props.get(key)
        if isinstance(val, str) and val.strip() and val.strip() != title:
            parts.append(val.strip())
    return "\n\n".join(parts)


def is_vault(out_dir: Path) -> bool:
    mark = out_dir / MARKER
    if mark.is_symlink() or not mark.is_file():
        return False
    try:
        return json.loads(mark.read_text(encoding="utf-8")).get("written_by") == "decisis"
    except (OSError, ValueError, AttributeError):
        return False


def within(path: str, top: str) -> bool:
    return path == top or path.startswith(top.rstrip(os.sep) + os.sep)


def check_target(out_dir: Path, force: bool = False, inputs: tuple[Path, ...] = ()) -> None:
    if out_dir.is_symlink():
        raise ValueError(f"vault output refuses a symbolic link: {out_dir}")
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"vault output exists and is not a directory: {out_dir}")
    where = os.path.realpath(out_dir)
    if Path(where).parent == Path(where):
        raise ValueError(f"vault output {out_dir} is the filesystem root; choose a new directory for the vault")
    for src in inputs:
        if within(os.path.realpath(src), where):
            raise ValueError(f"vault output {out_dir} holds {src}, an input of this run; choose a new directory for the vault")
    if within(os.path.realpath(os.getcwd()), where):
        raise ValueError(f"vault output {out_dir} is the current directory or above it; choose a new directory for the vault")
    if within(os.path.realpath(Path.home()), where):
        raise ValueError(f"vault output {out_dir} is your home directory or above it; choose a new directory for the vault")
    if out_dir.is_dir() and any(out_dir.iterdir()):
        if not force:
            raise ValueError(f"vault directory {out_dir} already exists and is not empty; pass --force to replace a vault decisis wrote")
        if not is_vault(out_dir):
            raise ValueError(f"vault directory {out_dir} has no {MARKER} file, so decisis did not write it; "
                             "--force replaces only a vault decisis wrote, and this directory was left as it is")


def check_graph(graph: Subgraph) -> None:
    check_ids(graph)
    found = unloadable(graph, prop_ids(graph))
    if found:
        raise LoadMismatch("the snapshot cannot be exported as a vault: " + "; ".join(found) + "; nothing was written")
    own = sorted({k for n in graph.nodes for k in (n.get("props") or {}) if k in OWN_KEYS})
    if own:
        raise ValueError(f"node props {', '.join(own)} are the vault's own keys (the note's file name and text); "
                         "rename them in the snapshot; nothing was written")


def _rows(graph: Subgraph) -> dict[str, list[dict]]:
    by_label: dict[str, list[dict]] = {}
    taken: dict[str, set[str]] = {}
    for n in graph.nodes:
        label = _label(n["kind"])
        flat = {k: v for k, v in _flat(n.get("props")).items() if k not in RESERVED_PROPS and k != "id"}
        by_label.setdefault(label, []).append({
            "id": n["id"], "title": n.get("title") or "", "domain": n.get("domain") or "",
            "props": {**flat, FILE_KEY: safe_name(str(n["id"]), taken.setdefault(label, set())), NOTE_KEY: body_of(n)}})
    return by_label


def _write(graph: Subgraph, stage: Path, by_label: dict[str, list[dict]]) -> dict:
    (stage / ".cypherlite").mkdir(parents=True)
    manifest = {"codec": "markdown", "bodies": {"default": [NOTE_KEY], "per_label": {}},
                "learned": {"keys": dict.fromkeys(sorted(by_label), FILE_KEY), "rel_types": [], "raw_files": [], "folded_keys": []}}
    (stage / ".cypherlite" / "manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    con = relate.connect(str(stage))
    try:
        con.autocommit = False
        made: dict[str, list[int]] = {}
        for label, rows in sorted(by_label.items()):
            for r in con.execute(f"UNWIND $rows AS r CREATE (n:{label} {{id: r.id, title: r.title, domain: r.domain}}) "
                                 "SET n += r.props RETURN n.id AS id, id(n) AS nid", {"rows": rows}).fetchall():
                if isinstance(r["id"], str):
                    made.setdefault(r["id"], []).append(r["nid"])
        seek = {i: n[0] for i, n in made.items() if len(n) == 1}
        for rel in sorted({e["type"] for e in graph.edges}):
            for by_id, rows in _runs([e for e in graph.edges if e["type"] == rel], seek):
                match = "MATCH (a) WHERE id(a) = r.s MATCH (b) WHERE id(b) = r.t" if by_id else "MATCH (a {id: r.s}), (b {id: r.t})"
                con.execute(f"UNWIND $rows AS r {match} CREATE (a)-[:{_label(rel)} {{evidence: r.evidence}}]->(b)", {"rows": rows})
        con.commit()
        con.autocommit = True
        nodes = con.execute("MATCH (n) RETURN count(n) AS c").single()
        edges = con.execute("MATCH ()-[r]->() RETURN count(r) AS c").single()
        got = {"nodes": dict(nodes)["c"] if nodes else 0, "edges": dict(edges)["c"] if edges else 0}
        if got != {"nodes": len(graph.nodes), "edges": len(graph.edges)}:
            raise LoadMismatch(f"the vault holds {got['nodes']} nodes and {got['edges']} edges, but the snapshot has "
                               f"{len(graph.nodes)} nodes and {len(graph.edges)} edges; nothing was written")
        if graph.nodes:
            apply_schema(con, graph)
    finally:
        con.close()
    (stage / MARKER).write_text(json.dumps({"written_by": "decisis", "note": "decisis export-vault --force may replace this directory"})
                                + "\n", encoding="utf-8")
    return got


def _swap(stage: Path, out_dir: Path) -> None:
    if not out_dir.exists():
        os.rename(stage, out_dir)
        return
    old = out_dir.parent / f".{out_dir.name}.decisis-old-{uuid.uuid4().hex}"
    os.rename(out_dir, old)
    try:
        os.rename(stage, out_dir)
    except BaseException:
        os.rename(old, out_dir)
        raise
    shutil.rmtree(old)


def export(graph: Subgraph, out_dir: Path, force: bool = False, limits: Limits | None = None,
           inputs: tuple[Path, ...] = ()) -> dict:
    check_size(graph, limits or Limits.resolve())
    check_target(out_dir, force, inputs)
    check_graph(graph)
    by_label = _rows(graph)
    shown = str(out_dir)
    out_dir = Path(os.path.abspath(out_dir))
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = out_dir.parent / f".{out_dir.name}.decisis-new-{uuid.uuid4().hex}"
    try:
        got = _write(graph, stage, by_label)
        check_target(out_dir, force, inputs)
        _swap(stage, out_dir)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    md_files = sorted(p.relative_to(out_dir).as_posix() for p in out_dir.rglob("*.md"))
    return {"out": shown, "codec": "markdown", "nodes": got["nodes"], "edges": got["edges"],
            "markdown_files": len(md_files)}
