from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

import relate

from .sandbox import RESERVED_PROPS, Limits, Subgraph, _flat, _label, _runs, apply_schema, check_size

SAFE = re.compile(r"[^A-Za-z0-9._-]+")
MAX_NAME = 80
VAULT_RESERVED = RESERVED_PROPS | frozenset({"name", "body", "id"})


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


def prepare_dir(out_dir: Path, force: bool) -> None:
    if out_dir.is_symlink():
        raise ValueError(f"vault output refuses a symbolic link: {out_dir}")
    if out_dir.exists():
        if not out_dir.is_dir():
            raise ValueError(f"vault output exists and is not a directory: {out_dir}")
        if any(out_dir.iterdir()):
            if not force:
                raise ValueError(f"vault directory {out_dir} already exists and is not empty; pass --force to replace it")
            shutil.rmtree(out_dir)
    (out_dir / ".cypherlite").mkdir(parents=True, exist_ok=True)
    (out_dir / ".cypherlite" / "manifest.json").write_text('{"codec": "markdown"}\n', encoding="utf-8")


def export(graph: Subgraph, out_dir: Path, force: bool = False, limits: Limits | None = None) -> dict:
    check_size(graph, limits or Limits.resolve())
    prepare_dir(out_dir, force)
    con = relate.connect(str(out_dir))
    try:
        con.autocommit = False
        made: dict[str, list[int]] = {}
        for kind in sorted({n["kind"] for n in graph.nodes}):
            taken: set[str] = set()
            rows = []
            for n in graph.nodes:
                if n["kind"] != kind:
                    continue
                flat = {k: v for k, v in _flat(n.get("props")).items() if k not in VAULT_RESERVED}
                rows.append({"id": n["id"], "name": safe_name(str(n["id"]), taken), "title": n.get("title") or "",
                             "domain": n.get("domain") or "", "body": body_of(n), "props": flat})
            for r in con.execute(f"UNWIND $rows AS r CREATE (n:{_label(kind)} {{id: r.id, name: r.name, title: r.title, "
                                 "domain: r.domain, body: r.body}) SET n += r.props RETURN n.id AS id, id(n) AS nid",
                                 {"rows": rows}).fetchall():
                if isinstance(r["id"], str):
                    made.setdefault(r["id"], []).append(r["nid"])
        seek = {i: n[0] for i, n in made.items() if len(n) == 1}
        for rel in sorted({e["type"] for e in graph.edges}):
            for by_id, rows in _runs([e for e in graph.edges if e["type"] == rel], seek):
                match = "MATCH (a) WHERE id(a) = r.s MATCH (b) WHERE id(b) = r.t" if by_id else "MATCH (a {id: r.s}), (b {id: r.t})"
                con.execute(f"UNWIND $rows AS r {match} CREATE (a)-[:{_label(rel)} {{evidence: r.evidence}}]->(b)", {"rows": rows})
        con.commit()
        con.autocommit = True
        if graph.nodes:
            apply_schema(con, graph)
    finally:
        con.close()
    md_files = sorted(p.relative_to(out_dir).as_posix() for p in out_dir.rglob("*.md"))
    return {"out": str(out_dir), "codec": "markdown", "nodes": len(graph.nodes), "edges": len(graph.edges),
            "markdown_files": len(md_files)}
