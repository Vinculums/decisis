from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import relate

TMPFS = Path("/dev/shm")


@dataclass(frozen=True)
class Subgraph:
    nodes: list[dict]
    edges: list[dict]
    meta: dict = field(default_factory=dict)


def default_root() -> Path:
    return TMPFS if TMPFS.is_dir() and os.access(TMPFS, os.W_OK) else Path(tempfile.gettempdir())


class LoadMismatch(ValueError):
    pass


def _mismatch(graph: Subgraph, got: dict) -> str:
    ids = [n["id"] for n in graph.nodes]
    known = set(ids)
    out = [f"loaded {got['nodes']} nodes and {got['edges']} edges, but the snapshot has {len(graph.nodes)} nodes and {len(graph.edges)} edges"]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        out.append("repeated node ids: " + ", ".join(dupes[:5]))
    dangling = [f"{e['source']} -{e['type']}-> {e['target']}" for e in graph.edges if e["source"] not in known or e["target"] not in known]
    if dangling:
        out.append("edges with a missing endpoint: " + ", ".join(dangling[:5]))
    return "; ".join(out)


class Sandbox:
    def __init__(self, root: Path | None = None):
        self.dir = (root or default_root()) / f"decisis-{uuid.uuid4().hex}"
        self.dir.mkdir(mode=0o700)
        self.path = self.dir / "task.rl"
        self.loaded = False

    def load(self, graph: Subgraph) -> dict:
        if self.loaded:
            raise RuntimeError("a sandbox is loaded once; build a new one for a new task")
        con = relate.connect(str(self.path))
        try:
            for kind in sorted({n["kind"] for n in graph.nodes}):
                rows = [{"id": n["id"], "title": n.get("title") or "", "domain": n.get("domain") or "", "props": _flat(n.get("props"))}
                        for n in graph.nodes if n["kind"] == kind]
                con.execute(f"UNWIND $rows AS r CREATE (n:{_label(kind)} {{id: r.id, title: r.title, domain: r.domain}}) SET n += r.props", {"rows": rows})
            for rel in sorted({e["type"] for e in graph.edges}):
                rows = [{"s": e["source"], "t": e["target"], "evidence": e.get("evidence") or ""} for e in graph.edges if e["type"] == rel]
                con.execute(f"UNWIND $rows AS r MATCH (a {{id: r.s}}), (b {{id: r.t}}) CREATE (a)-[:{_label(rel)} {{evidence: r.evidence}}]->(b)", {"rows": rows})
            nodes = con.execute("MATCH (n) RETURN count(n) AS c").single()
            edges = con.execute("MATCH ()-[r]->() RETURN count(r) AS c").single()
        finally:
            con.close()
        self.loaded = True
        got = {"nodes": dict(nodes)["c"] if nodes else 0, "edges": dict(edges)["c"] if edges else 0}
        if got != {"nodes": len(graph.nodes), "edges": len(graph.edges)}:
            raise LoadMismatch(_mismatch(graph, got))
        return got

    def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        if not self.loaded:
            raise RuntimeError("load the sandbox before querying it")
        con = relate.connect(str(self.path), read_only=True)
        try:
            return con.execute(cypher, params or {}).fetchall()
        finally:
            con.close()

    def destroy(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


@contextmanager
def sandbox(root: Path | None = None) -> Iterator[Sandbox]:
    box = Sandbox(root)
    try:
        yield box
    finally:
        box.destroy()


def _label(name: str) -> str:
    clean = "".join(ch if ch.isalnum() else "_" for ch in name.strip())
    if not clean or not clean[0].isalpha():
        raise ValueError(f"not a usable label: {name!r}")
    return clean[0].upper() + clean[1:]


def _flat(props: dict | None) -> dict:
    out = {}
    for k, v in (props or {}).items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) for x in v):
            out[k] = v
    return out
