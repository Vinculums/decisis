"""Which decisions, records and concepts govern a code path.

A node anchors a path when one of its `code_ref` values names that path. A ref may carry a repository
prefix (`Demo:api/server.py`) and a symbol suffix (`store/backend.py:_guard`); both are dropped before
matching. A ref matches a queried path when it is the same path, when it lies under the queried path
(the query names a directory), or when it is a directory that holds the queried path. From each
anchor, decisions and records within a bounded number of hops are listed with the edge path and the
evidence on each edge, in the snapshot's own edge direction.
"""
from __future__ import annotations

from .queries import load as query
from .sandbox import Subgraph, sandbox

GOVERNING = ["decision", "record"]
KIND_ORDER = {"decision": 0, "record": 1, "concept": 2}
MAX_HOPS = 6


def code_path(ref: str, repo: str | None = None) -> str | None:
    """The repository-relative path a code_ref names, or None when it names another repository."""
    ref = ref.strip()
    head, sep, tail = ref.partition(":")
    if sep and head and "/" not in head and "." not in head and ("/" in tail or "." in tail.split(":", 1)[0]):
        if repo and head != repo:
            return None
        ref = tail
    ref = ref.split(":", 1)[0].strip()
    while ref.startswith("./"):
        ref = ref[2:]
    ref = ref.rstrip("/")
    return ref or None


def refs_of(node: dict) -> list[str]:
    ref = (node.get("props") or {}).get("code_ref")
    if isinstance(ref, str):
        return [ref]
    if isinstance(ref, list):
        return [r for r in ref if isinstance(r, str)]
    return []


def match_kind(ref_path: str, path: str) -> str | None:
    if ref_path == path:
        return "exact"
    if ref_path.startswith(path + "/"):
        return "under"
    if path.startswith(ref_path + "/"):
        return "encloses"
    return None


def prepare(graph: Subgraph, repo: str | None = None) -> Subgraph:
    """Add `kind` and the normalized `code_paths` to each node so the query can match and filter."""
    nodes = []
    for n in graph.nodes:
        props = {**(n.get("props") or {}), "kind": n["kind"]}
        paths = sorted({p for p in (code_path(r, repo) for r in refs_of(n)) if p})
        if paths:
            props["code_paths"] = paths
        nodes.append({**n, "props": props})
    return Subgraph(nodes, graph.edges, graph.meta)


def _steps(row: dict, edges: set[tuple[str, str, str]]) -> list[dict]:
    out = []
    for a, b, rel, ev in zip(row["ids"], row["ids"][1:], row["rels"], row["evidence"]):
        s, t = (a, b) if (a, rel, b) in edges else (b, a)
        out.append({"source": s, "type": rel, "target": t, "evidence": ev or ""})
    return out


def collect(rows: list[dict], graph: Subgraph, path: str, repo: str | None = None) -> list[dict]:
    by_id = {n["id"]: n for n in graph.nodes}
    edges = {(e["source"], e["type"], e["target"]) for e in graph.edges}
    best: dict[str, dict] = {}
    for row in sorted(rows, key=lambda r: (r["hops"], r["anchor"], r["ids"])):
        best.setdefault(row["id"], row)
    out = []
    for nid, row in best.items():
        node = by_id.get(nid, {})
        item = {"id": nid, "kind": node.get("kind") or row["kind"], "title": node.get("title") or "", "hops": row["hops"],
                "via": row["anchor"], "nodes": row["ids"], "path": _steps(row, edges)}
        if row["hops"] == 0:
            refs = [(r, code_path(r, repo)) for r in refs_of(node)]
            item["code_ref"] = [{"ref": r, "match": m} for r, p in refs if p and (m := match_kind(p, path))]
        out.append(item)
    return sorted(out, key=lambda i: (i["hops"], KIND_ORDER.get(i["kind"], len(KIND_ORDER)), i["id"]))


def run(graph: Subgraph, paths: list[str], hops: int = 3, repo: str | None = None, root=None) -> dict:
    if not 0 <= hops <= MAX_HOPS:
        raise ValueError(f"hops must be between 0 and {MAX_HOPS}")
    wanted = []
    for raw in paths:
        p = code_path(raw)
        if not p:
            raise ValueError(f"not a usable code path: {raw!r}")
        wanted.append((raw, p))
    prepared = prepare(graph, repo)
    cypher = query("governing_nodes", hops=hops)
    results = []
    with sandbox(root) as box:
        counts = box.load(prepared)
        for raw, p in wanted:
            rows = box.query(cypher, {"path": p, "dir": p + "/", "kinds": GOVERNING})
            results.append({"path": raw, "matched_as": p, "governing": collect(rows, prepared, p, repo)})
    return {"loaded": counts, "hops": hops, "repo": repo, "impact": results}


def render(report: dict) -> str:
    lines = []
    for r in report["impact"]:
        gov = r["governing"]
        lines.append(f"{r['path']}: {len(gov)} node(s) within {report['hops']} hop(s)")
        if not gov:
            lines.append("  nothing in the snapshot names this path")
        for g in gov:
            head = f"  [{g['hops']}] {g['kind']:<8} {g['id']}"
            if g["hops"] == 0:
                head += "  code_ref " + ", ".join(f"{c['ref']} ({c['match']})" for c in g.get("code_ref", []))
            else:
                head += f"  via {g['via']}"
            lines.append(head)
            for s in g["path"]:
                ev = f"  ({s['evidence']})" if s["evidence"] else ""
                lines.append(f"        {s['source']} -{s['type']}-> {s['target']}{ev}")
    return "\n".join(lines)
