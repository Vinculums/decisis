"""Which decisions, records and concepts govern a code path.

A node anchors a path when one of its `code_ref` values, or a decision's `subject_path` and `also_touches`,
names that path. A ref may carry a repository
prefix (`Demo:api/server.py`) and a symbol suffix (`store/backend.py:_guard`); both are dropped before
matching. A ref matches a queried path when it is the same path, when it lies under the queried path
(the query names a directory), or when it is a directory that holds the queried path. From each
anchor, decisions and records within a bounded number of hops are listed with the edge path and the
evidence on each edge, in the snapshot's own edge direction.

The walk follows only edges that carry governance, each from the node that governs to the node it governs
(`CARRIES`). An edge type it does not name, or a direction it does not name, is not followed.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import cycles
from .queries import load as query
from .sandbox import Limits, Subgraph, sandbox

GOVERNING = ["decision", "record"]
KIND_ORDER = {"decision": 0, "record": 1, "concept": 2}
MAX_HOPS = 6


def code_path(ref: str, repo: str | None = None) -> str | None:
    """The repository-relative path a code_ref names, or None when it names another repository."""
    ref = ref.strip()
    head, sep, tail = ref.partition(":")
    if sep and head and "/" not in head and "." not in head and ("/" in tail or "." in tail.split(":", 1)[0]):
        if repo and head.lower() != repo.lower():
            return None
        ref = tail
    ref = ref.split(":", 1)[0].strip()
    while ref.startswith("./"):
        ref = ref[2:]
    ref = ref.rstrip("/")
    return ref or None


REF_KEYS = ("code_ref", "subject_path", "also_touches")


@dataclass(frozen=True)
class Carry:
    type: str
    source_kind: str
    governor: str
    why: str


ANY = "*"
RECORD_ATTACHES = "a record attaches to the node it is about with one of four edge types (GRAPH.md has no about from a record); it bears on that node"
SOURCE, TARGET, LOOSE = "source", "target", "loose"
CARRIES = (
    Carry("RELATED_TO", "record", SOURCE, RECORD_ATTACHES),
    Carry("PREREQUISITE_OF", "record", SOURCE, RECORD_ATTACHES),
    Carry("DERIVES_FROM", "record", SOURCE, RECORD_ATTACHES),
    Carry("INHERITS_FROM", "record", SOURCE, RECORD_ATTACHES),
    Carry("ABOUT", ANY, SOURCE, "a decision or episode is about its target; what it decides holds for the target"),
    Carry("DERIVES_FROM", ANY, TARGET, "A comes out of B; what governs B holds for what comes out of it"),
    Carry("INHERITS_FROM", ANY, TARGET, "A inherits from B; what governs B holds for its heir"),
    Carry("RELATED_TO", "concept", LOOSE, "a loose, undirected link between two concepts carries governance only from a concept that names "
          "no code of its own (an idea such as a budget) to the concept that implements it; a concept with its own code keeps "
          "what governs it to that code"),
)
NOT_CARRIED = {
    "PREREQUISITE_OF": "A comes before B is an order of work, not a rule that holds for B",
    "SUPERSEDES": "the new claim replaces the old; the old one no longer governs",
    "CONNECTS_VIA": "a bridge joins topics; it decides nothing about them",
    "RETURNS_TO": "work handed back between two roles; it is about the roles, not the code",
}


def refs_of(node: dict) -> list[str]:
    props = node.get("props") or {}
    out: list[str] = []
    for key in REF_KEYS:
        ref = props.get(key)
        if isinstance(ref, str):
            out.append(ref)
        elif isinstance(ref, list):
            out += [r for r in ref if isinstance(r, str)]
    return out


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


def has_code(node: dict) -> bool:
    return any(code_path(r) for r in refs_of(node))


def carry_of(rel: str, source_kind: str) -> Carry | None:
    for c in CARRIES:
        if c.type == rel and c.source_kind in (source_kind, ANY):
            return c
    return None


def governance_edges(graph: Subgraph) -> list[dict]:
    """Each edge that carries governance, oriented from the node that governs to the node it governs."""
    by_id = {n["id"]: n for n in graph.nodes}
    out: dict[tuple[str, str, str], dict] = {}
    for e in graph.edges:
        s, t = by_id.get(e["source"]), by_id.get(e["target"])
        if s is None or t is None:
            continue
        c = carry_of(e["type"], s["kind"])
        if c is None:
            continue
        if c.governor == SOURCE:
            pairs = [(s, t)]
        elif c.governor == TARGET:
            pairs = [(t, s)]
        elif t["kind"] != "concept":
            pairs = []
        else:
            pairs = [(g, d) for g, d in ((s, t), (t, s)) if not has_code(g)]
        for g, d in pairs:
            out.setdefault((g["id"], e["type"], d["id"]), {"source": g["id"], "target": d["id"], "type": e["type"], "evidence": e.get("evidence") or ""})
    return sorted(out.values(), key=lambda e: (e["source"], e["type"], e["target"]))


def _steps(row: dict, edges: set[tuple[str, str, str]]) -> list[dict]:
    out = []
    for a, b, rel, ev in zip(row["ids"], row["ids"][1:], row["rels"], row["evidence"]):
        s, t = (a, b) if (a, rel, b) in edges else (b, a)
        out.append({"source": s, "type": rel, "target": t, "evidence": ev or ""})
    return out


def from_anchor(row: dict) -> dict:
    return {**row, "ids": row["ids"][::-1], "rels": row["rels"][::-1], "evidence": row["evidence"][::-1]}


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
        status = (node.get("props") or {}).get("status")
        if item["kind"] == "decision" and isinstance(status, str) and status:
            item["status"] = status
        if row["hops"] == 0:
            refs = [(r, code_path(r, repo)) for r in refs_of(node)]
            item["code_ref"] = [{"ref": r, "match": m} for r, p in refs if p and (m := match_kind(p, path))]
        out.append(item)
    return sorted(out, key=lambda i: (i["hops"], KIND_ORDER.get(i["kind"], len(KIND_ORDER)), i["id"]))


def run(graph: Subgraph, paths: list[str], hops: int = 3, repo: str | None = None, root=None, limits: Limits | None = None) -> dict:
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
    replaced = superseded_by(graph)
    with sandbox(root, limits) as box:
        counts = box.load(Subgraph(prepared.nodes, governance_edges(prepared), prepared.meta))
        for raw, p in wanted:
            rows = [from_anchor(r) for r in box.query(cypher, {"path": p, "dir": p + "/", "kinds": GOVERNING})]
            results.append(split_superseded({"path": raw, "matched_as": p}, collect(rows, prepared, p, repo), replaced))
    return {"loaded": counts, "hops": hops, "repo": repo, "impact": results}


def superseded_by(graph: Subgraph) -> dict[str, list[str]]:
    """Each superseded decision and what replaces it: the target of a SUPERSEDES edge, or a decision whose status says superseded.

    A node in a SUPERSEDES cycle is not superseded, whatever its status says, so its rules are judged as if there were no cycle.
    """
    held = {m for c in cycles.find(graph.nodes, graph.edges) for m in c.members}
    out: dict[str, set[str]] = {}
    for n in graph.nodes:
        status = (n.get("props") or {}).get("status")
        if n["kind"] == "decision" and isinstance(status, str) and status.strip().lower().startswith("superseded") and n["id"] not in held:
            out.setdefault(n["id"], set())
    for e in graph.edges:
        if e["type"] == "SUPERSEDES" and e["target"] not in held:
            out.setdefault(e["target"], set()).add(e["source"])
    return {k: sorted(v) for k, v in out.items()}


def split_superseded(result: dict, items: list[dict], replaced: dict[str, list[str]]) -> dict:
    governing, old = [], []
    for item in items:
        if item["id"] in replaced and item["kind"] == "decision":
            old.append({**item, "superseded_by": replaced[item["id"]]})
        else:
            governing.append(item)
    result["governing"] = governing
    if old:
        result["superseded"] = old
    return result


def render(report: dict) -> str:
    lines = []
    for r in report["impact"]:
        gov, old = r["governing"], r.get("superseded", [])
        tail = f", and {len(old)} superseded decision(s)" if old else ""
        lines.append(f"{r['path']}: {len(gov)} node(s) within {report['hops']} hop(s){tail}")
        if not gov and not old:
            lines.append("  nothing in the snapshot names this path")
        for g in gov:
            lines += item_lines(g, "  ")
        if old:
            lines.append("  superseded, listed for the record:")
        for g in old:
            lines += item_lines(g, "  ", " superseded by " + ", ".join(g["superseded_by"]) if g["superseded_by"] else "")
    return "\n".join(lines)


def item_lines(g: dict, indent: str, note: str = "") -> list[str]:
    head = f"{indent}[{g['hops']}] {g['kind']:<8} {g['id']}"
    if g["hops"] == 0:
        head += "  code_ref " + ", ".join(f"{c['ref']} ({c['match']})" for c in g.get("code_ref", []))
    else:
        head += f"  via {g['via']}"
    if g.get("status"):
        head += f"  status {g['status']}"
    lines = [head + (f"  ({note.strip()})" if note else "")]
    for s in g["path"]:
        ev = f"  ({s['evidence']})" if s["evidence"] else ""
        lines.append(f"{indent}      {s['source']} -{s['type']}-> {s['target']}{ev}")
    return lines
