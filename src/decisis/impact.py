from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

from . import cycles, rules
from .queries import load as query
from .sandbox import Limits, LoadMismatch, Subgraph, sandbox

GOVERNING = ["decision", "record"]
KIND_ORDER = {"decision": 0, "record": 1, "concept": 2}
MAX_HOPS = 6


def code_path(ref: str, repo: str | None = None) -> str | None:
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
    by_id = {n["id"]: n for n in graph.nodes}
    dangling = [f"{e['source']} -{e['type']}-> {e['target']}" for e in graph.edges if e["source"] not in by_id or e["target"] not in by_id]
    if dangling:
        raise LoadMismatch("edges with a missing endpoint: " + ", ".join(dangling[:5]))
    out: dict[tuple[str, str, str], dict] = {}
    for e in graph.edges:
        s, t = by_id[e["source"]], by_id[e["target"]]
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
        until = valid_until(node) if item["kind"] == "decision" else None
        if until is not None:
            item["valid_until"] = until[1]
        if row["hops"] == 0:
            refs = [(r, code_path(r, repo)) for r in refs_of(node)]
            item["code_ref"] = [{"ref": r, "match": m} for r, p in refs if p and (m := match_kind(p, path))]
        out.append(item)
    return sorted(out, key=lambda i: (i["hops"], KIND_ORDER.get(i["kind"], len(KIND_ORDER)), i["id"]))


def run(graph: Subgraph, paths: list[str], hops: int = 3, repo: str | None = None, root=None, limits: Limits | None = None,
        day: datetime.date | None = None, keep_graph=None, force_graph: bool = False) -> dict:
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
    day = day or rules.today()
    replaced = superseded_by(graph)
    closed = closed_by(graph, day, replaced)
    with sandbox(root, limits, keep_graph=keep_graph, force=force_graph) as box:
        counts = box.load(Subgraph(prepared.nodes, governance_edges(prepared), prepared.meta))
        for raw, p in wanted:
            rows = [from_anchor(r) for r in box.query(cypher, {"path": p, "dir": p + "/", "kinds": GOVERNING})]
            results.append(split_superseded({"path": raw, "matched_as": p}, collect(rows, prepared, p, repo), replaced, closed))
    dated = any(valid_until(n) for n in graph.nodes if n["kind"] == "decision")
    return {"loaded": counts, "hops": hops, "repo": repo, **({"today": day.isoformat()} if dated else {}),
            **({"saved_graph": str(keep_graph)} if keep_graph is not None else {}), "impact": results}


def in_cycle(graph: Subgraph) -> set[str]:
    return {m for c in cycles.find(graph.nodes, graph.edges) for m in c.members}


def superseded_by(graph: Subgraph) -> dict[str, list[str]]:
    held = in_cycle(graph)
    out: dict[str, set[str]] = {}
    for n in graph.nodes:
        status = (n.get("props") or {}).get("status")
        if n["kind"] == "decision" and isinstance(status, str) and status.strip().lower().startswith("superseded") and n["id"] not in held:
            out.setdefault(n["id"], set())
    for e in graph.edges:
        if e["type"] == "SUPERSEDES" and e["target"] not in held:
            out.setdefault(e["target"], set()).add(e["source"])
    return {k: sorted(v) for k, v in out.items()}


_UNTIL = re.compile(
    r"([0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2})"
    r"([T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?(?:Z|[+-](?:[01][0-9]|2[0-3])(?::?[0-5][0-9])?)?)?)?)?"
)


def until_of(value) -> datetime.date | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = _UNTIL.fullmatch(text)
    if match is None:
        return None
    year, month, day, clock = match.groups()
    try:
        if clock is not None:
            iso = text[:-1] + "+00:00" if text.endswith("Z") else text
            dt = datetime.datetime.fromisoformat(iso)
            return dt.astimezone(datetime.timezone.utc).date() if dt.tzinfo is not None else dt.date()
        return datetime.date(int(year), int(month) if month else 1, int(day) if day else 1)
    except (ValueError, OverflowError):
        return None


def valid_until(node: dict) -> tuple[datetime.date, str] | None:
    found = []
    for raw in (node.get("valid_until"), (node.get("props") or {}).get("valid_until")):
        if (day := until_of(raw)) is not None:
            found.append((day, raw.strip()))
    return min(found) if found else None


def lapsed(graph: Subgraph, day: datetime.date) -> dict[str, str]:
    out = {}
    for n in graph.nodes:
        until = valid_until(n) if n["kind"] == "decision" else None
        if until is not None and until[0] <= day:
            out[n["id"]] = until[1]
    return out


def closed_by(graph: Subgraph, day: datetime.date | None = None, replaced: dict[str, list[str]] | None = None) -> dict[str, str]:
    replaced = superseded_by(graph) if replaced is None else replaced
    held = in_cycle(graph)
    return {nid: value for nid, value in lapsed(graph, day or rules.today()).items() if nid not in replaced and nid not in held}


def split_superseded(result: dict, items: list[dict], replaced: dict[str, list[str]], closed: dict[str, str] | None = None) -> dict:
    governing, old, shut = [], [], []
    for item in items:
        if item["kind"] != "decision":
            governing.append(item)
        elif item["id"] in replaced:
            old.append({**item, "superseded_by": replaced[item["id"]]})
        elif item["id"] in (closed or {}):
            shut.append(item)
        else:
            governing.append(item)
    result["governing"] = governing
    if old:
        result["superseded"] = old
    if shut:
        result["closed"] = shut
    return result


def render(report: dict) -> str:
    lines = []
    for r in report["impact"]:
        gov, old, shut = r["governing"], r.get("superseded", []), r.get("closed", [])
        tail = (f", and {len(old)} superseded decision(s)" if old else "") + (f", and {len(shut)} closed decision(s)" if shut else "")
        lines.append(f"{r['path']}: {len(gov)} node(s) within {report['hops']} hop(s){tail}")
        if not gov and not old and not shut:
            lines.append("  nothing in the snapshot names this path")
        for g in gov:
            lines += item_lines(g, "  ")
        if old:
            lines.append("  superseded, listed for the record:")
        for g in old:
            lines += item_lines(g, "  ", " superseded by " + ", ".join(g["superseded_by"]) if g["superseded_by"] else "")
        if shut:
            lines.append("  closed by valid_until, listed for the record:")
        for g in shut:
            lines += item_lines(g, "  ", "closed")
    return "\n".join(lines)


def item_lines(g: dict, indent: str, note: str = "") -> list[str]:
    head = f"{indent}[{g['hops']}] {g['kind']:<8} {g['id']}"
    if g["hops"] == 0:
        head += "  code_ref " + ", ".join(f"{c['ref']} ({c['match']})" for c in g.get("code_ref", []))
    else:
        head += f"  via {g['via']}"
    if g.get("status"):
        head += f"  status {g['status']}"
    if g.get("valid_until"):
        head += f"  valid_until {g['valid_until']}"
    lines = [head + (f"  ({note.strip()})" if note else "")]
    for s in g["path"]:
        ev = f"  ({s['evidence']})" if s["evidence"] else ""
        lines.append(f"{indent}      {s['source']} -{s['type']}-> {s['target']}{ev}")
    return lines
