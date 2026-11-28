from __future__ import annotations

from .impact import refs_of
from .sandbox import FULLTEXT_INDEX, Limits, Subgraph, _label, sandbox

MAX_QUERY = 512
MAX_LIMIT = 100
DEFAULT_LIMIT = 20
SEARCHABLE = ("decision", "record", "concept")


def run(graph: Subgraph, text: str, limit: int = DEFAULT_LIMIT, kinds: list[str] | None = None,
        root=None, limits: Limits | None = None) -> dict:
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("search query must not be empty")
    if len(cleaned) > MAX_QUERY:
        raise ValueError(f"search query is longer than {MAX_QUERY} characters")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    allowed = None
    if kinds:
        bad = [k for k in kinds if k.lower() not in SEARCHABLE]
        if bad:
            raise ValueError(f"unknown search kind: {', '.join(bad)} (expected one of {', '.join(SEARCHABLE)})")
        allowed = {k.lower() for k in kinds}
    by_id = {n["id"]: n for n in graph.nodes}
    labels = sorted({_label(k) for k in (allowed or SEARCHABLE)})
    cypher = (f"CALL db.index.fulltext.queryNodes('{FULLTEXT_INDEX}', $q) YIELD node, score "
              "WHERE any(l IN labels(node) WHERE l IN $labels) "
              "RETURN node.id AS id, score ORDER BY score DESC, id LIMIT $cap")
    with sandbox(root, limits) as box:
        counts = box.load(graph, fulltext=True)
        rows = box.query(cypher, {"q": cleaned, "labels": labels, "cap": limit + 1})
    more = len(rows) > limit
    matches = []
    for row in rows[:limit]:
        node = by_id.get(row["id"])
        if node is None:
            continue
        kind = node["kind"]
        if allowed is not None and kind.lower() not in allowed:
            continue
        props = node.get("props") or {}
        item = {"id": node["id"], "kind": kind, "title": node.get("title") or "", "score": round(float(row["score"]), 4)}
        if isinstance(props.get("statement"), str) and props["statement"]:
            item["statement"] = props["statement"]
        if isinstance(props.get("status"), str) and props["status"]:
            item["status"] = props["status"]
        if isinstance(props.get("source_file"), str) and props["source_file"]:
            item["source_file"] = props["source_file"]
        refs = refs_of(node)
        if refs:
            item["code_ref"] = refs
        matches.append(item)
    report = {"loaded": counts, "query": cleaned, "kinds": sorted(allowed) if allowed else list(SEARCHABLE),
              "match_count": len(matches), "matches": matches}
    if more:
        report["cut"] = f"more than {limit} nodes match; the {limit} best are shown; raise limit (at most {MAX_LIMIT}) or add keywords"
    return report


def render(report: dict) -> str:
    lines = [f"search {report['query']!r}: {report['match_count']} match(es)"]
    if not report["matches"]:
        lines.append("  no matching decisions, records or concepts")
    if report.get("cut"):
        lines.append(f"  {report['cut']}")
    for m in report["matches"]:
        status = f"  status {m['status']}" if m.get("status") else ""
        lines.append(f"  [{m['score']:.3f}] {m['kind']:<8} {m['id']}  {m['title']}{status}")
        if m.get("code_ref"):
            lines.append(f"          code_ref {', '.join(m['code_ref'])}")
        if m.get("statement"):
            lines.append(f"          {m['statement']}")
    return "\n".join(lines)
