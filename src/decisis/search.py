from __future__ import annotations

import re

from .impact import refs_of
from .sandbox import FULLTEXT_INDEX, Limits, Subgraph, _label, sandbox

MAX_QUERY = 512
MAX_LIMIT = 100
DEFAULT_LIMIT = 20
SEARCHABLE = ("decision", "record", "concept")
TERM = re.compile(r'([+-]?)("[^"]*"|\S+)')
HANGUL = re.compile(r"[\u1100-\u11ff\u3130-\u318f\uac00-\ud7a3]")
GROUPING = frozenset({"AND", "OR", "NOT", "&&", "||"})


def widen(term: str) -> str:
    if HANGUL.search(term) and not term.startswith('"') and not any(ch in term for ch in "*?~:()"):
        return f"({term} OR {term}*)"
    return term


def lucene(text: str) -> str:
    if not any(ch.isalnum() for ch in text):
        raise ValueError("search query has no letters or digits to search for; the index drops symbols and emoji")
    parts = TERM.findall(text)
    if any(t in GROUPING or "(" in t or ")" in t for _, t in parts):
        return " ".join(sign + widen(t) for sign, t in parts)
    must, may, nots = [], [], []
    for sign, term in parts:
        if not any(ch.isalnum() for ch in term):
            continue
        {"+": must, "-": nots, "": may}[sign].append(widen(term))
    if not must and not may:
        raise ValueError("a search query of only excluded words (-word) matches nothing; add a word to search for")
    if not must and not nots:
        return " ".join(may)
    core = f"({' AND '.join(must)})" if must else f"({' OR '.join(may)})"
    if must and may:
        core = f"{core} AND ({' OR '.join(must + may)})"
    return core + "".join(f" NOT {n}" for n in nots)


def indexed(graph: Subgraph) -> Subgraph:
    return Subgraph([{**n, "kind": n["kind"].lower()} if isinstance(n["kind"], str) and n["kind"].lower() in SEARCHABLE else n
                     for n in graph.nodes], graph.edges, graph.meta)


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
    searched = lucene(cleaned)
    by_id = {n["id"]: n for n in graph.nodes}
    labels = sorted({_label(k) for k in (allowed or SEARCHABLE)})
    cypher = (f"CALL db.index.fulltext.queryNodes('{FULLTEXT_INDEX}', $q) YIELD node, score "
              "WHERE any(l IN labels(node) WHERE l IN $labels) "
              "RETURN node.id AS id, score ORDER BY score DESC, id LIMIT $cap")
    with sandbox(root, limits) as box:
        counts = box.load(indexed(graph), fulltext=True)
        rows = box.query(cypher, {"q": searched, "labels": labels, "cap": limit + 1})
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
    if searched != " ".join(cleaned.split()):
        report["searched_as"] = searched
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
