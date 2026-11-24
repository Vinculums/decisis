"""Read-only Cypher on a snapshot: a check that refuses anything but a read before the query runs, and the schema an agent reads.

The check splits the text into tokens the way Relate does: strings with backslash escapes, // and /* */ comments,
backticked names with doubled backticks, and $parameters. Clause words are looked for only outside those. A query must
start with MATCH, OPTIONAL, WITH, UNWIND, RETURN or CALL, hold one statement, name no write, load or admin clause, and call
only the read procedures listed in READ_PROCEDURES. CALL { } subqueries are refused too: Relate plans every one of them as
read-write, so the plan check below would refuse them anyway; COLLECT { }, COUNT { }, EXISTS { } and UNION are planned as reads. A word right after a property dot or a colon, or right before a colon,
is a name (n.set, :Remove, {delete: 1}) and is not taken for a clause. What the check cannot classify, such as an unclosed
quote or a character outside ASCII in the query text, is refused. The query process then plans the query with EXPLAIN on a
read-only connection and runs it only when Relate plans it as a read; the read-only connection refuses writes on its own.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from .sandbox import Limits, NotReadOnly, Subgraph, _flat, _label, sandbox

MAX_ROWS = 500
MAX_BYTES = 1024 * 1024
MAX_CYPHER = 16 * 1024
STARTS = ("MATCH", "OPTIONAL", "WITH", "UNWIND", "RETURN", "CALL")
REFUSED = {
    **dict.fromkeys(("CREATE", "MERGE", "SET", "DELETE", "DETACH", "REMOVE", "DROP", "FOREACH", "INSERT"), "writes to the graph"),
    **dict.fromkeys(("LOAD", "COPY", "IMPORT", "EXPORT", "INSTALL", "ATTACH"), "reads or writes outside the graph"),
    **dict.fromkeys(("TERMINATE", "SHOW", "USE", "ALTER", "RENAME", "GRANT", "DENY", "REVOKE", "START", "STOP", "EXPLAIN",
                     "PROFILE"), "is not a read clause"),
}
READ_PROCEDURES = ("db.labels", "db.relationshipTypes", "db.propertyKeys", "db.schema.visualization",
                   "db.schema.nodeTypeProperties", "db.schema.relTypeProperties")
SCHEMA_LABELS = 40
SCHEMA_KEYS = 40
SCHEMA_JOINS = 8
TOKEN = re.compile(r"""
    (?P<space>[ \t\r\n]+)
  | (?P<comment>//[^\n\r\x0b\x0c\x85  ]*|/\*.*?\*/)
  | (?P<string>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
  | (?P<name>`(?:[^`]|``)*`)
  | (?P<param>\$(?:[A-Za-z_][A-Za-z0-9_]*|`(?:[^`]|``)*`|[0-9]+))
  | (?P<number>[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)
  | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<other>.)
""", re.S | re.X)
OWNERS = ("word", "name", "param")
CLOSERS = (")", "]", "}")


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    at: int


def tokens(text: str) -> list[Token]:
    out = []
    for m in TOKEN.finditer(text):
        kind = m.lastgroup
        if kind == "other":
            unreadable(text, m)
        if kind not in ("space", "comment"):
            out.append(Token(kind, m.group(), m.start()))
    return out


def unreadable(text: str, m: re.Match) -> None:
    ch = m.group()
    if ch in "'\"`":
        refuse(text, m.start(), f"the quote {ch} is not closed")
    if text.startswith("/*", m.start()):
        refuse(text, m.start(), "the comment /* is not closed")
    if not ch.isascii():
        refuse(text, m.start(), f"{ch!r} is outside ASCII; put names that need it in backticks and text in quotes")


def refuse(text: str, at: int, why: str) -> None:
    line = text.count("\n", 0, at) + 1
    col = at - (text.rfind("\n", 0, at) + 1) + 1
    raise NotReadOnly(f"refused before running, at line {line} column {col}: {why}. The query tool runs one read-only "
                      f"statement that starts with MATCH, OPTIONAL MATCH, WITH, UNWIND, RETURN or CALL, and calls only the procedures "
                      f"{', '.join(READ_PROCEDURES)}")


def check(text: str) -> None:
    toks = statement(text, tokens(text))
    first = toks[0]
    if first.kind != "word" or first.text.upper() not in STARTS:
        refuse(text, first.at, f"{first.text!r} does not start a read query")
    for i, tok in enumerate(toks):
        if tok.kind == "word" and not is_name(toks, i):
            clause(text, toks, i)


def statement(text: str, toks: list[Token]) -> list[Token]:
    if not toks:
        refuse(text, 0, "there is no query")
    end = next((i for i, t in enumerate(toks) if t.text == ";"), len(toks))
    if any(t.text != ";" for t in toks[end:]):
        refuse(text, toks[end].at, "a query holds one statement")
    if end == 0:
        refuse(text, 0, "there is no query")
    return toks[:end]


def is_name(toks: list[Token], i: int) -> bool:
    before = toks[i - 1] if i else None
    after = toks[i + 1] if i + 1 < len(toks) else None
    if after is not None and after.text == ":":
        return True
    if before is None:
        return False
    if before.text == ":":
        return True
    owner = toks[i - 2] if i > 1 else None
    return before.text == "." and owner is not None and (owner.kind in OWNERS or owner.text in CLOSERS)


def clause(text: str, toks: list[Token], i: int) -> None:
    word = toks[i].text.upper()
    if word in REFUSED:
        refuse(text, toks[i].at, f"{word} {REFUSED[word]}; a label, type or key named {toks[i].text} goes in backticks")
    if word == "CALL":
        procedure(text, toks, i)


def procedure(text: str, toks: list[Token], i: int) -> None:
    nxt = toks[i + 1] if i + 1 < len(toks) else None
    if nxt is not None and nxt.text in ("{", "("):
        refuse(text, toks[i].at, "Relate plans every CALL { } subquery as read-write, so it is not run; "
                                 "use COLLECT { }, COUNT { }, EXISTS { } or UNION")
    parts, j = [], i + 1
    while j < len(toks) and toks[j].kind in ("word", "name"):
        parts.append(unquote(toks[j]))
        if j + 1 < len(toks) and toks[j + 1].text == ".":
            j += 2
            continue
        break
    name = ".".join(parts)
    if name not in READ_PROCEDURES:
        refuse(text, toks[i].at, f"CALL {name or '?'} is not a read procedure this tool allows")


def unquote(tok: Token) -> str:
    return tok.text[1:-1].replace("``", "`") if tok.kind == "name" else tok.text


def run(graph: Subgraph, text: str, params: dict | None = None, root=None, limits: Limits | None = None) -> dict:
    check(text)
    with sandbox(root, limits) as box:
        counts = box.load(graph)
        page = box.page(text, params or {}, MAX_ROWS, MAX_BYTES)
    report = {"loaded": counts, "columns": page["columns"], "row_count": page["total"], "rows": page["rows"]}
    if len(page["rows"]) < page["total"]:
        report["cut"] = (f"{len(page['rows'])} of {page['total']} rows are shown: results stop at {MAX_ROWS} rows and "
                         f"{MAX_BYTES} bytes; add LIMIT and SKIP, or return fewer or smaller columns")
    return report


def label_counts(graph: Subgraph) -> Counter:
    return Counter(_label(n["kind"]) for n in graph.nodes)


def label_keys(graph: Subgraph) -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    for n in graph.nodes:
        keys.setdefault(_label(n["kind"]), {"id", "title", "domain"}).update(_flat(n.get("props")))
    return keys


def edge_joins(graph: Subgraph) -> dict[str, Counter]:
    kinds = {n["id"]: _label(n["kind"]) for n in graph.nodes}
    joins: dict[str, Counter] = {}
    for e in graph.edges:
        joins.setdefault(_label(e["type"]), Counter())[(kinds.get(e["source"], "?"), kinds.get(e["target"], "?"))] += 1
    return joins


def listed(items: list[str], cap: int) -> str:
    shown = ", ".join(items[:cap])
    return shown + (f", and {len(items) - cap} more" if len(items) > cap else "")


def label_lines(graph: Subgraph) -> list[str]:
    counts, keys = label_counts(graph), label_keys(graph)
    lines = [f"  :{label} ({count}): {listed(sorted(keys[label]), SCHEMA_KEYS)}" for label, count in sorted(counts.items())]
    return capped(lines, "labels")


def edge_lines(graph: Subgraph) -> list[str]:
    lines = []
    for rel, joins in sorted(edge_joins(graph).items()):
        pairs = [f"{a} -> {b} ({n})" for (a, b), n in sorted(joins.items(), key=lambda kv: (-kv[1], kv[0]))]
        lines.append(f"  :{rel} ({sum(joins.values())}): {listed(pairs, SCHEMA_JOINS)}")
    return capped(lines, "edge types")


def capped(lines: list[str], what: str) -> list[str]:
    if len(lines) <= SCHEMA_LABELS:
        return lines
    return lines[:SCHEMA_LABELS] + [f"  and {len(lines) - SCHEMA_LABELS} more {what}"]


def examples(graph: Subgraph) -> list[str]:
    joins = edge_joins(graph)
    if not joins:
        return ["  MATCH (n) RETURN labels(n) AS labels, count(*) AS nodes"]
    rel, pairs = max(sorted(joins.items()), key=lambda kv: sum(kv[1].values()))
    (a, b), _ = max(sorted(pairs.items()), key=lambda kv: kv[1])
    start = min(e["source"] for e in graph.edges if _label(e["type"]) == rel)
    return [f"  MATCH (a:{a})-[r:{rel}]->(b:{b}) RETURN a.id AS source, r.evidence AS evidence, b.id AS target LIMIT 25",
            f"  MATCH p = (a {{id: $id}})-[*1..3]-(b) RETURN b.id AS id, labels(b) AS labels, length(p) AS hops ORDER BY hops LIMIT 25"
            f"  with params {{\"id\": \"{start}\"}}"]


def describe(graph: Subgraph) -> str:
    return "\n".join([
        f"The snapshot this server loads has {len(graph.nodes)} nodes and {len(graph.edges)} edges.",
        "Node labels are node kinds with the first letter in upper case (count: property keys):",
        *label_lines(graph),
        "Edge types (count: source label -> target label):",
        *edge_lines(graph),
        "Every node has id, title and domain; every edge has evidence. Return properties and ids, not whole nodes, to keep results small.",
        "Examples:",
        *examples(graph),
    ])
