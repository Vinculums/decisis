"""Mermaid and HTML views of the `impact`, `paths` and `audit` reports.

Each kind names a title, a graph builder and the HTML sections in `KINDS`. A graph is a list of nodes
(id, label, class) and edges (source, label, target, violated); `mermaid` and `html` read only that table,
so a new report kind is one more entry.
"""
from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass, field
from typing import Callable

LINK = re.compile(r"^https?://[^\s\"'<>`]+$")
MERMAID_SAFE = set(" -_.,:/()@+=?!'*")
CLASSES = {
    "decision": "fill:#dbeafe,stroke:#1d4ed8,color:#0b1b3f",
    "record": "fill:#fef3c7,stroke:#b45309,color:#3b2603",
    "concept": "fill:#ecfdf5,stroke:#047857,color:#032b1f",
    "code": "fill:#f3f4f6,stroke:#4b5563,color:#111827",
    "repository": "fill:#f3f4f6,stroke:#4b5563,stroke-width:2px,color:#111827",
    "package": "fill:#f3f4f6,stroke:#4b5563,color:#111827",
    "advisory": "fill:#fde2e2,stroke:#b91c1c,color:#3f0a0a",
    "endpoint": "fill:#ede9fe,stroke:#6d28d9,color:#1e1037",
    "violated": "fill:#fecaca,stroke:#b91c1c,stroke-width:3px,color:#3f0a0a",
    "superseded": "fill:#f3f4f6,stroke:#9ca3af,stroke-dasharray:4 3,color:#4b5563",
}
VIOLATED_LINK = "stroke:#b91c1c,stroke-width:3px"


@dataclass
class Graph:
    nodes: dict[str, tuple[tuple[str, ...], str]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], bool] = field(default_factory=dict)

    def node(self, nid: str, lines: tuple[str, ...] = (), cls: str = "", replace: bool = False) -> None:
        if replace or nid not in self.nodes:
            self.nodes[nid] = (lines or (nid,), cls)

    def edge(self, source: str, label: str, target: str, violated: bool = False) -> None:
        for nid in (source, target):
            self.node(nid)
        key = (source, label, target)
        self.edges[key] = self.edges.get(key, False) or violated


@dataclass(frozen=True)
class Kind:
    title: Callable[[dict], str]
    graph: Callable[[dict], Graph]
    sections: Callable[[dict], list[str]]


def kind_class(kind: str) -> str:
    return kind if kind in CLASSES else ""


def label(nid: str, title: str = "") -> tuple[str, ...]:
    return (nid, title) if title and title != nid else (nid,)


def mermaid_text(text: str) -> str:
    out = []
    for ch in str(text):
        if ch.isspace():
            out.append(" ")
        elif ch.isalnum() or ch in MERMAID_SAFE:
            out.append(ch)
        else:
            out.append(f"#{ord(ch)};")
    return "".join(out)


def mermaid_label(lines: tuple[str, ...]) -> str:
    return "<br/>".join(mermaid_text(line) for line in lines)


def mermaid_lines(g: Graph) -> list[str]:
    ids = {nid: f"n{i}" for i, nid in enumerate(g.nodes)}
    lines = ["flowchart LR"]
    lines += [f'  {ids[nid]}["{mermaid_label(lab)}"]' for nid, (lab, _) in g.nodes.items()]
    lines += [f'  {ids[s]} -->|"{mermaid_text(lab)}"| {ids[t]}' for s, lab, t in g.edges]
    used = sorted({cls for _, cls in g.nodes.values() if cls})
    lines += [f"  classDef {cls} {CLASSES[cls]}" for cls in used]
    for cls in used:
        lines.append(f"  class {','.join(ids[n] for n, (_, c) in g.nodes.items() if c == cls)} {cls}")
    hot = [str(i) for i, v in enumerate(g.edges.values()) if v]
    if hot:
        lines.append(f"  linkStyle {','.join(hot)} {VIOLATED_LINK}")
    return lines


def impact_graph(report: dict) -> Graph:
    g = Graph()
    titles = {i["id"]: i.get("title") or "" for r in report.get("impact", []) for i in r.get("governing", []) + r.get("superseded", [])}
    for r in report.get("impact", []):
        code = f"path:{r['path']}"
        g.node(code, (r["path"],), "code")
        for item in r.get("governing", []):
            impact_node(g, item, code, titles, kind_class(item.get("kind") or ""))
        for item in r.get("superseded", []):
            impact_node(g, item, code, titles, "superseded", ("superseded",))
            for new in item.get("superseded_by", []):
                g.node(new, label(new, titles.get(new, "")), "decision")
                g.edge(new, "SUPERSEDES", item["id"])
    return g


def impact_node(g: Graph, item: dict, code: str, titles: dict, cls: str, extra: tuple[str, ...] = ()) -> None:
    g.node(item["id"], label(item["id"], item.get("title") or "") + extra, cls, replace=True)
    for c in item.get("code_ref", []):
        g.edge(item["id"], f"code_ref {c['match']}", code)
    for s in item.get("path", []):
        for nid in (s["source"], s["target"]):
            g.node(nid, label(nid, titles.get(nid, "")), kind_class(nid.split(":", 1)[0]))
        g.edge(s["source"], s["type"], s["target"])


def path_steps(path: dict) -> list[dict]:
    if path.get("steps"):
        return path["steps"]
    ids, rels = path.get("ids", []), path.get("rels", [])
    return [{"source": a, "type": r, "target": b, "evidence": ""} for a, b, r in zip(ids, ids[1:], rels)]


def paths_graph(report: dict) -> Graph:
    g = Graph()
    info = report.get("nodes", {})
    ends = {report.get("source"), report.get("target")}
    for p in report.get("paths", []):
        for nid in p.get("ids", []):
            n = info.get(nid, {})
            cls = "endpoint" if nid in ends else kind_class(n.get("kind") or nid.split(":", 1)[0])
            g.node(nid, label(nid, n.get("title") or ""), cls)
        for s in path_steps(p):
            g.edge(s["source"], s["type"], s["target"])
    return g


def violated(finding: dict) -> bool:
    return any(p.get("verdict") == "violated" for p in finding.get("policies", []))


def target(finding: dict) -> str:
    return finding.get("advisory") or finding["package"]


def detail(finding: dict) -> str:
    if finding.get("kind") == "license":
        return f"license {finding.get('license_expression') or 'unknown'}"
    if finding.get("kind") == "package":
        return "denied package"
    return finding.get("severity") or ""


def audit_graph(report: dict) -> Graph:
    g = Graph()
    repo = (report.get("meta") or {}).get("repo")
    if repo:
        g.node(f"repo:{repo}", (f"repo:{repo}",), "repository")
    for d in report.get("governing", []):
        g.node(d["decision"], label(d["decision"], d.get("title") or ""), "decision")
        g.edge(d["decision"], "ABOUT", d["via"])
        if repo:
            g.edge(f"repo:{repo}", "DESCRIBED_BY", d["via"])
    for f in report.get("findings", []):
        bad = violated(f)
        path = f.get("path", [])
        for nid in path[:-1]:
            g.node(nid, (nid,), "package" if nid.startswith("pkg:") else "repository")
        end = target(f)
        g.node(end, label(end, detail(f)), "violated" if bad else "advisory" if "advisory" in f else "package", replace=bad)
        for a, b in zip(path, path[1:]):
            g.edge(a, "AFFECTED_BY" if b == f.get("advisory") else "DEPENDS_ON", b, bad)
        for p in f.get("policies", []):
            if p.get("verdict") == "violated":
                g.edge(end, "violates", p["decision"], True)
    return g


def esc(value) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def code(value) -> str:
    return f"<code>{esc(value)}</code>"


def source_link(url) -> str:
    if isinstance(url, str) and LINK.match(url):
        return f'<a class="source" href="{esc(url)}" rel="noopener noreferrer">{esc(url)}</a>'
    return esc(url)


def dl(rows: list[tuple[str, str]]) -> str:
    return "<dl>" + "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


def steps_html(steps: list[dict]) -> str:
    if not steps:
        return ""
    items = []
    for s in steps:
        ev = f'<div class="evidence">{esc(s["evidence"])}</div>' if s.get("evidence") else ""
        items.append(f'<li>{code(s["source"])} <span class="rel">{esc(s["type"])}</span> {code(s["target"])}{ev}</li>')
    return '<ol class="steps">' + "".join(items) + "</ol>"


def impact_item(item: dict, cls: str = "") -> str:
    rows = [("hops", esc(item.get("hops"))), ("via", code(item.get("via")))]
    if item.get("status"):
        rows.append(("status", esc(item["status"])))
    if item.get("code_ref"):
        rows.append(("code_ref", ", ".join(f"{code(c['ref'])} ({esc(c['match'])})" for c in item["code_ref"])))
    if item.get("superseded_by"):
        rows.append(("superseded by", ", ".join(code(n) for n in item["superseded_by"])))
    kind = esc(item.get("kind")) + (f" {cls}" if cls else "")
    badge = '<span class="badge">superseded</span> ' if cls else ""
    style = ' style="border-style:dashed"' if cls else ""
    return (f'<li class="item {kind}"{style}><div class="head"><span class="badge">{esc(item.get("kind"))}</span> {badge}'
            f'{code(item["id"])}</div><div class="title">{esc(item.get("title"))}</div>{dl(rows)}{steps_html(item.get("path", []))}</li>')


def impact_sections(report: dict) -> list[str]:
    out = [dl([("hops", esc(report.get("hops"))), ("repo", esc(report.get("repo") or "any")), ("loaded", loaded(report))])]
    for r in report.get("impact", []):
        gov = r.get("governing", [])
        body = '<ul class="items">' + "".join(impact_item(i) for i in gov) + "</ul>" if gov else '<p class="none">nothing in the snapshot names this path</p>'
        old = r.get("superseded", [])
        if old:
            body += (f'<h3>Superseded, listed for the record</h3><ul class="items">' + "".join(impact_item(i, "superseded") for i in old) + "</ul>")
        out.append(f"<section><h2>{code(r['path'])}</h2><p>{esc(len(gov))} node(s), matched as {code(r.get('matched_as'))}</p>{body}</section>")
    return out


def loaded(report: dict) -> str:
    counts = report.get("loaded") or {}
    return esc(f"{counts.get('nodes', 0)} nodes, {counts.get('edges', 0)} edges")


def node_line(nid: str, info: dict) -> str:
    n = info.get(nid, {})
    parts = [code(nid)]
    if n.get("title"):
        parts.append(esc(n["title"]))
    if n.get("source"):
        parts.append("source " + source_link(n["source"]))
    return f"<li>{' '.join(parts)}</li>"


def paths_sections(report: dict) -> list[str]:
    info = report.get("nodes", {})
    head = [("loaded", loaded(report))]
    if report.get("source"):
        head = [("from", code(report["source"])), ("to", code(report.get("target")))] + head
    out = [dl(head)]
    if not report.get("paths"):
        out.append('<p class="none">no path within the hop bound</p>')
    for i, p in enumerate(report.get("paths", []), 1):
        nodes = '<ul class="nodes">' + "".join(node_line(n, info) for n in p.get("ids", [])) + "</ul>"
        out.append(f"<section><h2>Path {i}, {esc(len(p.get('rels', [])))} hop(s)</h2>{steps_html(path_steps(p))}{nodes}</section>")
    return out


def finding_rows(f: dict) -> list[tuple[str, str]]:
    tail = [("status", esc(f.get("status"))), ("dev only", esc("yes" if f.get("dev_only") else "no"))]
    if f.get("kind") == "license":
        return [("license", esc(f.get("license_expression") or "none given"))] + tail + [
            ("source", esc(f.get("source_system"))), ("fetched at", esc(f.get("fetched_at")))]
    if f.get("kind") == "package":
        return [("package", esc(f"{f.get('ecosystem')}:{f.get('name')} {f.get('version')}"))] + tail + [
            ("source", esc(f.get("source_system"))), ("fetched at", esc(f.get("fetched_at")))]
    severity = [("severity", esc(f.get("severity")))]
    if f.get("severity_source"):
        severity.append(("severity from", esc(f["severity_source"])))
    return severity + tail + [("source", source_link(f.get("source_url"))), ("fetched at", esc(f.get("fetched_at"))),
                              ("content hash", code(f.get("content_hash")))]


def policy_table(policies: list[dict]) -> str:
    if not policies:
        return ""
    named = any("rule" in p for p in policies)
    rule = lambda p: f'<td>{code(p.get("rule")) if p.get("rule") else ""}</td>' if named else ""
    rows = "".join(f'<tr class="{esc(p.get("verdict"))}"><td>{code(p.get("decision"))}</td>{rule(p)}<td>{esc(p.get("verdict"))}</td>'
                   f'<td>{esc(p.get("why"))}</td></tr>' for p in policies)
    head = "<tr><th>decision</th>" + ("<th>rule</th>" if named else "") + "<th>verdict</th><th>why</th></tr>"
    return f'<div class="scroll"><table>{head}{rows}</table></div>'


def finding_title(f: dict) -> str:
    if f.get("kind") == "license":
        return f"{f['package']} is licensed {f.get('license_expression') or 'with no license the inventory gives'}"
    if f.get("kind") == "package":
        return f"{f['package']} is a package a decision denies"
    return f.get("advisory_summary") or ""


def finding_html(f: dict) -> str:
    chain = " <span class=\"rel\">to</span> ".join(code(n) for n in f.get("path", []))
    bad = violated(f)
    mark = '<span class="badge bad">violates a decision</span> ' if bad else ""
    what = code(f["advisory"]) if "advisory" in f else esc(f"{f.get('kind')} rule")
    return (f'<li class="item{" violated" if bad else ""}"><div class="head">{mark}{code(f["package"])} {what}</div>'
            f'<div class="title">{esc(finding_title(f))}</div>{dl(finding_rows(f))}<p class="chain">{chain}</p>'
            f'{policy_table(f.get("policies", []))}</li>')


def audit_sections(report: dict) -> list[str]:
    meta = report.get("meta") or {}
    summary = report.get("summary") or {}
    head = [("repository", esc(meta.get("repo"))), ("space", esc(meta.get("space"))), ("extracted at", esc(meta.get("extracted_at"))),
            ("lockfile hash", code(meta.get("lockfile_hash"))), ("loaded", loaded(report)),
            ("findings", esc(", ".join(f"{v} {k}" for k, v in summary.items()))), ("violations", esc(report.get("violations", 0)))]
    gov = "".join(f"<li>{code(d['decision'])} {esc(d.get('title'))} via {code(d.get('via'))}</li>" for d in report.get("governing", []))
    items = "".join(finding_html(f) for f in report.get("findings", []))
    notes = "".join(f"<li>{esc(n)}</li>" for n in report.get("inventory_notes") or report.get("notes") or [])
    problems = "".join(f"<li>{code(p['decision'])} {code(p.get('rule') or 'rule')}: {esc(p['problem'])}</li>"
                       for p in report.get("rule_problems", []))
    return [dl(head), *([section("Notes", "<ul>" + notes + "</ul>")] if notes else []),
            section("Governing decisions", "<ul>" + gov + "</ul>" if gov else NONE),
            *([section("Rules that cannot be checked", "<ul>" + problems + "</ul>")] if problems else []),
            section("Findings", '<ul class="items">' + items + "</ul>" if items else NONE)]


def section(heading: str, body: str) -> str:
    return f"<section><h2>{esc(heading)}</h2>{body}</section>"


NONE = '<p class="none">none</p>'

KINDS: dict[str, Kind] = {
    "impact": Kind(lambda r: "Impact: " + ", ".join(i["path"] for i in r.get("impact", [])), impact_graph, impact_sections),
    "paths": Kind(lambda r: f"Paths: {r['source']} to {r['target']}" if r.get("source") else "Paths", paths_graph, paths_sections),
    "audit": Kind(lambda r: f"Audit: {(r.get('meta') or {}).get('repo') or 'repository'}", audit_graph, audit_sections),
}


def kind_of(kind: str) -> Kind:
    if kind not in KINDS:
        raise ValueError(f"no renderer for {kind!r}; known: {', '.join(sorted(KINDS))}")
    return KINDS[kind]


def mermaid(kind: str, report: dict) -> str:
    return "```mermaid\n" + "\n".join(mermaid_lines(kind_of(kind).graph(report))) + "\n```\n"


CSS = """
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;--bad:#b91c1c;--badbg:#fdecec;--accent:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--card:#151b23;--bad:#f87171;--badbg:#2d1214;--accent:#7aa2ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:60rem;margin:0 auto;padding:1rem}
h1{font-size:1.4rem;overflow-wrap:anywhere}
h2{font-size:1.1rem;margin-top:1.5rem;overflow-wrap:anywhere}
code{font:0.9em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
dl{display:grid;grid-template-columns:max-content 1fr;gap:0.2rem 0.8rem;margin:0.5rem 0}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
ul.items{list-style:none;padding:0}
.item{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:0.75rem;margin:0.75rem 0}
.item.violated{border-color:var(--bad);background:var(--badbg)}
.badge{font-size:0.8em;border:1px solid var(--line);border-radius:4px;padding:0 0.3rem;color:var(--muted)}
.badge.bad{border-color:var(--bad);color:var(--bad);font-weight:600}
.title{font-weight:600}
.steps{padding-left:1.4rem}
.rel{color:var(--accent);font-size:0.85em}
.evidence,.none{color:var(--muted)}
.chain{overflow-wrap:anywhere}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{border-top:1px solid var(--line);padding:0.3rem;text-align:left;vertical-align:top}
tr.violated td{color:var(--bad);font-weight:600}
a{color:var(--accent);overflow-wrap:anywhere}
pre{background:var(--card);border:1px solid var(--line);padding:0.5rem;overflow-x:auto}
"""
CSP = "default-src 'none'; style-src 'unsafe-inline'"


def html(kind: str, report: dict) -> str:
    k = kind_of(kind)
    title = k.title(report)
    body = "\n".join(k.sections(report))
    diagram = esc(mermaid(kind, report))
    return ("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            f'<meta http-equiv="Content-Security-Policy" content="{CSP}">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{esc(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n<main>\n"
            f"<h1>{esc(title)}</h1>\n{body}\n"
            f"<details><summary>Mermaid source</summary><pre>{diagram}</pre></details>\n"
            "</main>\n</body>\n</html>\n")


def annotate_paths(report: dict, graph, source: str, target: str) -> dict:
    by_id = {n["id"]: n for n in graph.nodes}
    edges = {(e["source"], e["type"], e["target"]): e.get("evidence") or "" for e in graph.edges}
    paths = []
    for p in report.get("paths", []):
        steps = []
        for a, b, rel in zip(p["ids"], p["ids"][1:], p["rels"]):
            s, t = (a, b) if (a, rel, b) in edges else (b, a)
            steps.append({"source": s, "type": rel, "target": t, "evidence": edges.get((s, rel, t), "")})
        paths.append({**p, "steps": steps})
    ids = {i for p in paths for i in p["ids"]}
    nodes = {i: node_info(by_id[i]) for i in sorted(ids) if i in by_id}
    return {**report, "source": source, "target": target, "nodes": nodes, "paths": paths}


def node_info(node: dict) -> dict:
    props = node.get("props") or {}
    src = next((props[k] for k in ("source_url", "source") if isinstance(props.get(k), str)), "")
    return {"kind": node.get("kind") or "", "title": node.get("title") or "", "source": src}
