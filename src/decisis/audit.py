from __future__ import annotations

import datetime
import json
import re

from . import external, init, inventory, rules, semver
from .queries import load as query
from .sandbox import Limits, Subgraph, sandbox

MAX_DEPTH = 16

SEVERITY = rules.SEVERITY
ORDER = {"affected": 0, "unresolved": 1, "not_affected": 2}


def governance_links(vinc_nodes: list[dict], repo: str) -> list[dict]:
    pattern = re.compile(rf"^{re.escape(repo)}(:|$)")
    out = []
    for n in vinc_nodes:
        ref = (n.get("props") or {}).get("code_ref") or ""
        if isinstance(ref, str) and pattern.match(ref):
            out.append({"source": f"repo:{repo}", "target": n["id"], "type": "DESCRIBED_BY",
                        "evidence": f"{n['id']} has code_ref {ref}"})
    return out


def compose(vinc: Subgraph, lock_text: str, repo: str, advisories=external.fetch_advisories, filename: str = "package-lock.json",
            siblings: dict[str, str] | None = None) -> Subgraph:
    pkg_nodes, dep_edges = inventory.read(lock_text, filename, repo, siblings)
    if inventory.advisories(lock_text, filename):
        nothing_to_query(pkg_nodes, filename)
    adv_nodes, adv_edges = advisories(pkg_nodes)
    links = governance_links(vinc.nodes, repo)
    lock_hash = next((n["props"].get("content_hash") for n in pkg_nodes if n["kind"] == "Repository"), "")
    nodes, edges = vinc.nodes + pkg_nodes + adv_nodes, vinc.edges + dep_edges + adv_edges + links
    meta = {**vinc.meta, "nodes": len(nodes), "edges": len(edges), "repo": repo, "lockfile_hash": lock_hash, "packages": sum(1 for n in pkg_nodes if n["kind"] == "Package"),
            "advisories": len(adv_nodes), "governance_links": len(links)}
    return Subgraph(nodes, edges, meta)


def nothing_to_query(pkg_nodes: list[dict], filename: str) -> None:
    pkgs = [n for n in pkg_nodes if n["kind"] == "Package"]
    if not any(external.queryable(n) for n in pkgs):
        first = pkgs[0]
        raise ValueError(f"none of the {len(pkgs)} packages in {filename} can be queried at OSV, so there is nothing to audit "
                         f"({first['id']}: {first['props']['unresolved']})")


def _policy(d: str, verdict: str, why: str, rule: str | None, named: bool) -> dict:
    return {"decision": d, "verdict": verdict, "why": why, **({"rule": rule} if named else {})}


def policies(governing: dict, parsed: rules.Parsed, subject: str, facts: dict, dev: bool, named: bool = False,
             day: datetime.date | None = None) -> list[dict]:
    d, via, day = governing["decision"], governing["via"], day or rules.today()
    if not parsed.stated:
        return [_policy(d, "relevant", f"governs this repository through {via}; it states no machine-checkable rule", None, named)]
    out = [_policy(d, "relevant", f"governs this repository through {via}; its rule cannot be checked: {p.reason}", p.kind, True)
           for p in parsed.problems]
    for rule in rules.judging(parsed, subject):
        judged = rules.waived(rule, facts, dev, parsed.waivers, day)
        out.append({**_policy(d, judged.pop("verdict"), judged.pop("why"), rule.kind, named), **judged})
    return out


def ruled(graph: Subgraph, decisions: list[dict]) -> list[tuple[dict, rules.Parsed]]:
    by_id = {n["id"]: n for n in graph.nodes}
    return [(d, rules.of(by_id.get(d["decision"], {}))) for d in fold(decisions)]


def fold(decisions: list[dict]) -> list[dict]:
    out: dict[str, dict] = {}
    for d in decisions:
        g = out.setdefault(d["decision"], {**d, "via": set()})
        g["via"].add(d["via"])
    return [{**g, "via": ", ".join(sorted(g["via"]))} for g in out.values()]


def verify(rows: list[dict], graph: Subgraph, decisions: list[dict], day: datetime.date | None = None) -> list[dict]:
    by_id = {n["id"]: n for n in graph.nodes}
    governing = ruled(graph, decisions)
    findings = []
    for key, paths in grouped(rows, lambda r: (r["package"], r["advisory"])).items():
        row = {"package": key[0], "advisory": key[1], "path": fitting(paths, graph_dev(by_id), bool(by_id[key[0]]["props"].get("dev")))}
        pkg, adv = by_id[row["package"]]["props"], by_id[row["advisory"]]["props"]
        applies = semver.affects(pkg["version"], pkg["ecosystem"], pkg["name"], json.loads(adv["affected_json"]))
        status = {True: "affected", False: "not_affected", None: "unresolved"}[applies]
        sev = adv.get("severity", "UNKNOWN")
        facts = {"status": status, "severity": sev, "ecosystem": pkg.get("ecosystem") or "", "name": pkg.get("name") or "",
                 "version": pkg.get("version") or "", "advisory": row["advisory"].split(":", 1)[1]}
        found = [p for d, parsed in governing for p in policies(d, parsed, "advisory", facts, bool(pkg.get("dev")), day=day)]
        source = {"severity_source": adv["severity_source"]} if adv.get("severity_source") else {}
        findings.append({"package": row["package"], "advisory": row["advisory"], "severity": sev, **source, "status": status,
                         "dev_only": bool(pkg.get("dev")), "path": row["path"], "source_url": adv.get("source_url"),
                         "fetched_at": adv.get("fetched_at"), "content_hash": adv.get("content_hash"),
                         "advisory_summary": by_id[row["advisory"]].get("title") or "", "policies": found})
    return ordered(findings)


def grouped(rows: list[dict], key) -> dict:
    out: dict = {}
    for r in rows:
        out.setdefault(key(r), []).append(r["path"])
    return out


def graph_dev(by_id: dict[str, dict]):
    return lambda nid: (by_id.get(nid) or {}).get("kind") == "Package" and bool(by_id[nid]["props"].get("dev"))


def fitting(paths: list[list[str]], is_dev, dev_only: bool) -> list[str]:
    if dev_only:
        return paths[0]
    return next((p for p in paths if not any(is_dev(x) for x in p[1:])), paths[0])


def ordered(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (ORDER[f["status"]], -SEVERITY.index(f["severity"]) if f.get("severity") in SEVERITY else 0,
                                           len(f["path"])))


def status_of(governing: list[tuple[dict, rules.Parsed]], subject: str, facts: dict) -> str | None:
    seen = {rules.outcome(r, facts)[0] for _, parsed in governing for r in rules.judging(parsed, subject)}
    return "affected" if rules.MATCH in seen else "unresolved" if rules.UNKNOWN in seen else None


def _subject_fields(subject: str, props: dict) -> dict:
    if subject == "license":
        return {"ecosystem": props.get("ecosystem") or "", "license_expression": props.get("license_expression") or "",
                "licenses": list(props.get("licenses") or [])}
    return {"ecosystem": props.get("ecosystem") or "", "name": props.get("name") or "", "version": props.get("version") or ""}


def package_finding(node: dict, subject: str, governing: list[tuple[dict, rules.Parsed]], day: datetime.date | None = None) -> dict | None:
    props = node["props"]
    status = status_of(governing, subject, props)
    if status is None:
        return None
    dev = bool(props.get("dev"))
    found = [p for d, parsed in governing for p in policies(d, parsed, subject, props, dev, named=True, day=day)]
    return {"kind": subject, "package": node["id"], **_subject_fields(subject, props), "status": status, "dev_only": dev,
            "path": [], "source_system": props.get("source_system"), "fetched_at": props.get("fetched_at"), "policies": found}


def package_findings(graph: Subgraph, decisions: list[dict], repo: str, depth: int, day: datetime.date | None = None) -> list[dict]:
    governing = ruled(graph, decisions)
    wanted = [s for s in rules.PACKAGE_SUBJECTS if any(rules.judging(p, s) for _, p in governing)]
    packages = sorted((n for n in graph.nodes if n["kind"] == "Package"), key=lambda n: n["id"])
    found = [f for n in packages for s in wanted if (f := package_finding(n, s, governing, day)) is not None]
    if not found:
        return []
    dev = graph_dev({n["id"]: n for n in graph.nodes})
    paths = package_paths(graph, f"repo:{repo}", {f["package"] for f in found}, depth, dev)
    return [{**f, "path": fitting(paths[f["package"]], dev, f["dev_only"])} for f in found if f["package"] in paths]


def package_paths(graph: Subgraph, start: str, wanted: set[str], depth: int, is_dev) -> dict[str, list[list[str]]]:
    after: dict[str, list[str]] = {}
    for e in graph.edges:
        if e["type"] == "DEPENDS_ON":
            after.setdefault(e["source"], []).append(e["target"])
    after = {s: sorted(set(t)) for s, t in after.items()}
    out: dict[str, list[list[str]]] = {}
    for allowed in (lambda nid: True, lambda nid: not is_dev(nid)):
        for pkg, path in shortest(after, start, wanted, depth, allowed).items():
            if path not in out.setdefault(pkg, []):
                out[pkg].append(path)
    return out


def shortest(after: dict[str, list[str]], start: str, wanted: set[str], depth: int, allowed) -> dict[str, list[str]]:
    parent: dict[str, str | None] = {start: None}
    level, found = [start], {}
    for _ in range(depth):
        nxt = []
        for node in level:
            for t in after.get(node, []):
                if t not in parent and allowed(t):
                    parent[t] = node
                    nxt.append(t)
                    if t in wanted:
                        found[t] = route(parent, t)
        if not nxt or len(found) == len(wanted):
            break
        level = nxt
    return found


def route(parent: dict[str, str | None], end: str) -> list[str]:
    out = [end]
    while (up := parent[out[-1]]) is not None:
        out.append(up)
    return out[::-1]


def rule_problems(graph: Subgraph, decisions: list[dict]) -> list[dict]:
    return [{"decision": d["decision"], "rule": p.kind, "problem": p.reason} for d, parsed in ruled(graph, decisions)
            for p in parsed.problems + parsed.waiver_problems]


def counted(findings: list[dict], verdict: str) -> int:
    return sum(1 for f in findings for p in f["policies"] if p["verdict"] == verdict)


def analyze(box, graph: Subgraph, repo: str, depth: int = 8, day: datetime.date | None = None) -> dict:
    if not 1 <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_DEPTH}")
    counts = box.load(graph)
    rows = box.query(query("dependency_paths", depth=depth), {"repo": f"repo:{repo}"})
    decisions = box.query(query("governing_decisions"), {"repo": f"repo:{repo}"})
    day = day or rules.today()
    findings = ordered(verify(rows, graph, decisions, day) + package_findings(graph, decisions, repo, depth, day))
    summary = {s: sum(1 for f in findings if f["status"] == s) for s in ("affected", "unresolved", "not_affected")}
    return {"meta": graph.meta, "loaded": counts, "today": day.isoformat(), "governing": decisions, "summary": summary,
            "violations": counted(findings, "violated"), "waived": counted(findings, rules.WAIVED), "findings": findings,
            "unresolved_packages": unresolved_packages(graph), "inventory_notes": inventory_notes(graph, repo),
            **problems_of(graph, decisions)}


def problems_of(graph: Subgraph, decisions: list[dict]) -> dict:
    found, unread = rule_problems(graph, decisions), init.unread_decisions(graph.meta)
    return {**({"rule_problems": found} if found else {}), **({"unread_decisions": unread} if unread else {})}


def inventory_notes(graph: Subgraph, repo: str) -> list[str]:
    return next((list(n["props"].get("inventory_notes") or []) for n in graph.nodes if n["id"] == f"repo:{repo}"), [])


def unresolved_packages(graph: Subgraph) -> list[dict]:
    return [{"package": n["id"], "reason": n["props"]["unresolved"]} for n in sorted(graph.nodes, key=lambda n: n["id"])
            if n["kind"] == "Package" and (n.get("props") or {}).get("unresolved")]


def run(vinc: Subgraph, lock_text: str, repo: str, depth: int = 8, advisories=external.fetch_advisories,
        limits: Limits | None = None, filename: str = "package-lock.json", siblings: dict[str, str] | None = None,
        root=None, day: datetime.date | None = None) -> dict:
    graph = compose(vinc, lock_text, repo, advisories, filename, siblings)
    with sandbox(root, limits) as box:
        report = analyze(box, graph, repo, depth, day)
    extra = [n for n in inventory.notes(lock_text, filename) if n not in report["inventory_notes"]]
    return {**report, "inventory_notes": report["inventory_notes"] + extra}
