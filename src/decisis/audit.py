from __future__ import annotations

import json
import re

from . import external, inventory, semver
from .queries import load as query
from .sandbox import Limits, Subgraph, sandbox

MAX_DEPTH = 16

SEVERITY = ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]



def governance_links(vinc_nodes: list[dict], repo: str) -> list[dict]:
    pattern = re.compile(rf"^{re.escape(repo)}(:|$)")
    out = []
    for n in vinc_nodes:
        ref = (n.get("props") or {}).get("code_ref") or ""
        if isinstance(ref, str) and pattern.match(ref):
            out.append({"source": f"repo:{repo}", "target": n["id"], "type": "DESCRIBED_BY",
                        "evidence": f"{n['id']} has code_ref {ref}"})
    return out


def rule_of(decision: dict) -> dict | None:
    rule = (decision.get("props") or {}).get("rule")
    if isinstance(rule, str):
        try:
            rule = json.loads(rule)
        except json.JSONDecodeError:
            return None
    return rule if isinstance(rule, dict) and rule.get("advisory_severity_at_least") in SEVERITY else None


def compose(vinc: Subgraph, lock_text: str, repo: str, advisories=external.fetch_advisories, filename: str = "package-lock.json",
            siblings: dict[str, str] | None = None) -> Subgraph:
    pkg_nodes, dep_edges = inventory.read(lock_text, filename, repo, siblings)
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


def judge(governing: dict, rule: dict | None, status: str, severity: str, dev: bool) -> dict:
    d = governing["decision"]
    if rule is None:
        return {"decision": d, "verdict": "relevant", "why": f"governs this repository through {governing['via']}; it states no machine-checkable rule"}
    if rule.get("dependencies") == "shipped" and dev:
        return {"decision": d, "verdict": "not_violated", "why": "reached only through development dependencies; the rule covers shipped ones"}
    if status == "affected" and severity in SEVERITY and SEVERITY.index(severity) >= SEVERITY.index(rule["advisory_severity_at_least"]):
        return {"decision": d, "verdict": "violated", "why": f"severity {severity} is at or above {rule['advisory_severity_at_least']}"}
    return {"decision": d, "verdict": "not_violated", "why": f"status {status}, severity {severity}"}


def fold(decisions: list[dict]) -> list[dict]:
    out: dict[str, dict] = {}
    for d in decisions:
        g = out.setdefault(d["decision"], {**d, "via": set()})
        g["via"].add(d["via"])
    return [{**g, "via": ", ".join(sorted(g["via"]))} for g in out.values()]


def verify(rows: list[dict], graph: Subgraph, decisions: list[dict]) -> list[dict]:
    by_id = {n["id"]: n for n in graph.nodes}
    rules = [(d, rule_of(by_id.get(d["decision"], {}))) for d in fold(decisions)]
    findings, seen = [], set()
    for row in rows:
        key = (row["package"], row["advisory"])
        if key in seen:
            continue
        seen.add(key)
        pkg, adv = by_id[row["package"]]["props"], by_id[row["advisory"]]["props"]
        applies = semver.affects(pkg["version"], pkg["ecosystem"], pkg["name"], json.loads(adv["affected_json"]))
        status = {True: "affected", False: "not_affected", None: "unresolved"}[applies]
        sev = adv.get("severity", "UNKNOWN")
        policies = [judge(d, rule, status, sev, bool(pkg.get("dev"))) for d, rule in rules]
        findings.append({"package": row["package"], "advisory": row["advisory"], "severity": sev, "status": status,
                         "dev_only": bool(pkg.get("dev")), "path": row["path"], "source_url": adv.get("source_url"),
                         "fetched_at": adv.get("fetched_at"), "content_hash": adv.get("content_hash"),
                         "advisory_summary": by_id[row["advisory"]].get("title") or "", "policies": policies})
    order = {"affected": 0, "unresolved": 1, "not_affected": 2}
    return sorted(findings, key=lambda f: (order[f["status"]], -SEVERITY.index(f["severity"]) if f["severity"] in SEVERITY else 0, len(f["path"])))


def analyze(box, graph: Subgraph, repo: str, depth: int = 8) -> dict:
    if not 1 <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_DEPTH}")
    counts = box.load(graph)
    rows = box.query(query("dependency_paths", depth=depth), {"repo": f"repo:{repo}"})
    decisions = box.query(query("governing_decisions"), {"repo": f"repo:{repo}"})
    findings = verify(rows, graph, decisions)
    summary = {s: sum(1 for f in findings if f["status"] == s) for s in ("affected", "unresolved", "not_affected")}
    return {"meta": graph.meta, "loaded": counts, "governing": decisions, "summary": summary,
            "violations": sum(1 for f in findings for p in f["policies"] if p["verdict"] == "violated"), "findings": findings,
            "unresolved_packages": unresolved_packages(graph), "inventory_notes": inventory_notes(graph, repo)}


def inventory_notes(graph: Subgraph, repo: str) -> list[str]:
    return next((list(n["props"].get("inventory_notes") or []) for n in graph.nodes if n["id"] == f"repo:{repo}"), [])


def unresolved_packages(graph: Subgraph) -> list[dict]:
    return [{"package": n["id"], "reason": n["props"]["unresolved"]} for n in sorted(graph.nodes, key=lambda n: n["id"])
            if n["kind"] == "Package" and (n.get("props") or {}).get("unresolved")]


def run(vinc: Subgraph, lock_text: str, repo: str, depth: int = 8, advisories=external.fetch_advisories,
        limits: Limits | None = None, filename: str = "package-lock.json", siblings: dict[str, str] | None = None,
        root=None) -> dict:
    graph = compose(vinc, lock_text, repo, advisories, filename, siblings)
    with sandbox(root, limits) as box:
        report = analyze(box, graph, repo, depth)
    extra = [n for n in inventory.notes(lock_text, filename) if n not in report["inventory_notes"]]
    return {**report, "inventory_notes": report["inventory_notes"] + extra}
