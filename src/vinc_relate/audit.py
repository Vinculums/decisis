from __future__ import annotations

import json
import re

from . import external, semver
from .queries import load as query
from .sandbox import Subgraph, sandbox

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


def compose(vinc: Subgraph, lock_text: str, repo: str, advisories=external.fetch_advisories) -> Subgraph:
    pkg_nodes, dep_edges = external.parse_npm_lock(lock_text, repo)
    adv_nodes, adv_edges = advisories(pkg_nodes)
    links = governance_links(vinc.nodes, repo)
    meta = {**vinc.meta, "repo": repo, "packages": sum(1 for n in pkg_nodes if n["kind"] == "Package"),
            "advisories": len(adv_nodes), "governance_links": len(links)}
    return Subgraph(vinc.nodes + pkg_nodes + adv_nodes, vinc.edges + dep_edges + adv_edges + links, meta)


def verify(rows: list[dict], graph: Subgraph, decisions: list[dict]) -> list[dict]:
    by_id = {n["id"]: n for n in graph.nodes}
    rules = [(d, rule_of(by_id.get(d["decision"], {}))) for d in decisions]
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
        policies = []
        for d, rule in rules:
            if rule is None:
                policies.append({"decision": d["decision"], "verdict": "relevant", "why": f"governs this repository through {d['via']}; it states no machine-checkable rule"})
            elif rule.get("dependencies") == "shipped" and pkg.get("dev"):
                policies.append({"decision": d["decision"], "verdict": "not_violated", "why": "reached only through development dependencies; the rule covers shipped ones"})
            elif status == "affected" and sev in SEVERITY and SEVERITY.index(sev) >= SEVERITY.index(rule["advisory_severity_at_least"]):
                policies.append({"decision": d["decision"], "verdict": "violated", "why": f"severity {sev} is at or above {rule['advisory_severity_at_least']}"})
            else:
                policies.append({"decision": d["decision"], "verdict": "not_violated", "why": f"status {status}, severity {sev}"})
        findings.append({"package": row["package"], "advisory": row["advisory"], "severity": sev, "status": status,
                         "dev_only": bool(pkg.get("dev")), "path": row["path"], "source_url": adv.get("source_url"), "policies": policies})
    order = {"affected": 0, "unresolved": 1, "not_affected": 2}
    return sorted(findings, key=lambda f: (order[f["status"]], -SEVERITY.index(f["severity"]) if f["severity"] in SEVERITY else 0, len(f["path"])))


def run(vinc: Subgraph, lock_text: str, repo: str, depth: int = 8, advisories=external.fetch_advisories) -> dict:
    graph = compose(vinc, lock_text, repo, advisories)
    with sandbox() as box:
        counts = box.load(graph)
        rows = box.query(query("dependency_paths", depth=depth), {"repo": f"repo:{repo}"})
        decisions = box.query(query("governing_decisions"), {"repo": f"repo:{repo}"})
    findings = verify(rows, graph, decisions)
    summary = {s: sum(1 for f in findings if f["status"] == s) for s in ("affected", "unresolved", "not_affected")}
    return {"meta": graph.meta, "loaded": counts, "governing": decisions, "summary": summary,
            "violations": sum(1 for f in findings for p in f["policies"] if p["verdict"] == "violated"), "findings": findings}
