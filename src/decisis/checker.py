from __future__ import annotations

import json

from . import audit, semver
from . import commit as wb
from .queries import load as query
from .sandbox import Sandbox, Subgraph

ECOSYSTEM = "npm"


def decisions(vinc: Subgraph) -> set[str]:
    return {n["id"] for n in vinc.nodes if n["kind"] == "decision"}


def _advisories(box, plan: dict) -> dict[str, dict]:
    ids = sorted({f"adv:{n['props']['value']}" for n in plan["nodes"]})
    if not ids:
        return {}
    return {r["advisory"]: r for r in box.query(query("advisory_records"), {"ids": ids})}


def _paths(box, repo: str, depth: int) -> set[tuple]:
    return {tuple(r["path"]) for r in box.query(query("dependency_paths", depth=depth), {"repo": f"repo:{repo}"})}


def check_record(node: dict, edges: list[dict], record: dict | None, found: set[tuple], known: set[str]) -> dict:
    p, problems, checks = node["props"], [], 1
    name = p["entity"].split(":", 1)[1]
    if record is None:
        problems.append(f"advisory {p['value']} is not in the sandbox graph")
    elif record["content_hash"] != p["advisory_content_hash"]:
        problems.append(f"the advisory hash differs from the OSV record of {p['value']}")
    affected = json.loads(record["affected_json"]) if record else []
    for version in p["versions"]:
        checks += 1
        if record is None or semver.affects(version, ECOSYSTEM, name, affected) is not True:
            problems.append(f"{name} {version} is not inside the advisory's affected ranges")
    for path in p["dependency_paths"]:
        checks += 1
        if tuple(path) not in found:
            problems.append("a dependency path is not in the sandbox graph: " + " -> ".join(path))
    for e in edges:
        checks += 1
        if e["to"] not in known:
            problems.append(f"{e['to']} is not a decision in the snapshot")
    return {"record": node["id"], "checks": checks, "problems": problems}


def check_plan(plan: dict, box, known: set[str], repo: str, depth: int = 8) -> list[dict]:
    records = _advisories(box, plan)
    found = _paths(box, repo, depth) if plan["nodes"] else set()
    return [check_record(n, [e for e in plan["edges"] if e["from"] == n["id"]],
                         records.get(f"adv:{n['props']['value']}"), found, known)
            for n in plan["nodes"]]


def withhold(plan: dict, checked: list[dict]) -> dict:
    failed = {c["record"]: c["problems"] for c in checked if c["problems"]}
    if not failed:
        return plan
    kept = {**plan, "nodes": [n for n in plan["nodes"] if n["id"] not in failed],
            "edges": [e for e in plan["edges"] if e["from"] not in failed],
            "held": plan["held"] + [{"record": r, "why": "failed the re-derivation checks", "failed": p}
                                    for r, p in sorted(failed.items())]}
    kept["digest"] = wb.digest(kept)
    return kept


def rederive(plan: dict, vinc: Subgraph, lock_text: str, repo: str, advisories, depth: int = 8,
             root=None) -> tuple[dict, list[dict]]:
    graph = audit.compose(vinc, lock_text, repo, advisories)
    box = Sandbox(root)
    try:
        box.load(graph)
        checked = check_plan(plan, box, decisions(vinc), repo, depth)
    finally:
        box.destroy()
    return withhold(plan, checked), checked
