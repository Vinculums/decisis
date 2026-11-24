from __future__ import annotations

import json

from . import audit, semver
from . import commit as wb
from .queries import load as query
from .sandbox import Sandbox, Subgraph

def decisions(vinc: Subgraph) -> set[str]:
    return {n["id"] for n in vinc.nodes if n["kind"] == "decision"}


def _name(node: dict) -> str:
    return node["props"]["entity"].split(":", 1)[1]


def _ends(node: dict) -> set[str]:
    return {path[-2] for path in node["props"]["dependency_paths"] if len(path) > 1}


def _package(name: str, version: str, facts: dict, ends: set[str]) -> dict | None:
    found = [r for r in facts["packages"].values() if r["name"] == name and r["version"] == version]
    return next((r for r in found if r["package"] in ends), found[0] if found else None)


def _own(node: dict, facts: dict) -> set[str]:
    rows = [_package(_name(node), v, facts, _ends(node)) for v in node["props"]["versions"]]
    return {r["package"] for r in rows if r is not None}


def _facts(box, plan: dict, repo: str, depth: int) -> dict:
    advisories = sorted({f"adv:{n['props']['value']}" for n in plan["nodes"]})
    names = sorted({_name(n) for n in plan["nodes"]})
    on_paths = sorted({x for n in plan["nodes"] for path in n["props"]["dependency_paths"] for x in path})
    packages = box.query(query("packages_named"), {"names": names}) + box.query(query("package_records"), {"ids": on_paths})
    return {"repo": f"repo:{repo}",
            "advisories": {r["advisory"]: r for r in box.query(query("advisory_records"), {"ids": advisories})},
            "packages": {r["package"]: r for r in packages},
            "paths": {tuple(r["path"]) for r in box.query(query("dependency_paths", depth=depth), {"repo": f"repo:{repo}"})}}


def _advisory(p: dict, record: dict | None) -> list[str]:
    if record is None:
        return [f"advisory {p['value']} is not in the sandbox graph"]
    out = []
    if record["content_hash"] != p["advisory_content_hash"]:
        out.append(f"the advisory hash differs from the OSV record of {p['value']}")
    if record["severity"] != p["severity"]:
        out.append(f"severity {p['severity']} differs from the OSV record's severity {record['severity']}")
    return out


def _version(name: str, version: str, record: dict | None, facts: dict, ends: set[str]) -> list[str]:
    pkg, out = _package(name, version, facts, ends), []
    if pkg is None:
        out.append(f"{name} {version} is not a package in the lockfile")
    if pkg is None or record is None or semver.affects(version, pkg["ecosystem"], name, json.loads(record["affected_json"])) is not True:
        out.append(f"{name} {version} is not inside the advisory's affected ranges")
    if pkg is None or pkg["package"] not in ends:
        out.append(f"no dependency path of this record reaches {name} {version}")
    return out


def _path(path: list[str], p: dict, own: set[str], facts: dict) -> list[str]:
    shown = " -> ".join(path)
    if len(path) < 3 or path[0] != facts["repo"] or path[-1] != f"adv:{p['value']}" or path[-2] not in own:
        return [f"a dependency path does not run from {facts['repo']} to this record's package and advisory: {shown}"]
    if tuple(path) not in facts["paths"]:
        return [f"a dependency path is not in the sandbox graph: {shown}"]
    dev = [bool((facts["packages"].get(x) or {}).get("dev")) for x in path[1:-1]]
    if not (dev[-1] if p["scope"] == "development" else p["scope"] == "shipped" and not any(dev)):
        return [f"a dependency path does not match scope {p['scope']}: {shown}"]
    return []


def check_record(node: dict, edges: list[dict], facts: dict, known: set[str]) -> dict:
    p, name, own, ends = node["props"], _name(node), _own(node, facts), _ends(node)
    record = facts["advisories"].get(f"adv:{p['value']}")
    problems = _advisory(p, record)
    for version in p["versions"]:
        problems += _version(name, version, record, facts, ends)
    for path in p["dependency_paths"]:
        problems += _path(path, p, own, facts)
    problems += [f"{e['to']} is not a decision in the snapshot" for e in edges if e["to"] not in known]
    checks = 1 + len(p["versions"]) + len(p["dependency_paths"]) + len(edges)
    return {"record": node["id"], "checks": checks, "problems": problems}


def check_plan(plan: dict, box, known: set[str], repo: str, depth: int = 8) -> list[dict]:
    if not plan["nodes"]:
        return []
    facts = _facts(box, plan, repo, depth)
    return [check_record(n, [e for e in plan["edges"] if e["from"] == n["id"]], facts, known) for n in plan["nodes"]]


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
             root=None, filename: str = "package-lock.json", siblings: dict[str, str] | None = None) -> tuple[dict, list[dict]]:
    graph = audit.compose(vinc, lock_text, repo, advisories, filename, siblings)
    box = Sandbox(root)
    try:
        box.load(graph)
        checked = check_plan(plan, box, decisions(vinc), repo, depth)
    finally:
        box.destroy()
    return withhold(plan, checked), checked
