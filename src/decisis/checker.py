from __future__ import annotations

import json

from . import audit, rules, semver
from . import commit as wb
from .queries import load as query
from .sandbox import Limits, Sandbox, Subgraph

SUBJECT = {"licensed_under": "license", "uses_denied_package": "package", "uses_unlisted_package": "allowlist",
           "not_pinned_to_commit": "pin"}


def decisions(vinc: Subgraph) -> dict[str, dict]:
    return {n["id"]: n for n in vinc.nodes if n["kind"] == "decision"}


def subject(node: dict) -> str:
    return SUBJECT.get(node["props"].get("predicate"), "advisory")


def _name(node: dict) -> str:
    return node["props"]["entity"].split(":", 1)[1]


def _ends(node: dict) -> set[str]:
    tail = 2 if subject(node) == "advisory" else 1
    return {path[-tail] for path in node["props"]["dependency_paths"] if len(path) >= tail}


def _package(name: str, version: str, facts: dict, ends: set[str], ecosystem: str | None = None) -> dict | None:
    found = [r for r in facts["packages"].values() if r["name"] == name and r["version"] == version
             and (ecosystem is None or r["ecosystem"] == ecosystem)]
    return next((r for r in found if r["package"] in ends), found[0] if found else None)


def _own(node: dict, facts: dict) -> set[str]:
    ecosystem = None if subject(node) == "advisory" else node["props"].get("ecosystem") or ""
    rows = [_package(_name(node), v, facts, _ends(node), ecosystem) for v in node["props"]["versions"]]
    return {r["package"] for r in rows if r is not None}


def _facts(box, graph: Subgraph, plan: dict, repo: str, depth: int) -> dict:
    advisories = sorted({f"adv:{n['props']['value']}" for n in plan["nodes"] if subject(n) == "advisory"})
    names = sorted({_name(n) for n in plan["nodes"]})
    on_paths = sorted({x for n in plan["nodes"] for path in n["props"]["dependency_paths"] for x in path})
    packages = box.query(query("packages_named"), {"names": names}) + box.query(query("package_records"), {"ids": on_paths})
    steps = sorted({x for n in plan["nodes"] if subject(n) != "advisory" for path in n["props"]["dependency_paths"] for x in path[1:]})
    governing = audit.governing(box, graph, repo)
    return {"repo": f"repo:{repo}",
            "governing": {r["decision"] for r in governing},
            "idle": audit.idle(graph, governing, repo),
            "advisories": {r["advisory"]: r for r in box.query(query("advisory_records"), {"ids": advisories})},
            "packages": {r["package"]: r for r in packages},
            "paths": {tuple(r["path"]) for r in box.query(query("dependency_paths", depth=depth), {"repo": f"repo:{repo}"})},
            "depth": depth,
            "package_edges": {(r["source"], r["target"]) for r in box.query(query("dependency_edges"), {"ids": steps})} if steps else set()}


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
    return _scope(path[1:-1], p, facts, shown)


def _scope(steps: list[str], p: dict, facts: dict, shown: str) -> list[str]:
    dev = [bool((facts["packages"].get(x) or {}).get("dev")) for x in steps]
    if not (dev[-1] if p["scope"] == "development" else p["scope"] == "shipped" and not any(dev)):
        return [f"a dependency path does not match scope {p['scope']}: {shown}"]
    return []


def _package_path(path: list[str], p: dict, own: set[str], facts: dict) -> list[str]:
    shown = " -> ".join(path)
    if len(path) < 2 or path[0] != facts["repo"] or path[-1] not in own:
        return [f"a dependency path does not run from {facts['repo']} to this record's package: {shown}"]
    if not _walk(path, facts):
        return [f"a dependency path is not in the sandbox graph: {shown}"]
    return _scope(path[1:], p, facts, shown)


def _walk(path: list[str], facts: dict) -> bool:
    steps = list(zip(path, path[1:]))
    return len(steps) <= facts["depth"] and len(set(steps)) == len(steps) and all(s in facts["package_edges"] for s in steps)


def _claimed(kind: str, name: str, version: str, pkg: dict, value: str) -> list[str]:
    if kind == "license" and (pkg.get("license_expression") or "") != value:
        return [f"{name} {version} is licensed {pkg.get('license_expression') or 'with no license'} in the inventory, not {value}"]
    if kind != "license" and f"{pkg.get('ecosystem')}:{pkg.get('name')}" != value:
        return [f"{name} {version} is {pkg.get('ecosystem')}:{pkg.get('name')} in the inventory, not {value}"]
    return []


def _forbids(decision: dict | None, kind: str, pkg: dict, dev: bool) -> bool:
    judged = rules.judging(rules.of(decision or {}), kind)
    return any(rules.verdict(r, pkg, dev)[0] == "violated" for r in judged)


def _package_version(node: dict, version: str, facts: dict, decided: dict[str, dict]) -> list[str]:
    p, name, kind = node["props"], _name(node), subject(node)
    pkg = _package(name, version, facts, _ends(node), p.get("ecosystem") or "")
    if pkg is None:
        return [f"{p.get('ecosystem')} {name} {version} is not a package in the lockfile"]
    out = _claimed(kind, name, version, pkg, p["value"])
    if pkg["package"] not in _ends(node):
        out.append(f"no dependency path of this record reaches {name} {version}")
    dev = p["scope"] == "development"
    out += [f"{d} has no {kind} rule that {name} {version} violates" for d in p["violates"] + p.get("waived", [])
            if not _forbids(decided.get(d), kind, pkg, dev)]
    return out


def _cited(node: dict, edges: list[dict], facts: dict, known) -> list[str]:
    p = node["props"]
    out = []
    for d in sorted({*p.get("violates", []), *p.get("waived", []), *(e["to"] for e in edges)}):
        if d not in known:
            out.append(f"{d} is not a decision in the snapshot")
        elif d not in facts["governing"]:
            out.append(f"{d} does not govern {facts['repo']}: {facts['idle'][d]}")
    return out


def check_package_record(node: dict, edges: list[dict], facts: dict, decided: dict[str, dict]) -> dict:
    p, own = node["props"], _own(node, facts)
    problems = []
    for version in p["versions"]:
        problems += _package_version(node, version, facts, decided)
    for path in p["dependency_paths"]:
        problems += _package_path(path, p, own, facts)
    problems += _cited(node, edges, facts, decided)
    checks = len(p["versions"]) * (2 + len(p["violates"]) + len(p.get("waived", []))) + len(p["dependency_paths"]) + len(edges)
    return {"record": node["id"], "checks": checks, "problems": problems}


def check_record(node: dict, edges: list[dict], facts: dict, known) -> dict:
    if subject(node) != "advisory":
        return check_package_record(node, edges, facts, known)
    p, name, own, ends = node["props"], _name(node), _own(node, facts), _ends(node)
    record = facts["advisories"].get(f"adv:{p['value']}")
    problems = _advisory(p, record)
    for version in p["versions"]:
        problems += _version(name, version, record, facts, ends)
    for path in p["dependency_paths"]:
        problems += _path(path, p, own, facts)
    problems += _cited(node, edges, facts, known)
    checks = 1 + len(p["versions"]) + len(p["dependency_paths"]) + len(edges)
    return {"record": node["id"], "checks": checks, "problems": problems}


def check_plan(plan: dict, box, graph: Subgraph, repo: str, depth: int = 8) -> list[dict]:
    if not plan["nodes"]:
        return []
    facts, known = _facts(box, graph, plan, repo, depth), decisions(graph)
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
             root=None, limits: Limits | None = None, filename: str = "package-lock.json",
             siblings: dict[str, str] | None = None) -> tuple[dict, list[dict]]:
    graph = audit.compose(vinc, lock_text, repo, advisories, filename, siblings)
    box = Sandbox(root, limits)
    try:
        box.load(graph)
        checked = check_plan(plan, box, graph, repo, depth)
    finally:
        box.destroy()
    return withhold(plan, checked), checked
