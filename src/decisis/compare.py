from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from pathlib import Path

from . import audit, external, impact, rules, semver
from . import checkout as co
from .queries import load as query
from .sandbox import Subgraph, sandbox

METHODS = ("A", "B", "C")
GOVERNING = ("decision", "record")


def load_inputs(root: Path, doc: dict) -> dict:
    read = lambda p: (root / p).read_text(encoding="utf-8")
    a, i = doc["inputs"]["audit"], doc["inputs"]["impact"]
    snaps = [co.load(read(p)) for p in i["snapshots"]]
    return {"repo": doc["repo"], "vinc": co.load(read(a["snapshot"])), "lock": read(a["lockfile"]),
            "cache": external.read_osv_cache(read(a["osv_cache"])), "hops": int(i["hops"]),
            "impact": Subgraph([n for s in snaps for n in s.nodes], [e for s in snaps for e in s.edges], {})}


def _step(s: str, rel: str, t: str) -> list[str]:
    return [s, rel, t]


def _claim(kind: str, key: list, evidence: list[list[str]], start: str, end: str) -> dict:
    return {"type": kind, "key": key, "evidence": evidence, "from": start, "to": end}


def _path_steps(ids: list[str], rels: list[str]) -> list[list[str]]:
    return [_step(a, r, b) for a, r, b in zip(ids, rels, ids[1:])]


def governing(vinc: Subgraph, repo: str) -> list[dict]:
    by_id = {n["id"]: n for n in vinc.nodes}
    out = []
    for link in audit.governance_links(vinc.nodes, repo):
        concept = link["target"]
        for e in vinc.edges:
            if e["target"] == concept and by_id.get(e["source"], {}).get("kind") == "decision":
                out.append({"decision": e["source"], "via": concept, "rule": rules.of(by_id[e["source"]]),
                            "evidence": [_step(link["source"], "DESCRIBED_BY", concept), _step(e["source"], e["type"], concept)]})
    return audit.fold(sorted(out, key=lambda d: (d["decision"], d["via"], d["evidence"])))


def _policy_claims(pkg: str, adv: str, status: str, severity: str, dev: bool, gov: list[dict], path_steps: list[list[str]]) -> list[dict]:
    out = []
    for d in gov:
        for p in audit.policies(d, d["rule"], "advisory", {"status": status, "severity": severity}, dev):
            out.append(_claim("policy_link", [pkg, adv, d["decision"], p["verdict"]], d["evidence"] + path_steps, d["decision"], adv))
    return out


def anchors(graph: Subgraph, subject: str, repo: str) -> list[str]:
    want = impact.code_path(subject)
    out = []
    for n in graph.nodes:
        paths = {impact.code_path(r, repo) for r in impact.refs_of(n)}
        if any(p and impact.match_kind(p, want) for p in paths):
            out.append(n["id"])
    return sorted(out)


def method_a_impact(inp: dict, subject: str) -> list[dict]:
    graph = inp["impact"]
    kind = {n["id"]: n["kind"] for n in graph.nodes}
    claims, seen = [], set()
    for anchor in anchors(graph, subject, inp["repo"]):
        for e in sorted(graph.edges, key=lambda e: (e["source"], e["type"], e["target"])):
            other = e["target"] if e["source"] == anchor else e["source"] if e["target"] == anchor else None
            if other is None or kind.get(other) not in GOVERNING or other in seen:
                continue
            seen.add(other)
            steps = [_step(e["source"], e["type"], e["target"])]
            claims.append(_claim("path", [anchor, other], steps, anchor, other))
            claims.append(_claim("policy_link", [subject, other], steps, anchor, other))
    return claims


def method_c_impact(inp: dict, subject: str) -> list[dict]:
    report = impact.run(inp["impact"], [subject], inp["hops"], inp["repo"])
    claims = []
    for g in report["impact"][0]["governing"]:
        if g["kind"] not in GOVERNING:
            continue
        steps = [_step(s["source"], s["type"], s["target"]) for s in g["path"]]
        claims.append(_claim("path", g["nodes"], steps, g["nodes"][0], g["id"]))
        claims.append(_claim("policy_link", [subject, g["id"]], steps, g["nodes"][0], g["id"]))
    return claims


def _pkg_of(subject: str) -> tuple[str, str]:
    name, version = subject.split("/", 1)[1].rsplit("@", 1)
    return name, version


def method_a_audit(inp: dict, subject: str) -> list[dict]:
    name, version = _pkg_of(subject)
    gov = governing(inp["vinc"], inp["repo"])
    claims = []
    for n in inp["vinc"].nodes:
        p = n.get("props") or {}
        if n["kind"] != "record" or p.get("entity") != f"npm:{name}" or version not in (p.get("versions") or []):
            continue
        adv = f"adv:{p.get('value')}"
        claims.append(_claim("finding", [subject, adv, "affected"], [], subject, adv))
        claims += _policy_claims(subject, adv, "affected", str(p.get("severity", "UNKNOWN")), p.get("scope") == "development", gov, [])
    return claims


def text_records(lock_text: str) -> tuple[set[str], list[dict]]:
    pkgs = json.loads(lock_text)["packages"]
    root = pkgs.get("", {})
    direct = set(root.get("dependencies") or {}) | set(root.get("devDependencies") or {})
    records = []
    for path, meta in sorted(pkgs.items()):
        if not path or not meta.get("version"):
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        records.append({"id": external.package_id("npm", name, meta["version"]), "name": name, "version": meta["version"],
                        "dev": bool(meta.get("dev")), "requires": sorted({**(meta.get("dependencies") or {}), **(meta.get("optionalDependencies") or {})})})
    return direct, records


def method_b_audit(inp: dict, subject: str) -> list[dict]:
    repo_id = f"repo:{inp['repo']}"
    direct, records = text_records(inp["lock"])
    rec = next((r for r in records if r["id"] == subject), None)
    if rec is None:
        return []
    gov = governing(inp["vinc"], inp["repo"])
    claims = []
    for vid, v in sorted(inp["cache"]["vulns"].items()):
        named = [a for a in v.get("affected") or [] if (a.get("package") or {}).get("name") == rec["name"]
                 and ((a.get("package") or {}).get("ecosystem") or "").lower() == "npm"]
        if not named:
            continue
        adv = f"adv:{vid}"
        applies = semver.affects(rec["version"], "npm", rec["name"], named)
        status = {True: "affected", False: "not_affected", None: "unresolved"}[applies]
        severity = ((v.get("database_specific") or {}).get("severity") or "UNKNOWN").upper()
        hit = [_step(subject, "AFFECTED_BY", adv)]
        claims.append(_claim("finding", [subject, adv, status], hit, subject, adv))
        paths = []
        if rec["name"] in direct:
            paths.append([repo_id, subject, adv])
        for parent in records:
            if rec["name"] in parent["requires"] and parent["name"] in direct:
                paths.append([repo_id, parent["id"], subject, adv])
        for ids in paths:
            steps = _path_steps(ids, ["DEPENDS_ON"] * (len(ids) - 2) + ["AFFECTED_BY"])
            claims.append(_claim("path", ids, steps, repo_id, adv))
        first = _path_steps(paths[0], ["DEPENDS_ON"] * (len(paths[0]) - 2) + ["AFFECTED_BY"]) if paths else hit
        claims += _policy_claims(subject, adv, status, severity, rec["dev"], gov, first)
    return claims


def method_c_audit(inp: dict, subject: str) -> list[dict]:
    repo, repo_id = inp["repo"], f"repo:{inp['repo']}"
    graph = audit.compose(inp["vinc"], inp["lock"], repo, external.cached_advisories(inp["cache"]))
    with sandbox() as box:
        box.load(graph)
        rows = box.query(query("dependency_paths", depth=8), {"repo": repo_id})
        decisions = box.query(query("governing_decisions"), {"repo": repo_id})
    rows = [r for r in rows if r["package"] == subject]
    by_rule = {d["decision"]: d for d in governing(inp["vinc"], repo)}
    gov = [by_rule[d["decision"]] for d in sorted(audit.fold(decisions), key=lambda d: d["decision"]) if d["decision"] in by_rule]
    claims = []
    for f in audit.verify(rows, graph, decisions):
        adv = f["advisory"]
        claims.append(_claim("finding", [subject, adv, f["status"]], [_step(subject, "AFFECTED_BY", adv)], subject, adv))
        mine = [r["path"] for r in rows if r["advisory"] == adv]
        for ids in mine:
            claims.append(_claim("path", ids, _path_steps(ids, ["DEPENDS_ON"] * (len(ids) - 2) + ["AFFECTED_BY"]), repo_id, adv))
        first = _path_steps(mine[0], ["DEPENDS_ON"] * (len(mine[0]) - 2) + ["AFFECTED_BY"])
        claims += _policy_claims(subject, adv, f["status"], f["severity"], f["dev_only"], gov, first)
    return claims


RUNNERS = {("audit", "A"): method_a_audit, ("audit", "B"): method_b_audit, ("audit", "C"): method_c_audit,
           ("impact", "A"): method_a_impact, ("impact", "B"): method_a_impact, ("impact", "C"): method_c_impact}


def facts(inp: dict) -> set[tuple[str, str, str]]:
    out = {(e["source"], e["type"], e["target"]) for g in (inp["vinc"], inp["impact"]) for e in g.edges}
    out |= {(e["source"], e["type"], e["target"]) for e in audit.governance_links(inp["vinc"].nodes, inp["repo"])}
    _, deps = external.parse_npm_lock(inp["lock"], inp["repo"])
    out |= {(e["source"], e["type"], e["target"]) for e in deps}
    out |= {(pid, "AFFECTED_BY", f"adv:{vid}") for pid, vids in inp["cache"]["queries"].items() for vid in vids}
    return out


def covered(claim: dict, known: set[tuple[str, str, str]]) -> bool:
    steps = claim["evidence"]
    if not steps or any(tuple(s) not in known for s in steps):
        return False
    adj: dict[str, set[str]] = {}
    for s, _, t in steps:
        adj.setdefault(s, set()).add(t)
        adj.setdefault(t, set()).add(s)
    seen, todo = {claim["from"]}, deque([claim["from"]])
    while todo:
        for nxt in adj.get(todo.popleft(), ()):
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return claim["to"] in seen


def expected_keys(task: dict) -> dict[str, set[tuple]]:
    exp = task["expected"]
    out = {"path": {tuple(p) for p in exp.get("paths", [])}, "finding": set(), "policy_link": set()}
    for f in exp.get("findings", []):
        out["finding"].add((f["package"], f["advisory"], f["status"]))
    for link in exp.get("policy_links", []):
        if task["kind"] == "audit":
            out["policy_link"].add((link["package"], link["advisory"], link["decision"], link["verdict"]))
        else:
            out["policy_link"].add((link["path"], link["node"]))
    return out


def score(task: dict, claims: list[dict], known: set) -> dict:
    exp = expected_keys(task)
    got: dict[str, set[tuple]] = {k: set() for k in exp}
    for c in claims:
        got[c["type"]].add(tuple(c["key"]))
    unique = {(c["type"], tuple(c["key"])): c for c in claims}
    hits = lambda k: len(got[k] & exp[k])
    return {"paths": [hits("path"), len(exp["path"])], "policy_links": [hits("policy_link"), len(exp["policy_link"])],
            "findings": [hits("finding"), len(exp["finding"])],
            "unsupported": [sum(1 for (k, key) in unique if key not in exp[k]), len(unique)],
            "covered": [sum(1 for c in unique.values() if covered(c, known)), len(unique)]}


def _cmp(c: dict, b: dict) -> str:
    def rate(pair, empty):
        return pair[0] / pair[1] if pair[1] else empty
    cs = (rate(c["paths"], 1.0), rate(c["policy_links"], 1.0), -rate(c["unsupported"], 0.0))
    bs = (rate(b["paths"], 1.0), rate(b["policy_links"], 1.0), -rate(b["unsupported"], 0.0))
    if cs == bs:
        return "same"
    if all(x >= y for x, y in zip(cs, bs)):
        return "better"
    if all(x <= y for x, y in zip(cs, bs)):
        return "worse"
    return "mixed"


def run(root: Path, tasks_path: Path) -> dict:
    raw = tasks_path.read_bytes()
    doc = json.loads(raw)
    inp = load_inputs(root, doc)
    known = facts(inp)
    per_task, totals = [], {m: {"paths": [0, 0], "policy_links": [0, 0], "findings": [0, 0], "unsupported": [0, 0],
                                "covered": [0, 0], "latency_ms": 0.0} for m in METHODS}
    for task in doc["tasks"]:
        results = {}
        for m in METHODS:
            start = time.perf_counter()
            claims = RUNNERS[(task["kind"], m)](inp, task["subject"])
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            s = score(task, claims, known)
            results[m] = {**s, "latency_ms": elapsed,
                          "claims": sorted(({"type": c["type"], "key": c["key"], "covered": covered(c, known)} for c in claims),
                                           key=lambda c: (c["type"], json.dumps(c["key"])))}
            for k in ("paths", "policy_links", "findings", "unsupported", "covered"):
                totals[m][k] = [totals[m][k][0] + s[k][0], totals[m][k][1] + s[k][1]]
            totals[m]["latency_ms"] = round(totals[m]["latency_ms"] + elapsed, 1)
        per_task.append({"id": task["id"], "kind": task["kind"], "subject": task["subject"], "connection": task["connection"],
                         "graph_expected_to_help": task["graph_expected_to_help"], "c_vs_b": _cmp(results["C"], results["B"]),
                         "results": results})
    return {"tasks_file": tasks_path.name, "tasks_sha256": hashlib.sha256(raw).hexdigest(), "methods": doc["methods"],
            "tasks": per_task, "total": totals,
            "c_vs_b": {v: [t["id"] for t in per_task if t["c_vs_b"] == v] for v in ("better", "same", "worse", "mixed")}}


def without_latency(result: dict) -> dict:
    def strip(x):
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k != "latency_ms"}
        if isinstance(x, list):
            return [strip(v) for v in x]
        return x
    return strip(result)


def _frac(pair: list[int]) -> str:
    return f"{pair[0]}/{pair[1]}" if pair[1] else "-"


def render(result: dict) -> str:
    lines = ["| Method | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |",
             "|---|---|---|---|---|---|---|"]
    for m in METHODS:
        t = result["total"][m]
        lines.append(f"| {m} | {_frac(t['paths'])} | {_frac(t['policy_links'])} | {_frac(t['findings'])} | {_frac(t['unsupported'])} "
                     f"| {_frac(t['covered'])} | {t['latency_ms']:.1f} |")
    lines += ["", "| Task | Graph expected to help | A paths, links, unsupported | B paths, links, unsupported | C paths, links, unsupported | C against B |",
              "|---|---|---|---|---|---|"]
    for t in result["tasks"]:
        cells = [f"{_frac(r['paths'])}, {_frac(r['policy_links'])}, {_frac(r['unsupported'])}" for r in (t["results"][m] for m in METHODS)]
        lines.append(f"| {t['id']} | {'yes' if t['graph_expected_to_help'] else 'no'} | " + " | ".join(cells) + f" | {t['c_vs_b']} |")
    return "\n".join(lines) + "\n"
