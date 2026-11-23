from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import date

from . import checkout as co

SLUG_MAX = 60
DOMAIN = "platform/security"


def _slug(text: str) -> str:
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


def record_id(repo: str, name: str, scope: str, advisory: str) -> str:
    adv = _slug(advisory)
    room = SLUG_MAX - len(adv) - len(scope) - 2
    return f"record:{_slug(f'{repo}-{name}')[:max(room, 8)].strip('-')}-{scope}-{adv}"


def _package_name(purl: str) -> str:
    return purl.split("/", 1)[-1].rsplit("@", 1)[0]


def claim(repo: str, name: str, versions: list[str], scope: str, osv: str, severity: str, summary: str,
          paths: list[list[str]]) -> str:
    use = "ships" if scope == "shipped" else "uses in development only"
    head = f"{repo} {use} {name} {' and '.join(versions)}, which OSV {osv} ({severity}) covers"
    head += f": {summary.rstrip('.')}." if summary and summary != osv else "."
    routes = sorted({" -> ".join(_package_name(x) for x in path[1:-1]) for path in paths})
    return f"{head} Path: {'; '.join(routes)}."


def digest(plan: dict) -> str:
    body = {k: plan[k] for k in ("space", "nodes", "edges")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def propose(report: dict, repo: str, space: str, today: str | None = None,
            lockfile_path: str = "package-lock.json", ref: str | None = None) -> dict:
    today = today or date.today().isoformat()
    lock_hash = (report.get("meta") or {}).get("lockfile_hash", "")
    groups: dict[str, dict] = {}
    held = []
    for f in report.get("findings", []):
        if f["status"] != "affected":
            held.append({"package": f["package"], "advisory": f["advisory"], "why": f"status {f['status']}: not recorded"})
            continue
        name, version = f["package"].split("/", 1)[1].rsplit("@", 1)
        osv = f["advisory"].split(":", 1)[1]
        scope = "development" if f["dev_only"] else "shipped"
        g = groups.setdefault(record_id(repo, name, scope, osv), {"name": name, "osv": osv, "scope": scope, "found": []})
        g["found"].append((version, f))
    nodes, edges = [], []
    for rid, g in sorted(groups.items()):
        name, osv, scope = g["name"], g["osv"], g["scope"]
        found = sorted(g["found"], key=lambda vf: vf[0])
        versions = sorted({v for v, _ in found})
        first = found[0][1]
        verdicts: dict[str, dict] = {}
        for _, f in found:
            for p in f["policies"]:
                if p["verdict"] in ("violated", "relevant") and verdicts.get(p["decision"], {}).get("verdict") != "violated":
                    verdicts[p["decision"]] = p
        statement = claim(repo, name, versions, scope, osv, first["severity"], first.get("advisory_summary") or "",
                          [f["path"] for _, f in found])
        nodes.append({"id": rid, "type": "record",
                      "title": f"{repo} {scope} dependency {name} {', '.join(versions)} is affected by {osv}",
                      "domain": DOMAIN, "valid_from": today,
                      "props": {"entity": f"{repo}:{name}", "predicate": "affected_by_advisory", "value": osv, "scope": scope,
                                "versions": versions, "statement": statement, "severity": first["severity"],
                                "dependency_paths": [f["path"] for _, f in found],
                                "violates": sorted(d for d, p in verdicts.items() if p["verdict"] == "violated"),
                                "source": first["source_url"], "source_system": "decisis audit over OSV",
                                "advisory_fetched_at": first.get("fetched_at"), "advisory_content_hash": first.get("content_hash"),
                                "measured_at": today, "measured_ref": ref or lock_hash or "lockfile",
                                "lockfile_hash": lock_hash,
                                "subject_path": f"{repo.lower()}:{lockfile_path.removeprefix('./').lstrip('/')}"}})
        for d, p in sorted(verdicts.items()):
            edges.append({"from": rid, "to": d, "type": "relates_to", "evidence": f"{p['verdict']}: {p['why']}"})
    plan = {"space": space, "nodes": nodes, "edges": edges, "held": held}
    plan["digest"] = digest(plan)
    return plan


def render(plan: dict) -> str:
    out = [f"Write set for space {plan['space']} (approval digest {plan['digest']}):", ""]
    for n in plan["nodes"]:
        out.append(f"  + {n['id']}  [{n['props']['severity']}, {n['props']['scope']}]")
        out.append(f"      {n['title']}")
    for e in plan["edges"]:
        out.append(f"  + {e['from']} -{e['type']}-> {e['to']}")
    if plan["held"]:
        out += ["", f"  held back, not written: {len(plan['held'])}"]
    out += ["", f"Approve with: decisis commit <plan file> --approve {plan['digest']}"]
    return "\n".join(out)


def check_approval(plan: dict, approve: str) -> None:
    if approve != plan.get("digest") or digest(plan) != plan.get("digest"):
        raise SystemExit("approval does not match this write set; nothing was written")


def commit(plan: dict, approve: str, client) -> dict:
    check_approval(plan, approve)
    if not plan["nodes"]:
        return {"written": [], "existing": [], "verified": True}
    existing = [n["id"] for n in plan["nodes"] if client.tool("vinc_node", {"node_id": n["id"]}).get("found")]
    nodes = [n for n in plan["nodes"] if n["id"] not in existing]
    edges = [e for e in plan["edges"] if e["from"] not in existing]
    reply = {}
    if nodes:
        op = str(uuid.uuid5(uuid.NAMESPACE_URL, f"decisis:{plan['digest']}"))
        reply = client.tool("vinc_ingest", {"nodes": nodes, "edges": edges, "create_only": True, "operation_id": op})
    problems = list(reply.get("warnings") or [])
    if reply.get("partial"):
        problems.append("the write reported partial")
    for n in nodes:
        got = client.tool("vinc_node", {"node_id": n["id"]})
        stored = (got.get("node") or {}).get("props") or {}
        if not got.get("found"):
            problems.append(f"{n['id']}: not found after the write")
        elif any(stored.get(k) != v for k, v in n["props"].items()):
            problems.append(f"{n['id']}: stored props differ from the write set")
    for n in nodes:
        want = {(e["from"], co.relation(e), e["to"]) for e in edges if e["from"] == n["id"]}
        if want:
            got = co.normalize([client.tool("vinc_graph", {"seed_id": n["id"], "depth": 1})], [n["id"]], plan["space"])
            have = {(e["source"], e["type"], e["target"]) for e in got.edges}
            problems += [f"{n['id']}: edge {s} -{t}-> {d} not found after the write with this type and direction"
                         for s, t, d in sorted(want - have)]
    return {"written": [n["id"] for n in nodes], "existing": existing, "edges": len(edges),
            "verified": not problems, "problems": problems}
