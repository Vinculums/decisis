from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import date

SLUG_MAX = 60
DOMAIN = "platform/security"


def _slug(text: str) -> str:
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


def record_id(repo: str, name: str, version: str, advisory: str) -> str:
    adv = _slug(advisory)
    head = _slug(f"{repo}-{name}")
    ver = _slug(version)
    room = SLUG_MAX - len(adv) - len(ver) - 2
    return f"record:{head[:max(room, 8)].strip('-')}-{ver}-{adv}"


def digest(plan: dict) -> str:
    body = {k: plan[k] for k in ("space", "nodes", "edges")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def propose(report: dict, repo: str, space: str, today: str | None = None) -> dict:
    today = today or date.today().isoformat()
    lock_hash = (report.get("meta") or {}).get("lockfile_hash", "")
    nodes, edges, held = [], [], []
    for f in report.get("findings", []):
        if f["status"] != "affected":
            held.append({"package": f["package"], "advisory": f["advisory"], "why": f"status {f['status']}: not recorded"})
            continue
        name, version = f["package"].split("/", 1)[1].rsplit("@", 1)
        osv = f["advisory"].split(":", 1)[1]
        scope = "development" if f["dev_only"] else "shipped"
        rid = record_id(repo, name, version, osv)
        violated = [p for p in f["policies"] if p["verdict"] == "violated"]
        statement = (f"{repo} resolves {name} {version} through {' -> '.join(f['path'][1:-1])}, and OSV {osv} "
                     f"({f['severity']}) covers that version.")
        nodes.append({"id": rid, "type": "record", "title": f"{repo} {scope} dependency {name} {version} is affected by {osv}",
                      "domain": DOMAIN, "valid_from": today,
                      "props": {"entity": f"{repo}:{name}", "predicate": "affected_by_advisory", "value": osv, "scope": scope,
                                "statement": statement, "severity": f["severity"], "dependency_path": f["path"],
                                "violates": [p["decision"] for p in violated], "source": f["source_url"],
                                "source_system": "vinc-relate audit over OSV", "measured_at": today,
                                "measured_ref": lock_hash or "lockfile", "subject_path": f"{repo.lower()}:package-lock.json"}})
        for p in f["policies"]:
            if p["verdict"] in ("violated", "relevant"):
                edges.append({"from": rid, "to": p["decision"], "type": "relates_to", "evidence": f"{p['verdict']}: {p['why']}"})
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
    out += ["", f"Approve with: vinc-relate commit <plan file> --approve {plan['digest']}"]
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
        op = str(uuid.uuid5(uuid.NAMESPACE_URL, f"vinc-relate:{plan['digest']}"))
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
        want = {e["to"] for e in edges if e["from"] == n["id"]}
        if want:
            seen = {x.get("id") for x in client.tool("vinc_neighbors", {"node": n["id"], "limit": 50}).get("neighbors", [])}
            problems += [f"{n['id']}: edge to {t} not found after the write" for t in sorted(want - seen)]
    return {"written": [n["id"] for n in nodes], "existing": existing, "edges": len(edges),
            "verified": not problems, "problems": problems}
