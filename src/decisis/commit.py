from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import date

from . import checkout as co

SLUG_MAX = 60
LICENSE_SLUG_MAX = 24
DOMAIN = "platform/security"


def _slug(text: str) -> str:
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


def record_id(repo: str, name: str, scope: str, advisory: str) -> str:
    adv = _slug(advisory)
    room = SLUG_MAX - len(adv) - len(scope) - 2
    return f"record:{_slug(f'{repo}-{name}')[:max(room, 8)].strip('-')}-{scope}-{adv}"


def _package_name(purl: str) -> str:
    return purl.split("/", 1)[-1].rsplit("@", 1)[0]


def _routes(paths: list[list[str]], tail: int) -> str:
    return "; ".join(sorted({" -> ".join(_package_name(x) for x in path[1:len(path) - tail]) for path in paths}))


def claim(repo: str, name: str, versions: list[str], scope: str, osv: str, severity: str, summary: str,
          paths: list[list[str]]) -> str:
    use = "ships" if scope == "shipped" else "uses in development only"
    head = f"{repo} {use} {name} {' and '.join(versions)}, which OSV {osv} ({severity}) covers"
    head += f": {summary.rstrip('.')}." if summary and summary != osv else "."
    return f"{head} Path: {_routes(paths, 1)}."


def package_claim(repo: str, name: str, versions: list[str], scope: str, what: str, paths: list[list[str]]) -> str:
    use = "ships" if scope == "shipped" else "uses in development only"
    return f"{repo} {use} {name} {' and '.join(versions)}, {what}. Path: {_routes(paths, 0)}."


def digest(plan: dict) -> str:
    body = {k: plan[k] for k in ("space", "nodes", "edges")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def license_slug(expression: str) -> str:
    slug = _slug(expression) or "none"
    if len(slug) <= LICENSE_SLUG_MAX:
        return f"license-{slug}"
    return f"license-{slug[:LICENSE_SLUG_MAX - 8].strip('-')}-{hashlib.sha256(expression.encode()).hexdigest()[:7]}"


def _split(package: str) -> tuple[str, str]:
    name, version = package.split("/", 1)[1].rsplit("@", 1)
    return name, version


def _group(f: dict, repo: str, scope: str) -> tuple[str, dict]:
    name, _ = _split(f["package"])
    kind = f.get("kind", "advisory")
    if kind == "license":
        value = f.get("license_expression") or ""
        return record_id(repo, name, scope, license_slug(value)), {"kind": kind, "name": name, "value": value, "scope": scope}
    if kind == "package":
        return record_id(repo, name, scope, "denied-package"), {"kind": kind, "name": name, "value": f"{f['ecosystem']}:{f['name']}",
                                                                 "scope": scope}
    osv = f["advisory"].split(":", 1)[1]
    return record_id(repo, name, scope, osv), {"kind": kind, "name": name, "osv": osv, "scope": scope}


def _held(f: dict) -> dict:
    why = f"status {f['status']}: not recorded"
    if "advisory" in f:
        return {"package": f["package"], "advisory": f["advisory"], "why": why}
    return {"package": f["package"], "kind": f["kind"], "why": why}


def _verdicts(found: list) -> dict[str, dict]:
    verdicts: dict[str, dict] = {}
    for _, f in found:
        for p in f["policies"]:
            if p["verdict"] in ("violated", "relevant") and verdicts.get(p["decision"], {}).get("verdict") != "violated":
                verdicts[p["decision"]] = p
    return verdicts


def _evidence(repo: str, today: str, ref: str | None, lock_hash: str, lockfile_path: str) -> dict:
    return {"measured_at": today, "measured_ref": ref or lock_hash or "lockfile", "lockfile_hash": lock_hash,
            "subject_path": f"{repo.lower()}:{lockfile_path.removeprefix('./').lstrip('/')}"}


def advisory_record(rid: str, g: dict, found: list, verdicts: dict, repo: str, today: str, evidence: dict) -> dict:
    name, osv, scope = g["name"], g["osv"], g["scope"]
    versions = sorted({v for v, _ in found})
    first = found[0][1]
    statement = claim(repo, name, versions, scope, osv, first["severity"], first.get("advisory_summary") or "",
                      [f["path"] for _, f in found])
    return {"id": rid, "type": "record",
            "title": f"{repo} {scope} dependency {name} {', '.join(versions)} is affected by {osv}",
            "domain": DOMAIN, "valid_from": today,
            "props": {"entity": f"{repo}:{name}", "predicate": "affected_by_advisory", "value": osv, "scope": scope,
                      "versions": versions, "statement": statement, "severity": first["severity"],
                      "dependency_paths": [f["path"] for _, f in found],
                      "violates": sorted(d for d, p in verdicts.items() if p["verdict"] == "violated"),
                      "source": first["source_url"], "source_system": "decisis audit over OSV",
                      "advisory_fetched_at": first.get("fetched_at"), "advisory_content_hash": first.get("content_hash"),
                      **evidence}}


PACKAGE_RECORD = {
    "license": ("licensed_under", "is licensed {value}", "licensed {value}"),
    "package": ("uses_denied_package", "is the denied package {value}", "a package a decision denies"),
}


def package_record(rid: str, g: dict, found: list, verdicts: dict, repo: str, today: str, evidence: dict) -> dict:
    name, scope, kind, value = g["name"], g["scope"], g["kind"], g["value"]
    predicate, title, what = PACKAGE_RECORD[kind]
    versions = sorted({v for v, _ in found})
    first = found[0][1]
    paths = [f["path"] for _, f in found]
    return {"id": rid, "type": "record",
            "title": f"{repo} {scope} dependency {name} {', '.join(versions)} {title.format(value=value)}",
            "domain": DOMAIN, "valid_from": today,
            "props": {"entity": f"{repo}:{name}", "predicate": predicate, "value": value, "scope": scope,
                      "versions": versions, "statement": package_claim(repo, name, versions, scope, what.format(value=value), paths),
                      "rules": sorted({p["rule"] for p in verdicts.values() if p.get("rule")}),
                      "dependency_paths": paths,
                      "violates": sorted(d for d, p in verdicts.items() if p["verdict"] == "violated"),
                      "source": evidence["subject_path"], "source_system": f"decisis audit over {first.get('source_system') or 'the inventory'}",
                      "inventory_fetched_at": first.get("fetched_at"), **evidence}}


def propose(report: dict, repo: str, space: str, today: str | None = None,
            lockfile_path: str = "package-lock.json", ref: str | None = None) -> dict:
    today = today or date.today().isoformat()
    lock_hash = (report.get("meta") or {}).get("lockfile_hash", "")
    evidence = _evidence(repo, today, ref, lock_hash, lockfile_path)
    groups: dict[str, dict] = {}
    held = []
    for f in report.get("findings", []):
        if f["status"] != "affected":
            held.append(_held(f))
            continue
        rid, g = _group(f, repo, "development" if f["dev_only"] else "shipped")
        groups.setdefault(rid, {**g, "found": []})["found"].append((_split(f["package"])[1], f))
    nodes, edges = [], []
    for rid, g in sorted(groups.items()):
        found = sorted(g["found"], key=lambda vf: vf[0])
        verdicts = _verdicts(found)
        build = advisory_record if g["kind"] == "advisory" else package_record
        nodes.append(build(rid, g, found, verdicts, repo, today, evidence))
        for d, p in sorted(verdicts.items()):
            edges.append({"from": rid, "to": d, "type": "relates_to", "evidence": f"{p['verdict']}: {p['why']}"})
    plan = {"space": space, "nodes": nodes, "edges": edges, "held": held}
    plan["digest"] = digest(plan)
    return plan


def render(plan: dict) -> str:
    out = [f"Write set for space {plan['space']} (approval digest {plan['digest']}):", ""]
    for n in plan["nodes"]:
        out.append(f"  + {n['id']}  [{n['props'].get('severity') or n['props']['predicate']}, {n['props']['scope']}]")
        out.append(f"      {n['title']}")
    for e in plan["edges"]:
        out.append(f"  + {e['from']} -{e['type']}-> {e['to']}")
    if plan["held"]:
        out += ["", f"  held back, not written: {len(plan['held'])}"]
        out += [f"    {h['record']}: {problem}" for h in plan["held"] for problem in h.get("failed", [])]
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
