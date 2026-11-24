"""Short forms of the tool reports for an agent's context: counts, ids and titles, and the first items of each list."""
from __future__ import annotations

FIRST = 10
DETAILS = ("summary", "full")
NOTE = (f'detail "summary" gives counts, ids and titles, and at most {FIRST} items of each list; '
        'call again with detail "full" for every item and field')


def shape(name: str, report: dict, detail: str = "summary") -> dict:
    return report if detail == "full" else {"detail": "summary", **SHORT[name](report), "note": NOTE}


def first(items: list, pick=None) -> list:
    return [pick(i) if pick else i for i in items[:FIRST]]


def impact(report: dict) -> dict:
    return {"loaded": report["loaded"], "hops": report["hops"], "repo": report["repo"],
            "impact": [impact_path(r) for r in report["impact"]]}


def impact_path(result: dict) -> dict:
    out = {"path": result["path"], "matched_as": result["matched_as"],
           "governing_count": len(result["governing"]), "governing": first(result["governing"], governing_item)}
    old = result.get("superseded")
    if old:
        out["superseded_count"] = len(old)
        out["superseded"] = first(old, lambda i: {"id": i["id"], "title": i["title"], "superseded_by": i["superseded_by"]})
    return out


def governing_item(item: dict) -> dict:
    keys = ("id", "kind", "title", "hops", "via", "status")
    return {k: item[k] for k in keys if k in item}


def paths(report: dict) -> dict:
    return {"loaded": report["loaded"], "path_count": len(report["paths"]), "paths": first(report["paths"])}


def audit(report: dict) -> dict:
    out = {"meta": {k: v for k, v in report["meta"].items() if not isinstance(v, (list, dict))}, "loaded": report["loaded"],
           "summary": report["summary"], "violations": report["violations"],
           **counted("governing", report["governing"], lambda g: {"decision": g["decision"], "title": g.get("title") or ""}),
           **counted("findings", report["findings"], finding),
           **counted("unresolved_packages", report["unresolved_packages"], lambda u: u["package"]),
           **counted("inventory_notes", report["inventory_notes"])}
    if report.get("rule_problems"):
        out.update(counted("rule_problems", report["rule_problems"]))
    return out


def counted(key: str, items: list, pick=None) -> dict:
    return {f"{key}_count": len(items), key: first(items, pick)}


def finding(f: dict) -> dict:
    keys = ("package", "advisory", "kind", "severity", "status", "dev_only")
    violated = [p["decision"] for p in f.get("policies", []) if p["verdict"] == "violated"]
    return {**{k: f[k] for k in keys if k in f}, "violated": violated}


def query(report: dict) -> dict:
    out = {"loaded": report["loaded"], "columns": report["columns"], "row_count": report["row_count"], "rows": first(report["rows"])}
    if "cut" in report:
        out["cut"] = report["cut"]
    return out


SHORT = {"impact": impact, "paths": paths, "audit": audit, "query": query}
