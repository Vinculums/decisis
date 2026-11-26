"""Short forms of the tool reports for an agent's context: counts, ids and titles, and the first items of each list."""
from __future__ import annotations

import copy
import json

FIRST = 10
NOTE_ROOM = 4096
DETAILS = ("summary", "full")
NOTE = (f'detail "summary" gives counts, ids and titles, and at most {FIRST} items of each list; '
        'call again with detail "full" for every item and field')


def shape(name: str, report: dict, detail: str = "summary") -> dict:
    return report if detail == "full" else {"detail": "summary", **SHORT[name](report), "note": NOTE}


def first(items: list, pick=None) -> list:
    return [pick(i) if pick else i for i in items[:FIRST]]


def impact(report: dict) -> dict:
    return {"loaded": report["loaded"], "hops": report["hops"], "repo": report["repo"],
            **({"today": report["today"]} if "today" in report else {}), "impact": [impact_path(r) for r in report["impact"]]}


def impact_path(result: dict) -> dict:
    out = {"path": result["path"], "matched_as": result["matched_as"],
           "governing_count": len(result["governing"]), "governing": first(result["governing"], governing_item)}
    old = result.get("superseded")
    if old:
        out["superseded_count"] = len(old)
        out["superseded"] = first(old, lambda i: {"id": i["id"], "title": i["title"], "superseded_by": i["superseded_by"]})
    shut = result.get("closed")
    if shut:
        out["closed_count"] = len(shut)
        out["closed"] = first(shut, lambda i: {"id": i["id"], "title": i["title"], "valid_until": i["valid_until"]})
    return out


def governing_item(item: dict) -> dict:
    keys = ("id", "kind", "title", "hops", "via", "status", "valid_until")
    return {k: item[k] for k in keys if k in item}


def paths(report: dict) -> dict:
    return {"loaded": report["loaded"], "path_count": len(report["paths"]), "paths": first(report["paths"])}


def audit(report: dict) -> dict:
    out = {"meta": {k: v for k, v in report["meta"].items() if not isinstance(v, (list, dict))}, "loaded": report["loaded"],
           "summary": report["summary"], "violations": report["violations"], "waived": report.get("waived", 0),
           **({"today": report["today"]} if "today" in report else {}),
           **counted("governing", report["governing"], lambda g: {"decision": g["decision"], "title": g.get("title") or ""}),
           **counted("findings", report["findings"], finding),
           **counted("unresolved_packages", report["unresolved_packages"], lambda u: u["package"]),
           **counted("inventory_notes", report["inventory_notes"])}
    for key in ("rule_problems", "not_governing", "unread_decisions", "expiring_soon"):
        if report.get(key):
            out.update(counted(key, report[key]))
    return out


def counted(key: str, items: list, pick=None) -> dict:
    return {f"{key}_count": len(items), key: first(items, pick)}


def finding(f: dict) -> dict:
    keys = ("package", "advisory", "kind", "severity", "status", "dev_only")
    violated = [p["decision"] for p in f.get("policies", []) if p["verdict"] == "violated"]
    waived = [{"decision": p["decision"], "expires": p["waiver"]["expires"]} for p in f.get("policies", []) if p["verdict"] == "waived"]
    return {**{k: f[k] for k in keys if k in f}, "violated": violated, **({"waived": waived} if waived else {})}


def query(report: dict) -> dict:
    out = {"loaded": report["loaded"], "columns": report["columns"], "row_count": report["row_count"], "rows": first(report["rows"])}
    if "cut" in report:
        out["cut"] = report["cut"]
    return out


def check(report: dict) -> dict:
    out = {"loaded": report["loaded"], "hops": report["hops"], "repo": report["repo"], "base": report["base"],
           **({"today": report["today"]} if "today" in report else {}),
           "reviewers": report["reviewers"], "summary": report["summary"], **counted("changed", report["changed"]),
           **counted("governing", report["governing"], lambda g: {"decision": g["decision"], "title": g["title"]}),
           **counted("superseded", report["superseded"], lambda g: {"decision": g["decision"], "superseded_by": g.get("superseded_by", [])}),
           **(counted("closed", report["closed"], lambda g: {"decision": g["decision"], "valid_until": g["valid_until"]})
              if report.get("closed") else {}),
           "rules_count": len(report["rules"]), "rules_covering_a_change": sum(1 for r in report["rules"] if r["files"]),
           "imports_count": len(report["imports"]),
           **counted("violations", report["violations"], judged), **counted("unresolved", report["unresolved"], judged),
           **counted("waived", report.get("waived", []), judged)}
    for key in ("rule_problems", "unread_decisions", "expiring_soon"):
        if report.get(key):
            out.update(counted(key, report[key]))
    if report.get("codeowners"):
        owned = report["codeowners"]
        out["codeowners"] = {"enforced": owned["enforced"], "note": owned["note"], **counted("files", owned["files"])}
    return out


def judged(r: dict) -> dict:
    return {k: r[k] for k in ("file", "line", "decision", "rule", "why", "import", "waiver", "expired_waiver") if r.get(k) is not None}


SHORT = {"impact": impact, "paths": paths, "audit": audit, "check": check, "query": query}


def fit(report: dict, size, limit: int) -> dict:
    if size(report) <= limit:
        return report
    out, cuts = copy.deepcopy(report), []
    while size(out) > limit - NOTE_ROOM:
        path = heaviest(out)
        if path is None:
            raise ValueError(f"the report is larger than {limit} bytes and has no list left to shorten")
        items = at(out, path)
        keep = longest_fit(out, path, items, size, limit - NOTE_ROOM)
        cuts.append((path, keep, len(items)))
        place(out, path, items[:keep])
    shortened = "; ".join(f"{'/'.join(map(str, p)) or 'the report'} {k} of {n}" for p, k, n in cuts[:FIRST])
    note = f"the response was shortened to stay under {limit} bytes: {shortened}; ask for less, such as fewer rows or detail \"summary\""
    out["cut"] = f"{out['cut']}; {note}" if isinstance(out.get("cut"), str) else note
    return out


def longest_fit(out: dict, path: tuple, items: list, size, target: int) -> int:
    lo, hi = 0, len(items) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        place(out, path, items[:mid])
        if size(out) <= target:
            lo = mid
        else:
            hi = mid - 1
    return lo


def lists(value, path: tuple = ()) -> list[tuple[int, tuple]]:
    found = []
    if isinstance(value, list) and value:
        found.append((len(json.dumps(value, ensure_ascii=False)), path))
    children = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, child in children:
        found += lists(child, (*path, key))
    return found


def heaviest(report: dict) -> tuple | None:
    found = lists(report)
    if not found:
        return None
    weight, path = max(found)
    while True:
        inner = [(w, p) for w, p in found if len(p) > len(path) and p[:len(path)] == path and w * 2 >= weight]
        if not inner:
            return path
        weight, path = max(inner)


def at(value, path: tuple):
    for key in path:
        value = value[key]
    return value


def place(report: dict, path: tuple, items: list) -> None:
    at(report, path[:-1])[path[-1]] = items
