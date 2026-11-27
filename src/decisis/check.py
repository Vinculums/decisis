from __future__ import annotations

import datetime
import posixpath
import subprocess
from pathlib import Path

from . import codeowners, cycles, imports, impact, init, rules
from .sandbox import Limits, Subgraph

MAX_CHANGED = 10_000
GIT_SECONDS = 120
CODEOWNERS_NOTE = ("decisis does not enforce CODEOWNERS: these owners are shown for context, and a missing owner review changes no verdict. "
                   "To enforce it, turn on \"Require review from Code Owners\" in the branch protection rule on GitHub, "
                   "or add a review_required rule to an ADR.")


def changed_since(root: Path, ref: str) -> list[str]:
    if not ref.strip() or ref.startswith("-"):
        raise ValueError(f"--base must name a commit, not {ref!r}")
    try:
        done = codeowners.git(root, "diff", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--relative",
                              f"{ref}...HEAD", "--", timeout=GIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError(f"git diff could not run in {root}: {e}") from None
    if done.returncode != 0:
        why = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ValueError(f"git diff {ref}...HEAD failed in {root}: {why[0] if why else 'exit ' + str(done.returncode)}")
    return sorted({p for p in done.stdout.decode("utf-8", "surrogateescape").split("\0") if p})


def normal(path: str) -> str:
    if "\x00" in path:
        raise ValueError(f"a changed file must be a path inside the repository, not {path!r}")
    p = posixpath.normpath(path.strip())
    if not path.strip() or p.startswith("/") or p in (".", "..") or p.startswith("../"):
        raise ValueError(f"a changed file must be a path inside the repository, not {path!r}")
    return p


def judged(graph: Subgraph, retired) -> list[tuple[dict, rules.Parsed]]:
    found = [(n, rules.of(n)) for n in graph.nodes if n["kind"] == "decision" and n["id"] not in retired]
    return sorted(found, key=lambda d: d[0]["id"])


def governing(report: dict, key: str) -> list[dict]:
    out: dict[str, dict] = {}
    for r in report["impact"]:
        for item in r.get(key, []):
            if item["kind"] != "decision":
                continue
            entry = out.setdefault(item["id"], {"decision": item["id"], "title": item.get("title") or "", "files": []})
            if item.get("status"):
                entry["status"] = item["status"]
            if "superseded_by" in item:
                entry["superseded_by"] = item["superseded_by"]
            if item.get("valid_until"):
                entry["valid_until"] = item["valid_until"]
            entry["files"].append(r["path"])
    return [out[k] for k in sorted(out)]


def value_of(rule: rules.Rule) -> dict:
    a, b = rule.value
    return {"paths": list(a), "reviewers": list(b)} if rule.kind == "review_required" else {"from": list(a), "to": list(b)}


def covered(rule: rules.Rule, files: list[str]) -> list[str]:
    return [f for f in files if rules.matches(rule.value[0], f)]


def entry(decision: str, rule: rules.Rule, file: str, line, judged: dict, found: imports.Import | None = None) -> dict:
    rest = {k: v for k, v in judged.items() if k not in ("verdict", "why")}
    return {"file": file, "line": line, "decision": decision, "rule": rule.kind, "verdict": judged["verdict"], "why": judged["why"],
            "import": found.specifier if found else None, "target": found.target if found else None, **rest}


def review_results(decisions: list[tuple[dict, rules.Parsed]], files: list[str], reviewers: list[str], day: datetime.date) -> list[dict]:
    out = []
    for node, parsed in decisions:
        for rule in rules.judging(parsed, "review"):
            for f in covered(rule, files):
                judged = rules.waived(rule, {"file": f, "reviewers": reviewers}, False, parsed.waivers, day)
                out.append(entry(node["id"], rule, f, None, judged))
    return out


def owner_index(graph: Subgraph, repo: str | None) -> dict[str, list[tuple[str, list[str]]]]:
    index: dict[str, list[tuple[str, list[str]]]] = {}
    for n in graph.nodes:
        names = (n.get("props") or {}).get("owners")
        if n["kind"] != "concept" or not isinstance(names, list) or not names or not all(isinstance(o, str) and o.strip() for o in names):
            continue
        for ref in impact.refs_of(n):
            path = impact.code_path(ref, repo)
            if path:
                index.setdefault(path, []).append((n["id"], list(names)))
    return index


def code_owners(graph: Subgraph, files: list[str], reviewed: frozenset[str] | set[str] = frozenset(), repo: str | None = None) -> list[dict]:
    index = owner_index(graph, repo)
    out = []
    for f in files:
        if f in reviewed:
            continue
        seen: set[str] = set()
        for path in (f, *codeowners.parents(f)):
            for nid, names in index.get(path, ()):
                if nid not in seen:
                    seen.add(nid)
                    out.append({"file": f, "owners": names, "concept": nid})
    return sorted(out, key=lambda e: (e["file"], e["concept"]))


def codeowners_notice(graph: Subgraph, files: list[str], reviewed: frozenset[str] | set[str] = frozenset(), repo: str | None = None) -> dict:
    found = code_owners(graph, files, reviewed, repo)
    return shown({"codeowners": {"enforced": False, "note": CODEOWNERS_NOTE, "files": found}}) if found else {}


def facts(file: str, found: imports.Import) -> dict:
    return {"file": file, "specifier": found.specifier, "resolution": found.resolution, "target": found.target, "why": found.why,
            "also": found.also}


def import_results(decisions: list[tuple[dict, rules.Parsed]], files: list[str], repo: imports.Repo,
                   day: datetime.date) -> tuple[list[dict], list[dict]]:
    ruled = [(node["id"], rule, parsed.waivers) for node, parsed in decisions for rule in rules.judging(parsed, "import")]
    read: dict[str, list[imports.Import]] = {}
    out = []
    for decision, rule, waivers in ruled:
        for f in covered(rule, files):
            if f not in read:
                read[f] = imports.read(repo, f)
            for found in read[f]:
                judged = rules.waived(rule, facts(f, found), False, waivers, day)
                out.append(entry(decision, rule, f, found.line, judged, found))
    listed = [{"file": f, "line": i.line, "import": i.specifier, "resolution": i.resolution, "target": i.target,
               **({"why": i.why} if i.why else {})} for f in sorted(read) for i in read[f]]
    return out, listed


def lapsed_note(c: cycles.Cycle, lapsed: dict[str, str]) -> str:
    named = [f"{m} (valid_until {lapsed[m]})" for m in c.decisions if m in lapsed]
    if not named:
        return ""
    one = len(named) == 1
    return f". {', '.join(named)} would be closed by {'its' if one else 'their'} valid_until, but {'stays' if one else 'stay'} in force while the cycle holds"


def cycle_results(found: list[cycles.Cycle], arriving: bool = False, lapsed: dict[str, str] | None = None) -> list[dict]:
    return [{"file": c.files[0] if c.files else "", "line": None, "decision": c.decisions[0], "rule": cycles.RULE, "verdict": "unresolved",
             "why": (c.arriving if arriving else c.reason) + lapsed_note(c, lapsed or {}), "import": None, "target": None,
             "decisions": list(c.members), "files": list(c.files)}
            for c in found]


def expiring(waived: list[dict], day: datetime.date, warn_days: int) -> list[dict]:
    return rules.expiring_soon([(r["decision"], r["waiver"]) for r in waived], day, warn_days)


def problems(decisions: list[tuple[dict, rules.Parsed]]) -> list[dict]:
    return [{"decision": n["id"], "rule": p.kind, "problem": p.reason} for n, parsed in decisions
            for p in parsed.problems + parsed.waiver_problems]


def ordered(results: list[dict], verdict: str) -> list[dict]:
    return sorted((r for r in results if r["verdict"] == verdict), key=lambda r: (r["file"], r["line"] or 0, r["decision"], r["rule"], r["import"] or ""))


def failed(report: dict, on_unresolved: bool) -> bool:
    return bool(report["violations"] or (on_unresolved and (report["unresolved"] or report.get("unread_decisions"))))


def run(graph: Subgraph, changed: list[str], root: Path, reviewers: list[str] = (), hops: int = 3, repo: str | None = None,
        base: str | None = None, limits: Limits | None = None, sandbox_root=None, day: datetime.date | None = None,
        warn_days: int = rules.WARN_DAYS, arriving: list[cycles.Cycle] = (), leaving: list[cycles.Cycle] = ()) -> dict:
    files = sorted({normal(p) for p in changed})
    if len(files) > MAX_CHANGED:
        raise ValueError(f"the change set has {len(files)} files, more than the {MAX_CHANGED} check judges")
    day = day or rules.today()
    report = impact.run(graph, files, hops, repo, root=sandbox_root, limits=limits, day=day)
    replaced = impact.superseded_by(graph)
    closed = impact.closed_by(graph, day, replaced)
    decisions = judged(graph, replaced.keys() | closed.keys())
    gov = governing(report, "governing")
    results = review_results(decisions, files, list(reviewers), day)
    found, listed = import_results(decisions, files, imports.Repo(root), day)
    gone = {c.members for c in leaving}
    held = [c for c in cycles.find(graph.nodes, graph.edges) if c.members not in gone]
    results += found + cycle_results(held, lapsed=impact.lapsed(graph, day)) + cycle_results(list(arriving), True)
    violations, unresolved, waived = ordered(results, "violated"), ordered(results, "unresolved"), ordered(results, rules.WAIVED)
    shut = governing(report, "closed")
    ruled = [{"decision": n["id"], "rule": r.kind, **value_of(r), "files": covered(r, files)}
             for n, parsed in decisions for s in rules.CHANGE_SUBJECTS for r in rules.judging(parsed, s)]
    out = {"loaded": report["loaded"], "hops": hops, "repo": repo, "base": base, "today": day.isoformat(), "changed": files,
           "reviewers": list(reviewers), "governing": gov, "superseded": governing(report, "superseded"), **({"closed": shut} if shut else {}),
           "rules": ruled, "imports": listed, "violations": violations, "unresolved": unresolved, "waived": waived,
           "summary": {"violated": len(violations), "unresolved": len(unresolved), "waived": len(waived),
                       "not_violated": sum(1 for r in results if r["verdict"] == "not_violated")},
           "impact": report["impact"]}
    odd = [f for f in files if not utf8(f)]
    if odd:
        extra = [{"file": f, "line": None, "decision": r["decision"], "rule": r["rule"], "verdict": "unresolved",
                  "why": "the file name is not UTF-8, so the rule cannot judge it", "import": None, "target": None}
                 for r in ruled for f in odd if f in r["files"]]
        out["unresolved"] = ordered(out["unresolved"] + extra, "unresolved")
        out["summary"]["unresolved"] = len(out["unresolved"])
    found_problems = problems(decisions)
    unread = init.unread_decisions(graph.meta)
    soon = expiring(waived, day, warn_days)
    reviewed = {f for r in ruled if r["rule"] == "review_required" for f in r["files"]}
    return shown({**out, **({"rule_problems": found_problems} if found_problems else {}), **({"unread_decisions": unread} if unread else {}),
                  **({rules.EXPIRING: soon} if soon else {}), **codeowners_notice(graph, files, reviewed, repo)})


def utf8(name: str) -> bool:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def shown(value):
    if isinstance(value, str):
        return value if utf8(value) else value.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    if isinstance(value, dict):
        return {shown(k): shown(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [shown(v) for v in value]
    return value


def where(r: dict) -> str:
    return f"{r['file']}:{r['line']}" if r.get("line") else r["file"]


def result_lines(results: list[dict]) -> list[str]:
    return [f"  {where(r)}  {r['decision']}  {r['rule']}: {r['why']}" for r in results]


def until(w: dict) -> str:
    return f"waiver {w['waiver']} until {w['expires']}, approved by {w['approved_by']}: {w['reason']}"


def waived_lines(results: list[dict]) -> list[str]:
    return [f"  {where(r)}  {r['decision']}  {r['rule']}: {r['why']} ({until(r['waiver'])})" for r in results]


def expiring_lines(entries: list[dict]) -> list[str]:
    return [f"  {e['decision']}  waiver {e['waiver']} until {e['expires']} ({e['days_left']} day(s) left), "
            f"approved by {e['approved_by']}: {e['reason']}" for e in entries]


def render(report: dict) -> str:
    base = f" against {report['base']}" if report.get("base") else ""
    who = ", ".join(report["reviewers"]) or "none given"
    lines = [f"{len(report['changed'])} changed file(s){base}; reviewers: {who}"]
    lines.append(f"governing decisions: {len(report['governing'])}")
    lines += [f"  {g['decision']}  {g['title']}  ({', '.join(g['files'])})" for g in report["governing"]]
    if report["superseded"]:
        lines.append("superseded, not judged:")
        lines += [f"  {g['decision']}  superseded by {', '.join(g.get('superseded_by') or ['a later decision'])}" for g in report["superseded"]]
    if report.get("closed"):
        lines.append(f"closed by valid_until (today is {report['today']}), not judged:")
        lines += [f"  {g['decision']}  valid_until {g['valid_until']}" for g in report["closed"]]
    lines.append(f"rules that cover a changed file: {sum(1 for r in report['rules'] if r['files'])}")
    lines.append(f"violations: {len(report['violations'])}")
    lines += result_lines(report["violations"])
    lines.append(f"cannot be judged: {len(report['unresolved'])}")
    lines += result_lines(report["unresolved"])
    if report.get("waived"):
        lines.append(f"waived, not counted as violations (today is {report['today']}): {len(report['waived'])}")
        lines += waived_lines(report["waived"])
    if report.get(rules.EXPIRING):
        lines.append(f"waivers that expire soon, still waiving (today is {report['today']}): {len(report[rules.EXPIRING])}")
        lines += expiring_lines(report[rules.EXPIRING])
    if report.get("rule_problems"):
        lines.append("rules that cannot be checked:")
        lines += [f"  {p['decision']}  {p['rule'] or 'rule'}: {p['problem']}" for p in report["rule_problems"]]
    if report.get("unread_decisions"):
        lines.append(f"decision files not read, so their rules are not judged: {len(report['unread_decisions'])}")
        lines += [f"  {u['file']}: {u['reason']}" for u in report["unread_decisions"]]
    if report.get("codeowners"):
        owned = report["codeowners"]
        lines.append(f"CODEOWNERS owners of changed files, shown and not enforced: {len(owned['files'])}")
        lines += [f"  {o['file']}  {' '.join(o['owners'])}" for o in owned["files"]]
        lines.append(owned["note"])
    return "\n".join(lines)
