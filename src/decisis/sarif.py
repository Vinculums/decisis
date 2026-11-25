"""SARIF 2.1.0 logs of the `check` and `audit` reports, for GitHub code scanning.

One run holds one report. The tool driver is `decisis` with its installed version, and each rule kind that judged
something is a `reportingDescriptor`. A violated result is an `error` and an unresolved one a `warning`; a waived one
keeps `error` and carries an external, accepted suppression whose justification is the waiver. A result that is not
violated is left out. `check` points each result at the changed file and the import line, `audit` at the inventory
file. Every result has a `partialFingerprints` value hashed from the decision, the rule kind, the file and the import
or package, so a later run of the same finding is the same alert.

Report text comes from snapshots and pull requests and is only ever put into JSON values: a message has its link
syntax escaped, a location is a percent-encoded repository-relative path or none, and nothing is formatted into
markup. A path that is absolute, leaves the repository, names a drive or holds a backslash gets no location.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from importlib import metadata
from pathlib import Path
from urllib.parse import quote

from . import rules
from .inventory.siblings import repository_root

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
VERSION = "2.1.0"
TOOL = "decisis"
URI = "https://github.com/Vinculums/decisis"
FINGERPRINT = "decisis/v1"
ERROR, WARNING = "error", "warning"
ADVISORY_RULE = "advisory_severity_at_least"
VIOLATED, UNRESOLVED = "violated", "unresolved"
JUDGED = (VIOLATED, UNRESOLVED, "not_violated", rules.WAIVED)
CHECK_LISTS = (("violations", ERROR), ("unresolved", WARNING), ("waived", ERROR))
DRIVE = re.compile(r"^[A-Za-z]:")
RULE_TEXT = {
    "advisory_severity_at_least": "A dependency has an advisory at or above the severity a decision sets",
    "license_denied": "A dependency is under a license a decision denies",
    "license_allowed": "A dependency is under a license a decision does not allow",
    "package_denied": "A dependency is a package a decision denies",
    "package_allowed": "A dependency is outside the allowlist a decision sets",
    "pinned_to_commit": "A GitHub Actions use is not pinned to the full commit SHA a decision requires",
    "review_required": "A changed file lacks a review a decision requires",
    "imports_forbidden": "A changed file imports a path a decision forbids",
}


def tool_version() -> str | None:
    try:
        return metadata.version(TOOL)
    except metadata.PackageNotFoundError:
        return None


def data(value):
    if isinstance(value, str):
        return "".join("�" if "\ud800" <= c <= "\udfff" else c for c in value)
    if isinstance(value, dict):
        return {data(str(k)): data(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [data(v) for v in value]
    return value


def message(*parts) -> dict:
    text = data(": ".join(str(p) for p in parts if p not in (None, "")))
    return {"text": text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")}


def relative(path) -> str | None:
    if not isinstance(path, str) or not path.strip() or DRIVE.match(path) or "\\" in path:
        return None
    flat = posixpath.normpath(data(path))
    if flat.startswith("/") or flat in (".", "..") or flat.startswith("../"):
        return None
    return flat


def inventory_path(path: Path, root: Path | None = None) -> str | None:
    base = path.parent.resolve()
    top = (root or repository_root(base)).resolve()
    if not base.is_relative_to(top):
        return None
    return relative((base / path.name).relative_to(top).as_posix())


def location(path, line=None, base: str = "") -> list[dict]:
    name = relative(path)
    joined = relative(posixpath.join(base, name)) if name and base else name
    if joined is None:
        return []
    found = {"artifactLocation": {"uri": quote(joined, safe="/")}}
    if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
        found["region"] = {"startLine": line}
    return [{"physicalLocation": found}]


def fingerprint(parts: list, seen: dict[str, int]) -> dict:
    text = json.dumps([data(str(p or "")) for p in parts], separators=(",", ":"))
    digest = hashlib.sha256(text.encode("ascii")).hexdigest()
    seen[digest] = seen.get(digest, 0) + 1
    return {FINGERPRINT: digest if seen[digest] == 1 else f"{digest}:{seen[digest]}"}


def justification(w: dict) -> str:
    return data(f"waiver {w.get('waiver')} until {w.get('expires')}, approved by {w.get('approved_by')}: {w.get('reason')}")


def result(rule: str, level: str, text: dict, where: list[dict], prints: dict, props: dict, waiver: dict | None = None) -> dict:
    out = {"ruleId": data(rule), "level": level, "message": text, **({"locations": where} if where else {}),
           "partialFingerprints": prints, "properties": data(props)}
    if waiver:
        out["suppressions"] = [{"kind": "external", "status": "accepted", "justification": justification(waiver)}]
    return out


def descriptors(kinds: set[str]) -> list[dict]:
    return [{"id": data(k), "shortDescription": {"text": RULE_TEXT.get(k) or message(k)["text"]}, "defaultConfiguration": {"level": ERROR}}
            for k in sorted(kinds)]


def run(results: list[dict], kinds: set[str], category: str, version: str | None) -> dict:
    index = {d["id"]: i for i, d in enumerate(descriptors(kinds))}
    version = version or tool_version()
    driver = {"name": TOOL, **({"version": version} if version else {}), "informationUri": URI, "rules": descriptors(kinds)}
    return {"tool": {"driver": driver}, "automationDetails": {"id": data(category)},
            "results": [{**r, "ruleIndex": index[r["ruleId"]]} for r in results]}


def check_run(report: dict, version: str | None = None, base: str = "") -> dict:
    out: list[dict] = []
    seen: dict[str, int] = {}
    for key, level in CHECK_LISTS:
        for r in report.get(key) or []:
            file, rule, decision = r.get("file"), r.get("rule") or "rule", r.get("decision")
            target = r.get("target")
            props = {"decision": decision, "rule": rule, "file": file, "import": r.get("import"), "target": target,
                     "path": [file, target] if target else [file], "waiver": r.get("waiver")}
            prints = fingerprint([decision, rule, posixpath.join(base, file) if base and isinstance(file, str) else file, r.get("import")], seen)
            out.append(result(rule, level, message(decision, r.get("why")), location(file, r.get("line"), base), prints, props,
                              r.get("waiver") if key == "waived" else None))
    kinds = {r.get("rule") or "rule" for r in report.get("rules") or [] if r.get("files")} | {r["ruleId"] for r in out}
    return run(out, kinds, "decisis/check/", version)


def policy_rule(finding: dict, policy: dict) -> str:
    return policy.get("rule") or (ADVISORY_RULE if finding.get("advisory") else str(finding.get("kind") or "rule"))


def audit_run(report: dict, inventory: str | None = None, version: str | None = None) -> dict:
    out: list[dict] = []
    kinds: set[str] = set()
    seen: dict[str, int] = {}
    for f in report.get("findings") or []:
        package, advisory = f.get("package"), f.get("advisory")
        for p in f.get("policies") or []:
            verdict = p.get("verdict")
            if verdict not in JUDGED:
                continue
            rule = policy_rule(f, p)
            kinds.add(rule)
            if verdict == "not_violated":
                continue
            what = f"{package} ({advisory})" if advisory else package
            props = {"decision": p.get("decision"), "rule": rule, "package": package, "advisory": advisory, "path": f.get("path") or [],
                     "waiver": p.get("waiver")}
            prints = fingerprint([p.get("decision"), rule, inventory, package, advisory], seen)
            out.append(result(rule, WARNING if verdict == UNRESOLVED else ERROR, message(p.get("decision"), f"{what}: {p.get('why')}"),
                              location(inventory), prints, props, p.get("waiver") if verdict == rules.WAIVED else None))
    name = relative(inventory) or "inventory"
    return run(out, kinds, f"decisis/audit/{name}/", version)


def log(runs: list[dict]) -> dict:
    return {"$schema": SCHEMA, "version": VERSION, "runs": runs}


def dumps(document: dict) -> str:
    return json.dumps(document, indent=1) + "\n"
