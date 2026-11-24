from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable

from . import semver
from .inventory.actions import DOCKER as DOCKER_USE
from .inventory.actions import LOCAL as LOCAL_USE
from .inventory.actions import local
from .inventory.shape import UNKNOWN_LICENSES

SEVERITY = ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]
SCOPES = ("all", "shipped")
MODIFIERS = ("dependencies",)
OPERATORS = ("AND", "OR", "WITH")
MATCH, CLEAR, UNKNOWN = "match", "clear", "unknown"
VERDICT = {MATCH: "violated", CLEAR: "not_violated", UNKNOWN: "unresolved"}
SHIPPED_ONLY = "reached only through development dependencies; the rule covers shipped ones"
_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:-]*$")
COMMIT = re.compile(r"[0-9a-f]{40}")
PINNED = "GitHub Actions"


@dataclass(frozen=True)
class Rule:
    kind: str
    value: tuple
    dependencies: str = "all"


@dataclass(frozen=True)
class Problem:
    kind: str | None
    reason: str


@dataclass(frozen=True)
class Parsed:
    rules: tuple[Rule, ...] = ()
    problems: tuple[Problem, ...] = ()
    stated: bool = False


@dataclass(frozen=True)
class Kind:
    subject: str
    read: Callable[[object], tuple]
    judge: Callable[[tuple, dict], tuple[str, str]]


def _severity(value) -> tuple:
    if value not in SEVERITY:
        raise ValueError(f"advisory_severity_at_least must be one of {', '.join(SEVERITY)}, not {value!r}")
    return (value,)


def _advisory(value: tuple, facts: dict) -> tuple[str, str]:
    status, severity, floor = facts["status"], facts["severity"], value[0]
    if status == "affected" and severity in SEVERITY and SEVERITY.index(severity) >= SEVERITY.index(floor):
        return MATCH, f"severity {severity} is at or above {floor}"
    return CLEAR, f"status {status}, severity {severity}"


def _license_list(name: str):
    def read(value) -> tuple:
        if not isinstance(value, list) or not value or not all(isinstance(x, str) and _ID.match(x) for x in value):
            raise ValueError(f"{name} must be a non-empty list of SPDX license ids")
        return tuple(value)
    return read


def license_tree(expression: str):
    tokens = _TOKEN.findall(expression or "")
    if not tokens:
        return None
    try:
        tree, end = _any_of(tokens, 0)
    except (IndexError, ValueError):
        return None
    return tree if end == len(tokens) else None


def _joined(tokens: list[str], i: int, word: str, part) -> tuple:
    node, i = part(tokens, i)
    parts = [node]
    while i < len(tokens) and tokens[i].upper() == word:
        node, i = part(tokens, i + 1)
        parts.append(node)
    return (parts[0] if len(parts) == 1 else (word.lower(), tuple(parts))), i


def _any_of(tokens: list[str], i: int) -> tuple:
    return _joined(tokens, i, "OR", _all_of)


def _all_of(tokens: list[str], i: int) -> tuple:
    return _joined(tokens, i, "AND", _term)


def _word(token: str) -> str:
    if token in ("(", ")") or token.upper() in OPERATORS or token in UNKNOWN_LICENSES or not _ID.match(token):
        raise ValueError(token)
    return token


def _term(tokens: list[str], i: int) -> tuple:
    if tokens[i] == "(":
        node, i = _any_of(tokens, i + 1)
        if tokens[i] != ")":
            raise ValueError(tokens[i])
        return node, i + 1
    word = _word(tokens[i])
    if i + 1 < len(tokens) and tokens[i + 1].upper() == "WITH":
        _word(tokens[i + 2])
        return ("id", word), i + 3
    return ("id", word), i + 1


def satisfiable(tree: tuple, ok: Callable[[str], bool]) -> bool:
    kind, body = tree
    if kind == "id":
        return ok(body)
    results = [satisfiable(part, ok) for part in body]
    return any(results) if kind == "or" else all(results)


def _expression(facts: dict) -> str:
    return facts.get("license_expression") or " AND ".join(facts.get("licenses") or [])


def _unknown_license(expression: str) -> tuple[str, str]:
    shown = f"license {expression!r} is not an SPDX expression" if expression else "the inventory gives no license"
    return UNKNOWN, f"{shown}; it cannot be judged"


def _license_denied(value: tuple, facts: dict) -> tuple[str, str]:
    expression = _expression(facts)
    tree = license_tree(expression)
    if tree is None:
        return _unknown_license(expression)
    denied = {x.lower() for x in value}
    if satisfiable(tree, lambda x: x.lower() not in denied):
        return CLEAR, f"license {expression} can be used without a denied license"
    return MATCH, f"license {expression} cannot be used without a denied license ({', '.join(value)})"


def _license_allowed(value: tuple, facts: dict) -> tuple[str, str]:
    expression = _expression(facts)
    tree = license_tree(expression)
    if tree is None:
        return _unknown_license(expression)
    allowed = {x.lower() for x in value}
    if satisfiable(tree, lambda x: x.lower() in allowed):
        return CLEAR, f"license {expression} can be used with allowed licenses only"
    return MATCH, f"license {expression} cannot be used with allowed licenses only ({', '.join(value)})"


def _package_spec(spec) -> dict:
    keys = {"ecosystem", "name", "versions"}
    if not isinstance(spec, dict) or set(spec) - keys or not all(isinstance(spec.get(k), str) and spec[k] for k in ("ecosystem", "name")):
        raise ValueError("package_denied must be a non-empty list of {ecosystem, name, versions?} mappings")
    versions = spec.get("versions")
    if versions is not None and (not isinstance(versions, list) or not versions or not all(isinstance(v, str) and v for v in versions)):
        raise ValueError(f"package_denied versions of {spec['name']} must be a non-empty list of exact versions")
    return {"ecosystem": spec["ecosystem"], "name": spec["name"], "versions": tuple(versions) if versions else ()}


def _packages(value) -> tuple:
    if not isinstance(value, list) or not value:
        raise ValueError("package_denied must be a non-empty list of {ecosystem, name, versions?} mappings")
    return tuple(_package_spec(spec) for spec in value)


def same_version(version: str, versions: tuple, ecosystem: str) -> bool:
    if version in versions:
        return True
    key = semver.order(ecosystem)
    if key is None:
        return False
    try:
        mine = key(version)
    except ValueError:
        return False
    for v in versions:
        try:
            if key(v) == mine:
                return True
        except ValueError:
            continue
    return False


def _denied_by(spec: dict, facts: dict) -> bool:
    if not semver.same_package(spec["ecosystem"], spec["name"], facts):
        return False
    return not spec["versions"] or same_version(facts.get("version") or "", spec["versions"], spec["ecosystem"])


def _package_denied(value: tuple, facts: dict) -> tuple[str, str]:
    shown = f"{facts.get('ecosystem')} {facts.get('name')} {facts.get('version')}"
    hit = next((spec for spec in value if _denied_by(spec, facts)), None)
    if hit is None:
        return CLEAR, f"{shown} is not a denied package"
    which = f"versions {', '.join(hit['versions'])}" if hit["versions"] else "every version"
    return MATCH, f"{shown} is denied ({which})"


def _allowed_spec(spec) -> dict:
    if not isinstance(spec, dict) or set(spec) != {"ecosystem", "name"} or not all(isinstance(spec[k], str) and spec[k] for k in spec):
        raise ValueError("package_allowed must be a non-empty list of {ecosystem, name} mappings")
    return {"ecosystem": spec["ecosystem"], "name": spec["name"]}


def _allowlist(value) -> tuple:
    if not isinstance(value, list) or not value:
        raise ValueError("package_allowed must be a non-empty list of {ecosystem, name} mappings")
    return tuple(_allowed_spec(spec) for spec in value)


def unnamed_use(facts: dict) -> str | None:
    if (facts.get("ecosystem") or "").lower() != PINNED.lower() or facts.get("version"):
        return None
    name = facts.get("name") or ""
    if facts.get("unresolved") == LOCAL_USE and local(name):
        return "local"
    return "docker" if facts.get("unresolved") == DOCKER_USE and name.startswith("docker://") else "unknown"


def _package_allowed(value: tuple, facts: dict) -> tuple[str, str]:
    ecosystem = facts.get("ecosystem") or ""
    shown = f"{ecosystem} {facts.get('name')} {facts.get('version')}"
    named = [spec for spec in value if spec["ecosystem"].lower() == ecosystem.lower()]
    if not named:
        return CLEAR, f"the allowlist names no {ecosystem or 'package without an ecosystem'} packages"
    use = unnamed_use(facts)
    if use == "local":
        return CLEAR, f"{facts.get('name')} is a local action in this repository, which the allowlist allows"
    if use == "docker":
        return UNKNOWN, f"{facts.get('name')} is a Docker image, not an action the allowlist can name; it cannot be judged"
    if use == "unknown":
        return UNKNOWN, f"uses {facts.get('name')!r} names no action, so it cannot be shown to be on the allowlist"
    if any(semver.same_package(spec["ecosystem"], spec["name"], facts) for spec in named):
        return CLEAR, f"{shown} is on the allowlist"
    return MATCH, f"{shown} is not on the allowlist of {ecosystem} packages ({', '.join(spec['name'] for spec in named)})"


def _pin(value) -> tuple:
    if value is not True:
        raise ValueError(f"pinned_to_commit must be true, not {value!r}")
    return (True,)


def _pinned(value: tuple, facts: dict) -> tuple[str, str]:
    ecosystem, name, version = facts.get("ecosystem") or "", facts.get("name"), facts.get("version") or ""
    if ecosystem.lower() != PINNED.lower():
        return CLEAR, f"pinned_to_commit covers {PINNED} only, not {ecosystem or 'a package without an ecosystem'}"
    use = unnamed_use(facts)
    if use == "local":
        return CLEAR, f"{name} is a local action, read at the same commit as the workflow"
    if use == "docker":
        return UNKNOWN, f"{name} is a Docker image, not pinned to a commit; whether it is pinned to a digest is not checked"
    if use == "unknown":
        return UNKNOWN, f"uses {name!r} names no action, so it cannot be shown to be pinned to a commit"
    if COMMIT.fullmatch(version):
        return CLEAR, f"{name} is pinned to commit {version}"
    return MATCH, f"{name} is pinned to {version!r}, not to a full 40-character commit SHA"


KINDS: dict[str, Kind] = {
    "advisory_severity_at_least": Kind("advisory", _severity, _advisory),
    "license_denied": Kind("license", _license_list("license_denied"), _license_denied),
    "license_allowed": Kind("license", _license_list("license_allowed"), _license_allowed),
    "package_denied": Kind("package", _packages, _package_denied),
    "package_allowed": Kind("allowlist", _allowlist, _package_allowed),
    "pinned_to_commit": Kind("pin", _pin, _pinned),
}


def subjects() -> list[str]:
    return sorted({k.subject for k in KINDS.values()})


def _known() -> str:
    return ", ".join(sorted(KINDS))


def _entry(entry) -> tuple[list[Rule], list[Problem]]:
    if not isinstance(entry, dict):
        return [], [Problem(None, f"a rule must be a mapping or a list of mappings, not {type(entry).__name__}")]
    scope = entry.get("dependencies", "all")
    kinds = [k for k in entry if k not in MODIFIERS]
    if not kinds:
        return [], [Problem(None, f"the rule names no kind; known kinds: {_known()}")]
    if scope not in SCOPES:
        return [], [Problem(k, f"dependencies must be shipped or all, not {scope!r}") for k in kinds]
    rules, problems = [], []
    for k in kinds:
        if k not in KINDS:
            problems.append(Problem(k, f"unknown rule kind {k}; known kinds: {_known()}"))
            continue
        try:
            rules.append(Rule(k, KINDS[k].read(entry[k]), scope))
        except ValueError as e:
            problems.append(Problem(k, str(e)))
    return rules, problems


def parse(raw) -> Parsed:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return Parsed()
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            return Parsed(problems=(Problem(None, f"the rule is not valid JSON ({e.msg})"),), stated=True)
    entries = raw if isinstance(raw, list) else [raw]
    if not entries:
        return Parsed(problems=(Problem(None, "the rule is an empty list"),), stated=True)
    rules, problems = [], []
    for entry in entries:
        r, p = _entry(entry)
        rules += r
        problems += p
    return Parsed(tuple(rules), tuple(problems), True)


def of(decision: dict) -> Parsed:
    return parse((decision.get("props") or {}).get("rule"))


def outcome(rule: Rule, facts: dict) -> tuple[str, str]:
    return KINDS[rule.kind].judge(rule.value, facts)


def verdict(rule: Rule, facts: dict, dev: bool) -> tuple[str, str]:
    if rule.dependencies == "shipped" and dev:
        return "not_violated", SHIPPED_ONLY
    result, why = outcome(rule, facts)
    return VERDICT[result], why


def judging(parsed: Parsed, subject: str) -> list[Rule]:
    return [r for r in parsed.rules if KINDS[r.kind].subject == subject]
