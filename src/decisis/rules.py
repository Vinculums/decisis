from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

from . import codeowners, semver
from .inventory.actions import DOCKER as DOCKER_USE
from .inventory.actions import LOCAL as LOCAL_USE
from .inventory.actions import local
from .inventory.shape import UNKNOWN_LICENSES

SEVERITY = ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]
SCOPES = ("all", "shipped")
MODIFIERS = ("dependencies",)
OPERATORS = ("AND", "OR", "WITH")
MAX_LICENSE_DEPTH = 64
MATCH, CLEAR, UNKNOWN = "match", "clear", "unknown"
VERDICT = {MATCH: "violated", CLEAR: "not_violated", UNKNOWN: "unresolved"}
SHIPPED_ONLY = "reached only through development dependencies; the rule covers shipped ones"
_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:-]*$")
COMMIT = re.compile(r"[0-9a-f]{40}")
PINNED = "GitHub Actions"
_HANDLE = re.compile(r"^@?[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?(?:/[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)?$")


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
class Waiver:
    index: int
    reason: str
    expires: datetime.date
    approved_by: str
    ecosystem: str | None = None
    name: str | None = None
    versions: tuple[str, ...] = ()
    advisory: str | None = None
    path: str | None = None
    to: str | None = None
    rule: str | None = None


@dataclass(frozen=True)
class Parsed:
    rules: tuple[Rule, ...] = ()
    problems: tuple[Problem, ...] = ()
    stated: bool = False
    waivers: tuple[Waiver, ...] = ()
    waiver_problems: tuple[Problem, ...] = ()


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
        tree, end = _any_of(tokens, 0, 0)
    except (IndexError, ValueError):
        return None
    return tree if end == len(tokens) else None


def _joined(tokens: list[str], i: int, word: str, part, depth: int) -> tuple:
    node, i = part(tokens, i, depth)
    parts = [node]
    while i < len(tokens) and tokens[i].upper() == word:
        node, i = part(tokens, i + 1, depth)
        parts.append(node)
    return (parts[0] if len(parts) == 1 else (word.lower(), tuple(parts))), i


def _any_of(tokens: list[str], i: int, depth: int = 0) -> tuple:
    return _joined(tokens, i, "OR", _all_of, depth)


def _all_of(tokens: list[str], i: int, depth: int = 0) -> tuple:
    return _joined(tokens, i, "AND", _term, depth)


def _word(token: str) -> str:
    if token in ("(", ")") or token.upper() in OPERATORS or token in UNKNOWN_LICENSES or not _ID.match(token):
        raise ValueError(token)
    return token


def _term(tokens: list[str], i: int, depth: int = 0) -> tuple:
    if tokens[i] == "(":
        if depth >= MAX_LICENSE_DEPTH:
            raise ValueError("license expression nesting too deep")
        node, i = _any_of(tokens, i + 1, depth + 1)
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


def _globs(name: str, key: str, value) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x.strip() for x in value):
        raise ValueError(f"{name} {key} must be a non-empty list of path globs")
    for glob in value:
        try:
            codeowners.compile_pattern(glob.strip())
        except codeowners.Unsupported as e:
            raise ValueError(f"{name} {key}: {e}") from None
    return tuple(x.strip() for x in value)


def _mapping(name: str, value, keys: tuple[str, str]) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{name} must be a mapping with exactly the keys {' and '.join(keys)}")
    return value


def _handles(value) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and _HANDLE.match(x) for x in value):
        raise ValueError("review_required reviewers must be a non-empty list of handles such as @alice or @org/team")
    return tuple(value)


def _review_rule(value) -> tuple:
    m = _mapping("review_required", value, ("paths", "reviewers"))
    return _globs("review_required", "paths", m["paths"]), _handles(m["reviewers"])


def _import_rule(value) -> tuple:
    m = _mapping("imports_forbidden", value, ("from", "to"))
    return _globs("imports_forbidden", "from", m["from"]), _globs("imports_forbidden", "to", m["to"])


def handle_key(handle: str) -> str:
    return handle if "/" in handle else handle.lstrip("@").lower()


@lru_cache(maxsize=4096)
def glob_regex(glob: str):
    return codeowners.compile_pattern(glob)


def matches(globs: tuple[str, ...], path: str | None) -> str | None:
    if not path:
        return None
    return next((g for g in globs if glob_regex(g).fullmatch(path)), None)


def _review(value: tuple, facts: dict) -> tuple[str, str]:
    paths, wanted = value
    glob = matches(paths, facts["file"])
    if glob is None:
        return CLEAR, "the rule does not cover this file"
    given = {handle_key(h) for h in facts.get("reviewers") or ()}
    found = [h for h in wanted if handle_key(h) in given]
    if found:
        return CLEAR, f"{glob} needs a review from {' or '.join(wanted)}; {', '.join(found)} reviewed"
    return MATCH, f"{glob} needs a review from {' or '.join(wanted)}; none of them is among the reviewers given"


def _package_target(to: tuple[str, ...], target: str) -> str | None:
    return matches(tuple(g for g in to if "node_modules" in g), target)


def _named(to: tuple[str, ...], paths: tuple[str, ...]) -> tuple[str | None, str | None]:
    return next(((g, p) for p in paths if (g := matches(to, p))), (None, None))


def _unresolved(to: tuple[str, ...], shown: str, target: str | None, also: tuple[str, ...], why: str) -> tuple[str, str]:
    if target and _named(to, (target, *also))[0] is None and _package_target(to, target) is None:
        return CLEAR, f"{shown}: {why}; even read as an import it names {target}, which no forbidden glob names"
    return UNKNOWN, f"{shown}: {why}; it cannot be judged"


def _import(value: tuple, facts: dict) -> tuple[str, str]:
    source, to = value
    glob = matches(source, facts["file"])
    if glob is None:
        return CLEAR, "the rule does not cover this file"
    shown, resolution, target = facts["specifier"], facts["resolution"], facts.get("target")
    also = tuple(facts.get("also") or ())
    if resolution == "unresolved":
        return _unresolved(to, shown, target, also, facts["why"])
    hit, path = (_package_target(to, target), target) if resolution == "external" else _named(to, (target, *also))
    if hit is None:
        where = "an external package" if resolution == "external" else target
        return CLEAR, f"{shown} is {where}, which no forbidden glob names"
    held = "" if path == target else f", which holds {path}"
    return MATCH, f"{glob} must not import {hit}; {shown} is {target}{held}"


KINDS: dict[str, Kind] = {
    "advisory_severity_at_least": Kind("advisory", _severity, _advisory),
    "license_denied": Kind("license", _license_list("license_denied"), _license_denied),
    "license_allowed": Kind("license", _license_list("license_allowed"), _license_allowed),
    "package_denied": Kind("package", _packages, _package_denied),
    "package_allowed": Kind("allowlist", _allowlist, _package_allowed),
    "pinned_to_commit": Kind("pin", _pin, _pinned),
    "review_required": Kind("review", _review_rule, _review),
    "imports_forbidden": Kind("import", _import_rule, _import),
}
PACKAGE_SUBJECTS = ("license", "package", "allowlist", "pin")
CHANGE_SUBJECTS = ("review", "import")


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
    props = decision.get("props") or {}
    parsed = parse(props.get("rule"))
    found, problems = waivers(props.get("waivers"))
    return Parsed(parsed.rules, parsed.problems, parsed.stated, found, problems)


WAIVED = "waived"
WAIVERS = "waivers"
EXPIRING = "expiring_soon"
WARN_DAYS = 14
MAX_WARN_DAYS = 3650
WAIVER_TEXT = ("reason", "approved_by")
WAIVER_KEYS = ("reason", "expires", "approved_by", "package", "advisory", "path", "to", "rule")
AUDIT_SUBJECTS = ("advisory", *PACKAGE_SUBJECTS)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def date_of(text, what: str) -> datetime.date:
    if isinstance(text, str) and _DATE.fullmatch(text):
        try:
            return datetime.date.fromisoformat(text)
        except ValueError:
            pass
    raise ValueError(f"{what} must be a date such as 2026-01-31, not {text!r}")


def today(text: str | None = None) -> datetime.date:
    if text is None:
        return datetime.datetime.now(datetime.timezone.utc).date()
    return date_of(text, "today")


def _line(value, key: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{key} must be one line of text")
    return value.strip()


def _glob(value, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a path glob")
    try:
        codeowners.compile_pattern(value.strip())
    except codeowners.Unsupported as e:
        raise ValueError(f"{key}: {e}") from None
    return value.strip()


def _waived_package(value) -> tuple[str, str, tuple[str, ...]]:
    if not isinstance(value, dict) or set(value) - {"ecosystem", "name", "versions"} or \
            not all(isinstance(value.get(k), str) and value[k].strip() for k in ("ecosystem", "name")):
        raise ValueError("package must be a mapping with ecosystem, name and optional versions")
    versions = value.get("versions")
    if versions is not None and (not isinstance(versions, list) or not versions or not all(isinstance(v, str) and v.strip() for v in versions)):
        raise ValueError("package versions must be a non-empty list of exact versions")
    return value["ecosystem"].strip(), value["name"].strip(), tuple(v.strip() for v in versions or ())


def _waived_rule(value, subjects: tuple[str, ...], form: str) -> str:
    if not isinstance(value, str) or value not in KINDS or KINDS[value].subject not in subjects:
        known = ", ".join(sorted(k for k in KINDS if KINDS[k].subject in subjects))
        raise ValueError(f"rule must name a rule kind a {form} waiver can cover ({known}), not {value!r}")
    return value


def _advisory_id(value) -> str:
    if not isinstance(value, str) or not _ID.match(value) or value.lower().startswith("adv:"):
        raise ValueError(f"advisory must be an OSV id such as GHSA-xxxx-xxxx-xxxx, without adv:, not {value!r}")
    return value


def _waiver(index: int, entry) -> Waiver:
    if not isinstance(entry, dict):
        raise ValueError(f"a waiver must be a mapping, not {type(entry).__name__}")
    unknown = sorted(str(k) for k in entry if k not in WAIVER_KEYS)
    if unknown:
        raise ValueError(f"unknown key {', '.join(unknown)}; a waiver has {', '.join(WAIVER_KEYS)}")
    missing = [k for k in ("reason", "expires", "approved_by") if k not in entry]
    if missing:
        raise ValueError(f"it has no {' and no '.join(missing)}")
    if ("package" in entry) == ("path" in entry):
        raise ValueError("it must name a package (for audit) or a path glob (for check), exactly one of them")
    base = {"index": index, "reason": _line(entry["reason"], "reason"), "approved_by": _line(entry["approved_by"], "approved_by"),
            "expires": date_of(entry["expires"], "expires")}
    if "package" in entry:
        if "to" in entry:
            raise ValueError("to goes with a path waiver, not a package waiver")
        ecosystem, name, versions = _waived_package(entry["package"])
        advisory = _advisory_id(entry["advisory"]) if "advisory" in entry else None
        subjects = ("advisory",) if advisory else AUDIT_SUBJECTS
        rule = _waived_rule(entry["rule"], subjects, "package" + (" and advisory" if advisory else "")) if "rule" in entry else None
        return Waiver(**base, ecosystem=ecosystem, name=name, versions=versions, advisory=advisory, rule=rule)
    if "advisory" in entry:
        raise ValueError("advisory goes with a package waiver, not a path waiver")
    to = _glob(entry["to"], "to") if "to" in entry else None
    subjects = ("import",) if to else CHANGE_SUBJECTS
    rule = _waived_rule(entry["rule"], subjects, "path" + (" and to" if to else "")) if "rule" in entry else None
    return Waiver(**base, path=_glob(entry["path"], "path"), to=to, rule=rule)


def waivers(raw) -> tuple[tuple[Waiver, ...], tuple[Problem, ...]]:
    if raw is None:
        return (), ()
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            return (), (Problem(WAIVERS, f"waivers is not valid JSON ({e.msg})"),)
    if not isinstance(raw, list) or not raw:
        return (), (Problem(WAIVERS, "waivers must be a non-empty list of waiver mappings"),)
    found, problems = [], []
    for i, entry in enumerate(raw, 1):
        try:
            found.append(_waiver(i, entry))
        except ValueError as e:
            problems.append(Problem(WAIVERS, f"waiver {i} waives nothing: {e}"))
    return tuple(found), tuple(problems)


def _module(path: str) -> str:
    key = path.rstrip("/")
    if key.endswith(".rs"):
        return key[:-3]
    return key.rpartition("/")[0] if key.endswith(".go") else key


def _to_covers(w: Waiver, rule: Rule, facts: dict) -> bool:
    to, target = rule.value[1], facts.get("target")
    if facts.get("resolution") == "external":
        return bool(target and _package_target(to, target) and matches((w.to,), target))
    named = [p for p in (target, *(facts.get("also") or ())) if p]
    forbidden = {_module(p) for p in named if matches(to, p)}
    return bool(forbidden) and all(any(matches((w.to,), p) for p in named if _module(p) == m) for m in forbidden)


def covers(w: Waiver, rule: Rule, facts: dict) -> bool:
    subject = KINDS[rule.kind].subject
    if w.rule is not None and w.rule != rule.kind:
        return False
    if w.ecosystem is not None:
        if subject not in AUDIT_SUBJECTS or (w.advisory is not None and (subject != "advisory" or facts.get("advisory") != w.advisory)):
            return False
        if not semver.same_package(w.ecosystem, w.name, facts):
            return False
        return not w.versions or same_version(facts.get("version") or "", w.versions, w.ecosystem)
    if subject not in CHANGE_SUBJECTS or matches((w.path,), facts.get("file")) is None:
        return False
    if w.to is None:
        return True
    return subject == "import" and _to_covers(w, rule, facts)


def shown(w: Waiver) -> dict:
    return {"waiver": w.index, "reason": w.reason, "expires": w.expires.isoformat(), "approved_by": w.approved_by}


def waived(rule: Rule, facts: dict, dev: bool, found: tuple[Waiver, ...], day: datetime.date) -> dict:
    verdict_, why = verdict(rule, facts, dev)
    out = {"verdict": verdict_, "why": why}
    hits = [w for w in found if covers(w, rule, facts)] if verdict_ == VERDICT[MATCH] else []
    if not hits:
        return out
    active = [w for w in hits if day <= w.expires]
    if active:
        w = max(active, key=lambda w: (w.expires, -w.index))
        return {"verdict": WAIVED, "why": why, "waiver": shown(w)}
    w = max(hits, key=lambda w: (w.expires, -w.index))
    return {**out, "why": f"{why}; waiver {w.index} ({w.reason}, approved by {w.approved_by}) expired at the end of {w.expires.isoformat()}",
            "expired_waiver": shown(w)}


def expiring_soon(waived_by: list[tuple[str, dict]], day: datetime.date, warn_days: int) -> list[dict]:
    if warn_days <= 0:
        return []
    found: dict[tuple[str, int], dict] = {}
    for decision, w in waived_by:
        left = (datetime.date.fromisoformat(w["expires"]) - day).days
        if left <= warn_days:
            found[(decision, w["waiver"])] = {"decision": decision, "waiver": w["waiver"], "reason": w["reason"],
                                              "approved_by": w["approved_by"], "expires": w["expires"], "days_left": left}
    return sorted(found.values(), key=lambda e: (e["expires"], e["decision"], e["waiver"]))


def outcome(rule: Rule, facts: dict) -> tuple[str, str]:
    return KINDS[rule.kind].judge(rule.value, facts)


def verdict(rule: Rule, facts: dict, dev: bool) -> tuple[str, str]:
    if rule.dependencies == "shipped" and dev:
        return "not_violated", SHIPPED_ONLY
    result, why = outcome(rule, facts)
    return VERDICT[result], why


def judging(parsed: Parsed, subject: str) -> list[Rule]:
    return [r for r in parsed.rules if KINDS[r.kind].subject == subject]
