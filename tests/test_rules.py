from __future__ import annotations

import copy
import json

import pytest

from decisis import audit, checker, cvss, external, render, rules
from decisis import checkout as co
from decisis import commit as wb

DENY_GPL = {"license_denied": ["GPL-3.0-only"]}
ALLOW_PERMISSIVE = {"license_allowed": ["MIT", "Apache-2.0", "ISC"]}
DENY_EVENT_STREAM = {"package_denied": [{"ecosystem": "npm", "name": "event-stream", "versions": ["3.3.6"]}]}

LOCK = {
    "name": "shop", "version": "1.0.0", "lockfileVersion": 3,
    "packages": {
        "": {"name": "shop", "version": "1.0.0",
             "dependencies": {"gpl-lib": "1.0.0", "dual": "2.0.0", "event-stream": "3.3.6", "mystery": "1.0.0"},
             "devDependencies": {"gpl-tool": "1.0.0"}},
        "node_modules/gpl-lib": {"version": "1.0.0", "license": "GPL-3.0-only"},
        "node_modules/dual": {"version": "2.0.0", "license": "(MIT OR GPL-3.0-only)", "dependencies": {"both": "1.0.0"}},
        "node_modules/both": {"version": "1.0.0", "license": "MIT AND GPL-3.0-only"},
        "node_modules/event-stream": {"version": "3.3.6", "license": "MIT"},
        "node_modules/mystery": {"version": "1.0.0", "license": "SEE LICENSE IN LICENSE.md"},
        "node_modules/gpl-tool": {"version": "1.0.0", "license": "GPL-3.0-only", "dev": True},
    },
}


def no_advisories(packages):
    return [], []


def snapshot(*decisions: tuple[str, object]) -> co.Subgraph:
    nodes = [{"id": "concept:shop", "kind": "concept", "title": "Shop", "props": {"code_ref": "Shop"}}]
    edges = []
    for did, rule in decisions:
        props = {} if rule is None else {"rule": rule}
        nodes.append({"id": did, "kind": "decision", "title": did, "props": props})
        edges.append({"source": did, "target": "concept:shop", "type": "ABOUT", "evidence": "test"})
    return co.load(json.dumps({"nodes": nodes, "edges": edges}))


def audit_of(*decisions: tuple[str, object]) -> dict:
    return audit.run(snapshot(*decisions), json.dumps(LOCK), "Shop", advisories=no_advisories)


def finding(report: dict, package: str, kind: str) -> dict:
    return next(f for f in report["findings"] if f["package"] == package and f.get("kind") == kind)


def verdicts(f: dict) -> dict[str, str]:
    return {p["decision"]: p["verdict"] for p in f["policies"]}


def facts(expression: str) -> dict:
    return {"license_expression": expression}


def judged(rule: dict, expression: str) -> str:
    parsed = rules.parse(rule)
    assert not parsed.problems
    return rules.verdict(parsed.rules[0], facts(expression), False)[0]


def test_a_rule_is_a_mapping_a_list_of_mappings_or_a_json_string():
    one = rules.parse(DENY_GPL)
    many = rules.parse([DENY_GPL, {**DENY_EVENT_STREAM, "dependencies": "shipped"}])
    text = rules.parse(json.dumps([{"advisory_severity_at_least": "HIGH"}, ALLOW_PERMISSIVE]))
    assert [r.kind for r in one.rules] == ["license_denied"] and one.stated and not one.problems
    assert [(r.kind, r.dependencies) for r in many.rules] == [("license_denied", "all"), ("package_denied", "shipped")]
    assert [r.kind for r in text.rules] == ["advisory_severity_at_least", "license_allowed"]
    assert rules.parse(None) == rules.Parsed() and not rules.parse("").stated


def test_every_kind_is_one_entry_in_the_table():
    assert sorted(rules.KINDS) == ["advisory_severity_at_least", "imports_forbidden", "license_allowed", "license_denied", "package_allowed",
                                   "package_denied", "pinned_to_commit", "review_required"]
    assert rules.subjects() == ["advisory", "allowlist", "import", "license", "package", "pin", "review"]


@pytest.mark.parametrize("raw, kind, reason", [
    ({"licence_denied": ["MIT"]}, "licence_denied", "unknown rule kind licence_denied"),
    ({"dependencies": "shipped"}, None, "the rule names no kind"),
    ({"license_denied": "GPL-3.0-only"}, "license_denied", "license_denied must be a non-empty list of SPDX license ids"),
    ({"license_allowed": []}, "license_allowed", "license_allowed must be a non-empty list"),
    ({"package_denied": [{"name": "x"}]}, "package_denied", "package_denied must be a non-empty list of {ecosystem, name, versions?}"),
    ({"package_denied": [{"ecosystem": "npm", "name": "x", "versions": "1.0.0"}]}, "package_denied", "versions of x must be"),
    ({"advisory_severity_at_least": "SEVERE"}, "advisory_severity_at_least", "must be one of LOW"),
    ({**DENY_GPL, "dependencies": "runtime"}, "license_denied", "dependencies must be shipped or all, not 'runtime'"),
    ("{not json", None, "the rule is not valid JSON"),
    ([], None, "the rule is an empty list"),
    (["license_denied"], None, "a rule must be a mapping or a list of mappings, not str"),
])
def test_a_malformed_rule_or_an_unknown_kind_is_a_problem_with_its_reason(raw, kind, reason):
    parsed = rules.parse(raw)
    assert parsed.stated and not parsed.rules
    assert [p.kind for p in parsed.problems] == [kind] and reason in parsed.problems[0].reason


def test_a_bad_entry_does_not_drop_the_good_ones_beside_it():
    parsed = rules.parse([DENY_GPL, {"imports_forbidden": ["os"]}])
    assert [r.kind for r in parsed.rules] == ["license_denied"]
    assert [p.kind for p in parsed.problems] == ["imports_forbidden"]


@pytest.mark.parametrize("expression, denied, allowed", [
    ("MIT", "not_violated", "not_violated"),
    ("GPL-3.0-only", "violated", "violated"),
    ("MIT OR GPL-3.0-only", "not_violated", "not_violated"),
    ("(GPL-3.0-only OR MIT)", "not_violated", "not_violated"),
    ("MIT AND GPL-3.0-only", "violated", "violated"),
    ("MIT AND Apache-2.0", "not_violated", "not_violated"),
    ("(MIT OR GPL-3.0-only) AND BSD-3-Clause", "not_violated", "violated"),
    ("GPL-3.0-only WITH Classpath-exception-2.0", "violated", "violated"),
    ("gpl-3.0-ONLY", "violated", "violated"),
    ("mit or apache-2.0", "not_violated", "not_violated"),
])
def test_license_expressions_pass_when_one_or_branch_passes_and_every_and_part_does(expression, denied, allowed):
    assert judged(DENY_GPL, expression) == denied
    assert judged(ALLOW_PERMISSIVE, expression) == allowed


@pytest.mark.parametrize("expression", ["", "NOASSERTION", "NONE", "SEE LICENSE IN LICENSE.md", "MIT OR", "(MIT", "MIT WITH"])
def test_an_unknown_license_is_unresolved_never_violated(expression):
    assert judged(ALLOW_PERMISSIVE, expression) == "unresolved"
    assert judged(DENY_GPL, expression) == "unresolved"
    assert rules.license_tree(expression) is None


def test_the_licenses_list_stands_in_when_no_expression_is_given():
    rule = rules.parse(ALLOW_PERMISSIVE).rules[0]
    assert rules.verdict(rule, {"license_expression": "", "licenses": ["MIT", "GPL-3.0-only"]}, False)[0] == "violated"


def test_package_denied_matches_name_ecosystem_and_listed_versions():
    rule = rules.parse(DENY_EVENT_STREAM).rules[0]
    every = rules.parse({"package_denied": [{"ecosystem": "PyPI", "name": "Py_YAML"}]}).rules[0]
    assert rules.verdict(rule, {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"}, False)[0] == "violated"
    assert rules.verdict(rule, {"ecosystem": "npm", "name": "event-stream", "version": "v3.3.6"}, False)[0] == "violated"
    assert rules.verdict(rule, {"ecosystem": "npm", "name": "event-stream", "version": "3.3.5"}, False)[0] == "not_violated"
    assert rules.verdict(rule, {"ecosystem": "PyPI", "name": "event-stream", "version": "3.3.6"}, False)[0] == "not_violated"
    assert rules.verdict(every, {"ecosystem": "PyPI", "name": "py-yaml", "version": "6.0"}, False)[0] == "violated"
    pinned = rules.parse({"package_denied": [{"ecosystem": "PyPI", "name": "pyyaml", "versions": ["6.0"]}]}).rules[0]
    assert rules.verdict(pinned, {"ecosystem": "PyPI", "name": "pyyaml", "version": "6.0.0"}, False)[0] == "violated"


def test_the_shipped_modifier_clears_development_packages_for_every_kind():
    for raw in (DENY_GPL, ALLOW_PERMISSIVE, DENY_EVENT_STREAM, {"advisory_severity_at_least": "LOW"}):
        rule = rules.parse({**raw, "dependencies": "shipped"}).rules[0]
        assert rules.verdict(rule, {}, True) == ("not_violated", rules.SHIPPED_ONLY)


def test_audit_judges_every_package_against_every_rule_and_names_the_rule_kind():
    rep = audit_of(("decision:no-gpl", DENY_GPL), ("decision:permissive-only", ALLOW_PERMISSIVE),
                   ("decision:no-event-stream", DENY_EVENT_STREAM))
    gpl = finding(rep, "pkg:npm/gpl-lib@1.0.0", "license")
    assert gpl["status"] == "affected" and gpl["license_expression"] == "GPL-3.0-only"
    assert gpl["path"] == ["repo:Shop", "pkg:npm/gpl-lib@1.0.0"]
    assert verdicts(gpl) == {"decision:no-gpl": "violated", "decision:permissive-only": "violated"}
    assert {p["rule"] for p in gpl["policies"]} == {"license_denied", "license_allowed"}
    assert verdicts(finding(rep, "pkg:npm/both@1.0.0", "license"))["decision:no-gpl"] == "violated"
    assert finding(rep, "pkg:npm/both@1.0.0", "license")["path"] == ["repo:Shop", "pkg:npm/dual@2.0.0", "pkg:npm/both@1.0.0"]
    assert not any(f["package"] == "pkg:npm/dual@2.0.0" for f in rep["findings"])
    mystery = finding(rep, "pkg:npm/mystery@1.0.0", "license")
    assert mystery["status"] == "unresolved" and set(verdicts(mystery).values()) == {"unresolved"}
    stream = finding(rep, "pkg:npm/event-stream@3.3.6", "package")
    assert stream["status"] == "affected" and stream["policies"] == [
        {"decision": "decision:no-event-stream", "verdict": "violated", "why": "npm event-stream 3.3.6 is denied (versions 3.3.6)",
         "rule": "package_denied"}]
    assert rep["violations"] == 1 + 2 + 2 + 2
    assert rep["summary"] == {"affected": 4, "unresolved": 1, "not_affected": 0}
    assert "rule_problems" not in rep


def test_a_shipped_only_rule_leaves_a_development_package_as_not_violated():
    rep = audit_of(("decision:no-gpl-shipped", {**DENY_GPL, "dependencies": "shipped"}))
    tool = finding(rep, "pkg:npm/gpl-tool@1.0.0", "license")
    assert tool["dev_only"] and tool["status"] == "affected"
    assert tool["policies"][0]["verdict"] == "not_violated" and tool["policies"][0]["why"] == rules.SHIPPED_ONLY


def test_a_malformed_rule_is_relevant_with_its_reason_and_listed_once_in_the_report():
    rep = audit_of(("decision:no-gpl", DENY_GPL), ("decision:typo", {"licence_denied": ["MIT"]}), ("decision:plain", None))
    gpl = finding(rep, "pkg:npm/gpl-lib@1.0.0", "license")
    typo = next(p for p in gpl["policies"] if p["decision"] == "decision:typo")
    assert typo["verdict"] == "relevant" and typo["rule"] == "licence_denied" and "unknown rule kind licence_denied" in typo["why"]
    assert next(p for p in gpl["policies"] if p["decision"] == "decision:plain")["verdict"] == "relevant"
    assert rep["rule_problems"] == [{"decision": "decision:typo", "rule": "licence_denied",
                                     "problem": typo["why"].split("cannot be checked: ", 1)[1]}]
    assert not any(p["verdict"] == "violated" for f in rep["findings"] for p in f["policies"] if p["decision"] == "decision:typo")


def test_without_license_or_package_rules_there_are_no_new_findings():
    rep = audit_of(("decision:no-high", {"advisory_severity_at_least": "HIGH"}))
    assert rep["findings"] == [] and "rule_problems" not in rep


def plan_and_check(rep: dict, vinc: co.Subgraph) -> tuple[dict, list[dict]]:
    plan = wb.propose(rep, "Shop", "test-space", today="2026-11-25")
    return checker.rederive(plan, vinc, json.dumps(LOCK), "Shop", no_advisories)


def test_propose_turns_license_and_package_violations_into_records_the_checker_derives_again():
    vinc = snapshot(("decision:no-gpl", DENY_GPL), ("decision:no-event-stream", DENY_EVENT_STREAM))
    rep = audit.run(vinc, json.dumps(LOCK), "Shop", advisories=no_advisories)
    plan, checked = plan_and_check(rep, vinc)
    assert [c["problems"] for c in checked] == [[]] * len(checked) and plan["digest"] == wb.digest(plan)
    by_id = {n["id"]: n for n in plan["nodes"]}
    lic = by_id["record:shop-npm-gpl-lib-shipped-license-gpl-3-0-only"]["props"]
    assert lic["predicate"] == "licensed_under" and lic["value"] == "GPL-3.0-only" and lic["violates"] == ["decision:no-gpl"]
    assert lic["rules"] == ["license_denied"] and lic["dependency_paths"] == [["repo:Shop", "pkg:npm/gpl-lib@1.0.0"]]
    assert lic["statement"] == "Shop ships gpl-lib 1.0.0, licensed GPL-3.0-only. Path: gpl-lib."
    pkg = by_id["record:shop-npm-event-stream-shipped-denied-package"]["props"]
    assert pkg["predicate"] == "uses_denied_package" and pkg["value"] == "npm:event-stream" and pkg["rules"] == ["package_denied"]
    assert {"package": "pkg:npm/mystery@1.0.0", "kind": "license", "why": "status unresolved: not recorded"} in plan["held"]
    assert "[licensed_under, shipped]" in wb.render(plan) and "[uses_denied_package, shipped]" in wb.render(plan)


def test_a_long_license_expression_gives_a_short_record_id():
    long = "Apache-2.0 AND BSD-3-Clause AND GPL-3.0-only WITH Classpath-exception-2.0"
    assert wb.license_slug("GPL-3.0-only") == "license-gpl-3-0-only"
    slug = wb.license_slug(long)
    assert slug.startswith("license-apache-2-0-and-b") and len(slug) == len("license-") + 24 and slug != wb.license_slug(long + " AND MIT")


@pytest.mark.parametrize("tamper, problem", [
    (lambda f: f.update(license_expression="MIT"), "gpl-lib 1.0.0 is licensed GPL-3.0-only in the inventory, not MIT"),
    (lambda f: f.update(path=["repo:Shop", "pkg:npm/dual@2.0.0", "pkg:npm/gpl-lib@1.0.0"]), "a dependency path is not in the sandbox graph"),
    (lambda f: f.update(dev_only=True), "a dependency path does not match scope development"),
    (lambda f: f["policies"].append({"decision": "decision:no-event-stream", "verdict": "violated", "why": "made up", "rule": "license_denied"}),
     "decision:no-event-stream has no license rule that gpl-lib 1.0.0 violates"),
])
def test_a_tampered_license_record_is_held_with_its_failed_check(tamper, problem):
    vinc = snapshot(("decision:no-gpl", DENY_GPL), ("decision:no-event-stream", DENY_EVENT_STREAM))
    rep = copy.deepcopy(audit.run(vinc, json.dumps(LOCK), "Shop", advisories=no_advisories))
    tamper(finding(rep, "pkg:npm/gpl-lib@1.0.0", "license"))
    plan, checked = plan_and_check(rep, vinc)
    failed = [p for c in checked for p in c["problems"]]
    assert any(problem in p for p in failed), failed
    assert len(plan["held"]) == 2 and not any(n["props"]["value"] in ("MIT", "GPL-3.0-only") for n in plan["nodes"]
                                              if n["props"]["predicate"] == "licensed_under" and "gpl-lib" in n["id"])


BOM = {"bomFormat": "CycloneDX", "specVersion": "1.5",
       "metadata": {"component": {"bom-ref": "root", "name": "shop", "version": "1.0.0"}},
       "components": [{"bom-ref": "a", "name": "foo", "version": "1.0.0", "purl": "pkg:npm/foo@1.0.0",
                       "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
                      {"bom-ref": "b", "name": "foo", "version": "1.0.0", "purl": "pkg:pypi/foo@1.0.0",
                       "licenses": [{"license": {"id": "GPL-3.0-only"}}]}],
       "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}]}


def test_one_name_in_two_ecosystems_gives_one_record_each_and_both_are_kept():
    vinc = snapshot(("decision:no-foo", {"package_denied": [{"ecosystem": "npm", "name": "foo"}, {"ecosystem": "PyPI", "name": "foo"}]}),
                    ("decision:no-gpl", DENY_GPL))
    text = json.dumps(BOM)
    rep = audit.run(vinc, text, "Shop", advisories=no_advisories, filename="bom.cdx.json")
    plan = wb.propose(rep, "Shop", "s", today="2026-11-25", lockfile_path="bom.cdx.json")
    kept, checked = checker.rederive(plan, vinc, text, "Shop", no_advisories, filename="bom.cdx.json")
    assert [c["problems"] for c in checked] == [[]] * 4 and kept["held"] == []
    assert {(n["id"], n["props"]["ecosystem"], n["props"]["value"]) for n in kept["nodes"]} == {
        ("record:shop-npm-foo-shipped-denied-package", "npm", "npm:foo"),
        ("record:shop-pypi-foo-shipped-denied-package", "PyPI", "PyPI:foo"),
        ("record:shop-npm-foo-shipped-license-gpl-3-0-only", "npm", "GPL-3.0-only"),
        ("record:shop-pypi-foo-shipped-license-gpl-3-0-only", "PyPI", "GPL-3.0-only")}


MIXED = {"name": "shop", "version": "1.0.0", "lockfileVersion": 3, "packages": {
    "": {"name": "shop", "version": "1.0.0", "dependencies": {"a": "1.0.0"}, "devDependencies": {"tool": "1.0.0"}},
    "node_modules/a": {"version": "1.0.0", "license": "MIT", "dependencies": {"b": "1.0.0"}},
    "node_modules/b": {"version": "1.0.0", "license": "MIT", "dependencies": {"lib": "1.0.0"}},
    "node_modules/tool": {"version": "1.0.0", "license": "MIT", "dev": True, "dependencies": {"lib": "1.0.0"}},
    "node_modules/lib": {"version": "1.0.0", "license": "GPL-3.0-only"}}}
SHIPPED_ROUTE = ["repo:Shop", "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/lib@1.0.0"]


def lib_advisory(packages):
    node = {"id": "adv:GHSA-test-0001", "kind": "Advisory", "title": "bad lib",
            "props": {"osv_id": "GHSA-test-0001", "severity": "HIGH", "aliases": [], "published": "",
                      "affected_json": json.dumps([{"package": {"ecosystem": "npm", "name": "lib"}, "versions": ["1.0.0"]}]),
                      "source_system": "osv", "source_ref": "GHSA-test-0001", "source_url": "https://osv.dev/vulnerability/GHSA-test-0001",
                      "fetched_at": "2026-11-25T00:00:00Z", "content_hash": "x"}}
    return [node], [{"source": p["id"], "target": node["id"], "type": "AFFECTED_BY", "evidence": "t"}
                    for p in packages if p["props"].get("name") == "lib"]


def test_a_shipped_package_also_reached_through_a_development_tool_keeps_its_shipped_route():
    vinc = snapshot(("decision:no-high", {"advisory_severity_at_least": "HIGH"}), ("decision:no-gpl", DENY_GPL),
                    ("decision:no-lib", {"package_denied": [{"ecosystem": "npm", "name": "lib"}]}))
    text = json.dumps(MIXED)
    rep = audit.run(vinc, text, "Shop", advisories=lib_advisory)
    assert {(f.get("kind", "advisory"), tuple(f["path"]), f["dev_only"]) for f in rep["findings"]} == {
        ("advisory", (*SHIPPED_ROUTE, "adv:GHSA-test-0001"), False), ("license", tuple(SHIPPED_ROUTE), False),
        ("package", tuple(SHIPPED_ROUTE), False)}
    plan = wb.propose(rep, "Shop", "s", today="2026-11-25")
    kept, checked = checker.rederive(plan, vinc, text, "Shop", lib_advisory)
    assert [c["problems"] for c in checked] == [[]] * 3 and kept["held"] == [] and len(kept["nodes"]) == 3
    assert all(n["props"]["violates"] for n in kept["nodes"])


def test_render_shows_license_and_package_findings_and_rule_problems():
    rep = audit_of(("decision:no-gpl", DENY_GPL), ("decision:no-event-stream", DENY_EVENT_STREAM), ("decision:typo", {"x": 1}))
    page = render.html("audit", rep)
    chart = render.mermaid("audit", rep)
    assert "license GPL-3.0-only" in page and "<th>rule</th>" in page and "Rules that cannot be checked" in page
    assert "pkg:npm/event-stream@3.3.6 is a package a decision denies" in page
    assert "violates" in chart and "denied package" in chart


@pytest.mark.parametrize("vector, score, band", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MODERATE"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "MODERATE"),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "MODERATE"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7, "LOW"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "UNKNOWN"),
])
def test_cvss_v3_base_scores_and_bands(vector, score, band):
    assert cvss.base_score(vector) == score and cvss.band(score) == band


@pytest.mark.parametrize("vector", ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N/AC:L",
                                    "AV:N/AC:L/Au:N/C:P/I:P/A:P", ""])
def test_vectors_that_are_not_complete_cvss_v3_are_not_scored(vector):
    assert cvss.base_score(vector) is None


def test_the_bands_agree_with_ghsa_on_every_fixture_record_that_has_both():
    from pathlib import Path
    vulns = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "inventory" / "osv-cache.json").read_text())["vulns"]
    both = [(v["database_specific"]["severity"], s["score"]) for v in vulns.values() for s in v.get("severity") or []
            if (v.get("database_specific") or {}).get("severity") and s["type"] == "CVSS_V3"]
    assert both and all(cvss.band(cvss.base_score(vector)) == sev for sev, vector in both)


V3_HIGH = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
V4 = {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}


def test_severity_comes_from_the_record_then_a_ghsa_alias_then_cvss_v3_else_unknown():
    records = {"GHSA-aaaa-bbbb-cccc": {"aliases": ["CVE-1"], "database_specific": {"severity": "moderate"}},
               "GHSA-back-ward-ssss": {"aliases": ["RUSTSEC-2"], "database_specific": {"severity": "CRITICAL"}}}
    own = {"database_specific": {"severity": "low"}, "aliases": ["GHSA-aaaa-bbbb-cccc"], "severity": [V3_HIGH]}
    assert external.severity_of("GHSA-own", own, records) == ("LOW", "")
    assert external.severity_of("PYSEC-1", {"aliases": ["GHSA-aaaa-bbbb-cccc"], "severity": [V3_HIGH]}, records) == (
        "MODERATE", "GHSA alias GHSA-aaaa-bbbb-cccc in the same OSV data")
    assert external.severity_of("RUSTSEC-2", {}, records) == ("CRITICAL", "GHSA alias GHSA-back-ward-ssss in the same OSV data")
    assert external.severity_of("GO-3", {"aliases": ["GHSA-not-in-data"], "severity": [V3_HIGH, V4]}, records) == (
        "HIGH", f"CVSS v3 base score 7.5 of {V3_HIGH['score']}")
    sev, why = external.severity_of("GO-4", {"severity": [V4]}, records)
    assert sev == "UNKNOWN" and why.endswith("CVSS_V4 is not scored")
    assert external.severity_of("GO-5", {}, records)[0] == "UNKNOWN"


def test_a_finding_says_where_a_derived_severity_came_from():
    from pathlib import Path
    fix = Path(__file__).resolve().parents[1] / "fixtures"
    cache = external.read_osv_cache((fix / "inventory" / "osv-cache.json").read_text(encoding="utf-8"))
    vinc = snapshot(("decision:no-high", {"advisory_severity_at_least": "HIGH"}))
    rep = audit.run(vinc, (fix / "inventory" / "Cargo.lock").read_text(), "Shop", advisories=external.cached_advisories(cache),
                    filename="Cargo.lock")
    rust = [f for f in rep["findings"] if f["advisory"].startswith("adv:RUSTSEC-")]
    ghsa = [f for f in rep["findings"] if f["advisory"].startswith("adv:GHSA-")]
    assert rust and all(f["severity"] != "UNKNOWN" and f["severity_source"].startswith("GHSA alias GHSA-") for f in rust)
    assert ghsa and all("severity_source" not in f for f in ghsa)


def test_long_names_that_share_a_start_keep_their_own_record_ids():
    from decisis.commit import record_id
    core = record_id("Shop", "maven-org.apache.logging.log4j:log4j-core", "shipped", "denied-package")
    api = record_id("Shop", "maven-org.apache.logging.log4j:log4j-api", "shipped", "denied-package")
    assert core != api
    assert core == record_id("Shop", "maven-org.apache.logging.log4j:log4j-core", "shipped", "denied-package")
    assert record_id("Demo", "lodash", "shipped", "GHSA-r5fr-rjxr-66jc") == "record:demo-lodash-shipped-ghsa-r5fr-rjxr-66jc"
