from __future__ import annotations

import datetime
import functools
import json
import re
import time
from pathlib import Path

import pytest

from test_action import FakeGitHub
from test_adr_subfolders import commit, write
from test_audit import no_network
from test_base_decisions import ADR as BASE_ADR
from test_base_decisions import env_for, repository, summary
from test_init import SHOP, adr_repo
from test_suggest_patch import git_apply, needs_git
from decisis import action, check, cli, committed, init, rules, yamltext
from decisis import checkout as co

ROOT = Path(__file__).resolve().parents[1]
BOOKSHOP = ROOT / "examples" / "bookshop" / "app"
DATA_MODEL = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
CODE = "code_ref: src/a.py\n"
DAY = datetime.date(2026, 11, 25)

RULE = {"advisory_severity_at_least": "HIGH", "dependencies": "shipped"}
RULES = [
    {"license_denied": ["GPL-3.0-only"], "dependencies": "shipped"},
    {"package_denied": [{"ecosystem": "npm", "name": "event-stream", "versions": ["3.3.6"]}]},
    {"pinned_to_commit": True},
]
WAIVERS = [
    {"reason": "no patched release yet", "expires": "2099-12-31", "approved_by": "@shop/security",
     "package": {"ecosystem": "npm", "name": "lodash", "versions": ["4.17.15"]}, "advisory": "GHSA-p6mc-m468-83gw",
     "rule": "advisory_severity_at_least"},
    {"reason": "legacy code", "expires": "2099-12-31", "approved_by": "@shop/security", "path": "src/legacy/**"},
]

RULE_FORMS = {
    "inline JSON object": ("rule: " + json.dumps(RULE) + "\n", RULE),
    "multi-line JSON object": ('rule: {\n  "advisory_severity_at_least": "HIGH",\n  "dependencies": "shipped"\n}\n', RULE),
    "flow mapping": ("rule: {advisory_severity_at_least: HIGH, dependencies: shipped}\n", RULE),
    "multi-line flow mapping": ("rule: {\n  advisory_severity_at_least: HIGH,\n  dependencies: shipped\n}\n", RULE),
    "block mapping": ("rule:\n  advisory_severity_at_least: HIGH\n  dependencies: shipped\n", RULE),
    "block mapping with quotes, comments and blank lines":
        ("rule:  # one rule\n  # why\n  \"advisory_severity_at_least\": 'HIGH'\n\n  dependencies: shipped  # only what ships\n", RULE),
    "inline JSON array": ("rule: " + json.dumps(RULES) + "\n", RULES),
    "flow list": ("rule: [{license_denied: [GPL-3.0-only], dependencies: shipped},"
                  " {package_denied: [{ecosystem: npm, name: event-stream, versions: [3.3.6]}]}, {pinned_to_commit: true}]\n", RULES),
    "block list": ("rule:\n  - license_denied: [GPL-3.0-only]\n    dependencies: shipped\n  - package_denied:\n"
                   "      - ecosystem: npm\n        name: event-stream\n        versions:\n          - 3.3.6\n  - pinned_to_commit: true\n", RULES),
    "block list at the key's own column": ("rule:\n- license_denied:\n  - GPL-3.0-only\n  dependencies: shipped\n- package_denied:\n"
                                           "  - {ecosystem: npm, name: event-stream, versions: ['3.3.6']}\n- pinned_to_commit: true\n", RULES),
}
WAIVER_FORMS = {
    "inline JSON array": ("waivers: " + json.dumps(WAIVERS) + "\n", WAIVERS),
    "multi-line JSON array": ("waivers: " + json.dumps(WAIVERS, indent=2) + "\n", WAIVERS),
    "flow list": ("waivers: [{reason: no patched release yet, expires: 2099-12-31, approved_by: '@shop/security',"
                  " package: {ecosystem: npm, name: lodash, versions: [4.17.15]}, advisory: GHSA-p6mc-m468-83gw,"
                  " rule: advisory_severity_at_least}, {reason: legacy code, expires: 2099-12-31, approved_by: '@shop/security',"
                  " path: src/legacy/**}]\n", WAIVERS),
    "block list": ("waivers:\n  - reason: no patched release yet\n    expires: 2099-12-31\n    approved_by: \"@shop/security\"\n"
                   "    package:\n      ecosystem: npm\n      name: lodash\n      versions: [4.17.15]\n    advisory: GHSA-p6mc-m468-83gw\n"
                   "    rule: advisory_severity_at_least\n  - reason: legacy code\n    expires: 2099-12-31\n"
                   "    approved_by: \"@shop/security\"\n    path: src/legacy/**\n", WAIVERS),
    "block list at the key's own column": ("waivers:\n- reason: no patched release yet\n  expires: 2099-12-31\n  approved_by: \"@shop/security\"\n"
                                           "  package: {ecosystem: npm, name: lodash, versions: [4.17.15]}\n  advisory: GHSA-p6mc-m468-83gw\n"
                                           "  rule: advisory_severity_at_least\n- reason: legacy code\n  expires: 2099-12-31\n"
                                           "  approved_by: \"@shop/security\"\n  path: src/legacy/**\n", WAIVERS),
}


def decision(tmp_path: Path, front: str) -> dict:
    snap = init.build(adr_repo(tmp_path, front))
    assert snap["meta"]["problems"] == [] and [n["kind"] for n in snap["nodes"]] == ["decision"]
    return snap["nodes"][0]


def skipped(tmp_path: Path, front: str) -> dict:
    snap = init.build(adr_repo(tmp_path, front))
    assert snap["nodes"] == []
    [problem] = snap["meta"]["problems"]
    assert problem["file"] == "docs/adr/0001-a.md" and problem["action"] == "skipped"
    assert [u["reason"] for u in init.unread_decisions(snap["meta"])] == [problem["reason"]]
    return problem


@pytest.mark.parametrize("form", RULE_FORMS)
def test_each_form_of_rule_gives_the_props_the_equivalent_inline_json_gives(tmp_path, form):
    front, expected = RULE_FORMS[form]
    node = decision(tmp_path, front + CODE)
    assert node["props"]["rule"] == expected
    assert rules.of(node).problems == () and rules.of(node).rules == rules.parse(expected).rules != ()


@pytest.mark.parametrize("form", WAIVER_FORMS)
def test_each_form_of_waivers_gives_the_props_the_equivalent_inline_json_gives(tmp_path, form):
    front, expected = WAIVER_FORMS[form]
    node = decision(tmp_path, RULE_FORMS["block mapping"][0] + front + CODE)
    assert node["props"]["waivers"] == expected
    assert rules.of(node).waiver_problems == () and rules.of(node).waivers == rules.waivers(expected)[0] != ()


def test_a_waivers_mapping_reads_as_the_inline_json_object_does_and_is_a_waiver_problem_of_the_decision(tmp_path):
    inline = decision(tmp_path / "a", 'waivers: {"reason": "r", "path": "src/**"}\n' + CODE)
    block = decision(tmp_path / "b", "waivers:\n  reason: r\n  path: src/**\n" + CODE)
    assert inline["props"]["waivers"] == block["props"]["waivers"] == {"reason": "r", "path": "src/**"}
    assert [p.reason for p in rules.of(block).waiver_problems] == [p.reason for p in rules.of(inline).waiver_problems] != []


REVIEW = {"review_required": {"paths": ["src/**"], "reviewers": ["@shop/payments"]}}
REVIEW_FORMS = {
    "json": 'rule: {"review_required": {"paths": ["src/**"], "reviewers": ["@shop/payments"]}}\n',
    "flow": "rule: {review_required: {paths: [src/**], reviewers: ['@shop/payments']}}\n",
    "block": "rule:\n  review_required:\n    paths:\n      - src/**\n    reviewers:\n      - '@shop/payments'\n",
    "list": "rule:\n- review_required:\n    paths: [src/**]\n    reviewers: ['@shop/payments']\n",
}


LEGACY_CODE = {"reason": "legacy code", "expires": "2099-12-31", "approved_by": "@shop/security", "path": "src/legacy/**"}
WAIVE_FORMS = {
    "json": "waivers: " + json.dumps([LEGACY_CODE]) + "\n",
    "flow": "waivers: [{reason: legacy code, expires: 2099-12-31, approved_by: '@shop/security', path: src/legacy/**}]\n",
    "block": "waivers:\n  - reason: legacy code\n    expires: 2099-12-31\n    approved_by: '@shop/security'\n    path: src/legacy/**\n",
    "list": "waivers:\n- reason: legacy code\n  expires: 2099-12-31\n  approved_by: '@shop/security'\n  path: src/legacy/**\n",
}


@pytest.mark.parametrize("waived", [False, True])
def test_the_yaml_forms_run_through_check_to_the_report_the_json_form_gives(tmp_path, waived):
    reports = {}
    for name, front in REVIEW_FORMS.items():
        root = adr_repo(tmp_path / name, front + (WAIVE_FORMS[name] if waived else "") + "code_ref: src/\n")
        (root / "src" / "legacy").mkdir(parents=True)
        (root / "src" / "legacy" / "a.py").write_text("A = 1\n", encoding="utf-8")
        reports[name] = check.run(co.load(init.dump(init.build(root, "Shop"))), ["src/legacy/a.py"], root, [], 3, "Shop", day=DAY)
    assert len({json.dumps(r, sort_keys=True) for r in reports.values()}) == 1
    assert bool(reports["json"]["waived"]) is waived and bool(reports["json"]["violations"]) is not waived


YAML_TYPES = ["rule:", "  float: 1.0", "  date: 2026-01-31", "  stamp: 2026-01-31T10:00:00Z", "  exponent: 1e3", "  zeros: 007", "  hex: 0x1F",
              "  half: .5", "  triple: 3.0.1", "  yes_word: yes", "  whole: 12", "  negative: -3", "  zero: 0", "  true_word: true",
              "  false_word: False", "  nothing: null", "  tilde: ~", "  empty:", "  quoted_number: '12'", "  quoted_bool: \"true\"",
              "  versions: [1.0, '1.0', 1, 1.10]", "  block: |", "    two", "    lines"]
YAML_TYPED = {"float": "1.0", "date": "2026-01-31", "stamp": "2026-01-31T10:00:00Z", "exponent": "1e3", "zeros": "007", "hex": "0x1F",
              "half": ".5", "triple": "3.0.1", "yes_word": "yes", "whole": 12, "negative": -3, "zero": 0, "true_word": True, "false_word": False,
              "nothing": None, "tilde": None, "empty": None, "quoted_number": "12", "quoted_bool": "true",
              "versions": ["1.0", "1.0", 1, "1.10"], "block": "two\nlines"}


def test_a_yaml_scalar_is_text_unless_it_is_a_whole_number_a_boolean_or_null():
    assert init.front_matter(YAML_TYPES) == {"rule": YAML_TYPED}


def test_a_version_written_as_a_float_keeps_the_text_as_written(tmp_path):
    node = decision(tmp_path, "rule:\n  package_denied:\n    - ecosystem: PyPI\n      name: foo\n      versions: [1.0, 2.10]\n" + CODE)
    assert node["props"]["rule"]["package_denied"][0]["versions"] == ["1.0", "2.10"]
    assert rules.of(node).problems == ()


def test_aliases_that_stay_small_are_read_as_their_expansion(tmp_path):
    front = ("rule:\n  - review_required:\n      paths: [src/payments/**]\n      reviewers: &team ['@shop/payments', '@shop/security']\n"
             "  - imports_forbidden:\n      from: [src/ui/**]\n      to: [src/db/**]\n"
             "waivers:\n  - reason: a\n    expires: 2099-12-31\n    approved_by: &who '@shop/security'\n    path: src/a/**\n"
             "  - reason: b\n    expires: 2099-12-31\n    approved_by: *who\n    path: src/b/**\n")
    node = decision(tmp_path, front + CODE)
    assert node["props"]["rule"][0]["review_required"]["reviewers"] == ["@shop/payments", "@shop/security"]
    assert [w["approved_by"] for w in node["props"]["waivers"]] == ["@shop/security", "@shop/security"]
    assert rules.of(node).problems == () and rules.of(node).waiver_problems == ()


def bomb(levels: int = 12, fan: int = 10) -> list[str]:
    lines = ["  - &a0 [" + ", ".join(["x"] * fan) + "]"]
    lines += [f"  - &a{i} [" + ", ".join([f"*a{i - 1}"] * fan) + "]" for i in range(1, levels)]
    return lines


LAUGHS = ("rule: [&a0 [x, x, x, x, x, x, x, x, x, x], " + ", ".join(f"&a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]" for i in range(1, 9)) + "]\n")
HOSTILE = {
    "an alias bomb in a block": ("rule:\n" + "\n".join(bomb()) + "\n", "expands to more than 20000 YAML nodes"),
    "an alias bomb in a flow list": (LAUGHS, "expands to more than 20000 YAML nodes"),
    "an alias bomb in waivers": ("waivers:\n" + "\n".join(bomb()) + "\n", "expands to more than 20000 YAML nodes"),
    "a node that holds itself": ("rule: &a [*a]\n", "holds a YAML node inside itself"),
    "a block mapping nested 40 levels": ("rule:\n" + "".join("  " * (i + 1) + "a:\n" for i in range(40)) + "  " * 41 + "z: 1\n",
                                         "nests YAML deeper than 16 levels"),
    "a block list nested 40 levels": ("rule:\n" + "".join("  " * i + "- \n" for i in range(1, 41)) + "  " * 41 + "- z: 1\n",
                                      "nests YAML deeper than 16 levels"),
    "a flow mapping nested 100 levels": ("rule: " + "{a: " * 100 + "1" + "}" * 100 + "\n", "nests YAML deeper than 16 levels"),
    "a flow list nested 100 levels in waivers": ("waivers:\n  - [" + "[" * 99 + "x" + "]" * 99 + "]\n", "nests YAML deeper than 16 levels"),
    "a flow list nested 100000 levels": ("rule: " + "[" * 100_000 + "]" * 100_000 + "\n", "nests too deeply"),
    "a mapping nested 100000 levels": ("rule: " + '{"a": ' * 100_000 + "1" + "}" * 100_000 + "\n", "nests too deeply"),
    "text over the size limit": ("rule:\n  a: " + "x" * 70_000 + "\n", "is larger than 65536 bytes"),
    "a key given twice": ("rule:\n  a: 1\n  a: 2\n", "gives the key a twice"),
    "a key that is not text": ("rule:\n  ? [a, b]\n  : c\n", "has a mapping key that is not text"),
    "a python tag": ("rule: !!python/object/apply:os.mkdir ['{marker}']\n", "uses a YAML tag"),
    "a python tag in a block": ("rule:\n  a: !!python/object/new:os.mkdir ['{marker}']\n", "uses a YAML tag"),
    "a typed tag": ("waivers:\n  - reason: !!binary aGk=\n", "uses a YAML tag"),
}


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_yaml_under_rule_or_waivers_leaves_the_adr_unread_with_the_reason_and_runs_nothing(tmp_path, name):
    marker = tmp_path / "executed"
    front, reason = HOSTILE[name]
    started = time.monotonic()
    problem = skipped(tmp_path / "repo", front.replace("{marker}", str(marker)) + CODE)
    assert reason in problem["reason"] and problem["reason"].startswith("front matter line 2: ")
    assert not marker.exists() and time.monotonic() - started < 20


def test_yamltext_plain_yields_plain_data_and_refuses_what_it_cannot_bound():
    assert yamltext.plain("a: [1, 1.5, true, null, x, '3']\nb: {c: ~}\n", "doc") == {"a": [1, "1.5", True, None, "x", "3"], "b": {"c": None}}
    many = "a: &x [1, 2]\n" + "".join(f"c{i}: *x\n" for i in range(30))
    for text, reason in ((many, "expands to more than 20 YAML nodes"), ("a: !!float 1\n", "uses a YAML tag"), ("a: [\n", "is not valid YAML"),
                         ("a: 1\na: 2\n", "gives the key a twice")):
        with pytest.raises(ValueError, match=reason):
            yamltext.plain(text, "doc", max_nodes=20)
    with pytest.raises(ValueError, match="deeper than 3 levels"):
        yamltext.plain("a: [[[[x]]]]\n", "doc", max_depth=3)
    with pytest.raises(ValueError, match="larger than 5 bytes"):
        yamltext.plain("a: 12345\n", "doc", max_bytes=5)


TYPED = "rule must be an inline JSON object, a YAML mapping or a list of mappings"
BAD = [
    ("rule:\n  a: [1\n", "rule is not valid YAML", 3),
    ("rule:\n\ta: 1\n", "rule is not valid YAML", 3),
    ("rule:\n  a: 1\n b: 2\n", "rule is not valid YAML", 4),
    ("rule:\n  a: 1\n- b\n", "rule is not valid YAML", 4),
    ("rule: {a: 1\n", "inline JSON does not parse", 2),
    ("rule: [{a: 1}\n", "inline JSON does not parse", 2),
    ('rule: [{"a": 1}, ]x\n', "inline JSON does not parse", 2),
    ("rule: {a: 1} trailing\n", "rule is not valid YAML", 2),
    ("rule:\n  - a: 1\n  - b\n", "rule must be a mapping or a list of mappings", 2),
    ("rule: [{a: 1}, b]\n", "rule must be a mapping or a list of mappings", 2),
    ("rule:\n  - - a: 1\n", "rule must be a mapping or a list of mappings", 2),
    ("rule: |\n  text\n", "rule must be a mapping or a list of mappings", 2),
    ("rule: 5\n", TYPED, None),
    ("rule: []\n", TYPED, None),
    ("rule:\n", TYPED, None),
    ("rule: just text\n", TYPED, None),
    ("waivers:\n  - reason: a\n  - not a mapping\n", "waivers must be a mapping or a list of mappings", 2),
    ("waivers:\n  reason: [\n", "waivers is not valid YAML", 3),
    ("waivers:\n  - reason: a\n    approved_by: @shop/security\n", "waivers is not valid YAML", 4),
    ("waivers: [{reason: x}\n", "inline JSON does not parse", 2),
    ("waivers: |\n  text\n", "waivers must be a mapping or a list of mappings", 2),
]


@pytest.mark.parametrize("front,reason,line", BAD)
def test_a_value_that_does_not_parse_or_is_not_mappings_leaves_the_adr_unread_with_the_line_and_the_reason(tmp_path, front, reason, line):
    problem = skipped(tmp_path, front + CODE)
    assert reason in problem["reason"]
    assert problem["reason"].startswith(f"front matter line {line}: " if line else "front matter rule must")


def test_the_reason_names_the_line_of_the_error_and_a_later_line_keeps_its_own_number(tmp_path):
    problem = skipped(tmp_path / "a", "status: accepted\nrule:\n  - a: 1\n  - b: [2\n    c: 3\ncode_ref: src/a.py\n")
    assert problem["reason"].startswith("front matter line 6: rule is not valid YAML")
    problem = skipped(tmp_path / "b", "status: accepted\nrule:\n  advisory_severity_at_least: HIGH\nowner:\n  name: Ana\n")
    assert problem["reason"] == "front matter line 6: nested mappings are not supported"
    problem = skipped(tmp_path / "c", "rule:\n  advisory_severity_at_least: HIGH\n\n# note\njust text\n")
    assert problem["reason"] == "front matter line 6: expected 'key: value'"
    assert skipped(tmp_path / "d", "rule:\n  a: 1\nrule: {}\n")["reason"] == "front matter line 4: rule is given twice"


def test_a_rule_kind_or_value_the_rule_reader_refuses_still_goes_to_rule_problems(tmp_path):
    node = decision(tmp_path, "rule:\n  - licence_denied: [GPL-3.0-only]\n  - advisory_severity_at_least: SEVERE\n  - pinned_to_commit: true\n"
                    + CODE + "waivers:\n  - reason: x\n    path: src/**\n")
    read = rules.of(node)
    assert [p.kind for p in read.problems] == ["licence_denied", "advisory_severity_at_least"]
    assert "unknown rule kind licence_denied" in read.problems[0].reason
    assert [r.kind for r in read.rules] == ["pinned_to_commit"]
    assert len(read.waiver_problems) == 1 and "it has no expires" in read.waiver_problems[0].reason


def test_rule_problems_reach_the_check_report_the_same_from_yaml_and_from_json(tmp_path):
    bad = [{"licence_denied": ["GPL-3.0-only"]}, {"review_required": {"paths": ["src/**"], "reviewers": ["@a"]}}]
    reports = []
    for name, front in (("json", "rule: " + json.dumps(bad) + "\n"),
                        ("yaml", "rule:\n  - licence_denied: [GPL-3.0-only]\n  - review_required:\n      paths: [src/**]\n      reviewers: ['@a']\n")):
        root = adr_repo(tmp_path / name, front + CODE)
        (root / "src").mkdir()
        (root / "src" / "a.py").write_text("A = 1\n", encoding="utf-8")
        reports.append(check.run(co.load(init.dump(init.build(root, "Shop"))), ["src/a.py"], root, [], 3, "Shop"))
    assert reports[0] == reports[1] and [p["rule"] for p in reports[0]["rule_problems"]] == ["licence_denied"]
    assert len(reports[0]["violations"]) == 1


OTHER_KEYS = [
    ("owner:\n  name: Ana\n", "front matter line 3: nested mappings are not supported"),
    ("tags:\n  a: 1\n", "front matter line 3: nested mappings are not supported"),
    ("title:\n  a: b\n", "front matter line 3: nested mappings are not supported"),
    ("rules:\n  a: 1\n", "front matter line 3: nested mappings are not supported"),
    ("rule_set:\n  - a: 1\n", "front matter line 3: nested mappings are not supported; quote text that holds ': '"),
    ("decisions:\n  k: v\n", "front matter line 3: nested mappings are not supported"),
    ('code_ref:\n  - {"a": 1}\n', "front matter line 3: nested lists and mappings are not supported"),
    ('subject_path: [{"a": 1}]\n', "front matter line 2: list items must be text or whole numbers"),
    ("status: {a: 1}\n", "front matter line 2: inline JSON does not parse (Expecting property name enclosed in double quotes)"),
    ("code_ref: &a src/a.py\n", "front matter line 2: '&' starts YAML this reader does not support (block text, anchors, aliases or tags)"),
    ("summary: |\n  text\n", "front matter line 2: '|' starts YAML this reader does not support (block text, anchors, aliases or tags)"),
    ("consulted:\n  a: 1\n", "front matter line 3: nested mappings are not supported"),
    ("waiver:\n  - reason: x\n", "front matter line 3: nested mappings are not supported; quote text that holds ': '"),
]


@pytest.mark.parametrize("front,reason", OTHER_KEYS)
def test_a_yaml_block_under_any_other_key_is_reported_as_it_was(tmp_path, front, reason):
    assert skipped(tmp_path, front)["reason"] == reason


def test_the_keys_around_a_rule_block_read_as_they_did(tmp_path):
    front = ("status: Accepted\ndeciders: Ana, Ben\nrule:\n  advisory_severity_at_least: HIGH\n\n# between\nsubject_path: x.py\n"
             "waivers:\n- reason: r\n  expires: 2099-12-31\n  approved_by: '@a'\n  path: src/**\ncode_ref:\n- src/a.py\n- src/b/\nalso_touches: [lib/c.py]\n")
    props = decision(tmp_path, front)["props"]
    assert props["rule"] == {"advisory_severity_at_least": "HIGH"} and props["waivers"][0]["path"] == "src/**"
    assert (props["status"], props["deciders"], props["subject_path"], props["code_ref"], props["also_touches"]) == (
        "accepted", ["Ana", "Ben"], ["x.py"], ["src/a.py", "src/b/"], ["lib/c.py"])


LEGACY = [
    'rule: {"advisory_severity_at_least": "LOW"}\n', 'rule: {"a": 1, "a": 2}\n', 'rule: {"a": 1}  # note\n', "rule: {}\n", "rule: []\n", "rule:\n",
    "rule:  # empty\n", "rule: advisory HIGH\n", "rule: [a, b]\n", "rule: [1, 2]\n", 'rule: "x"\n', "rule: 'it''s'\n", "rule: 3\n", "rule:\n- a\n- b\n",
    "rule:\n  - a\n  - b\n", 'rule: {"a": 1.5}\n', 'waivers: [{"reason": "r", "path": "src/**"}]\n', "waivers: [1, 2.5]\n", 'waivers: ["a", {"b": 1}]\n',
    'waivers: {"reason": "r"}\n', "waivers: []\n", "waivers:\n", "waivers: text\n", 'waivers: "text"\n', "waivers: 5\n", "waivers: '[{\"path\": \"a\"}]'\n",
    "waivers:\n- a\n- b\n", "waivers:\n  - a\n  - 3\n", 'waivers: [{"a": 1}] # note\n',
]


@pytest.mark.parametrize("front", LEGACY)
def test_whatever_the_subset_reader_read_it_still_reads_the_same(front):
    lines = (front + "status: accepted\n").split("\n")[:-1]
    assert init.front_matter(lines) == init.front_matter(lines, blocks=False)


def trees() -> list[Path]:
    return [SHOP, BOOKSHOP]


@pytest.mark.parametrize("tree", trees(), ids=lambda p: p.name)
def test_the_existing_fixtures_build_the_same_snapshot_as_the_reader_that_knows_no_blocks(tree, monkeypatch):
    now = init.dump(init.build(tree, "Shop"))
    monkeypatch.setattr(init, "front_matter", functools.partial(init.front_matter, blocks=False))
    assert init.dump(init.build(tree, "Shop")) == now


def adr_text(rule: str, waivers: str = "", *front: str) -> str:
    return "".join(["---\n", "status: accepted\n", *front, "code_ref: [src/payments/]\n", rule, waivers, "---\n\n# Payments are reviewed\n"])


PAYMENTS_REVIEW = {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}
YAML_REVIEW = "rule:\n  review_required:\n    paths: [src/payments/**]\n    reviewers: ['@shop/payments']\n"
YAML_WAIVER = "waivers:\n  - reason: legacy handler\n    expires: 2099-12-31\n    approved_by: '@shop/security'\n    path: src/payments/**\n"


def test_the_base_commit_reader_gives_what_init_gives_for_yaml_blocks(tmp_path):
    root = write(tmp_path / "repo", {"docs/adr/0001-a.md": adr_text(YAML_REVIEW, YAML_WAIVER), "docs/adr/0002-b.md": adr_text(RULE_FORMS["block list"][0]),
                                     "docs/adr/0003-c.md": adr_text("rule: [{pinned_to_commit: true}]\n"), "src/payments/charge.py": "A = 1\n"})
    sha = commit(root)
    local, base = init.build(root, "shop"), committed.built(root, sha, "shop", [])
    props = lambda nodes: {n["id"]: (n["props"].get("rule"), n["props"].get("waivers")) for n in nodes if n["kind"] == "decision"}
    assert props(local["nodes"]) == props(base.nodes) and len(props(base.nodes)) == 3
    assert props(base.nodes)["decision:shop-docs-adr-0002-b"][0] == RULES
    assert local["meta"]["problems"] == base.meta["problems"] == [] and init.unread_decisions(base.meta) == []


def judged(tmp_path: Path, adr: str, fmt: str) -> tuple[int, str]:
    (tmp_path / fmt).mkdir()
    root, base = repository(tmp_path / fmt, {"src/payments/charge.py": "AMOUNT = 1\n", BASE_ADR: adr}, {"src/payments/charge.py": "AMOUNT = 2\n"})
    code = action.main(env_for(tmp_path / fmt, root, base, DECISIS_FAIL_ON_VIOLATION="true"), FakeGitHub())
    return code, re.sub(r"\b[0-9a-f]{12,40}\b", "SHA", summary(tmp_path / fmt))


@pytest.mark.parametrize("waivers", [("", ""), (YAML_WAIVER, "waivers: " + json.dumps([{"reason": "legacy handler", "expires": "2099-12-31",
                                                                                          "approved_by": "@shop/security", "path": "src/payments/**"}]) + "\n")])
def test_the_action_judges_a_pull_request_by_a_yaml_block_rule_as_it_does_by_the_json_one(tmp_path, no_network, waivers):
    yaml_waiver, json_waiver = waivers
    as_json = adr_text("rule: " + json.dumps(PAYMENTS_REVIEW) + "\n", json_waiver)
    as_yaml = adr_text(YAML_REVIEW, yaml_waiver)
    (code_json, out_json), (code_yaml, out_yaml) = judged(tmp_path, as_json, "json"), judged(tmp_path, as_yaml, "yaml")
    assert code_json == code_yaml == (0 if yaml_waiver else 1)
    assert out_json == out_yaml
    assert ("#### Waived, not counted as violations (1)" in out_yaml) is bool(yaml_waiver)
    assert ("#### Violations (1)" in out_yaml) is not bool(yaml_waiver)


CLIENT = "The client is `src/payments/client.py`, and `src/payments/retry.py` is its helper.\n"


def patched_repo(tmp_path: Path, front: str) -> Path:
    return write(tmp_path / "repo", {"docs/adr/0001-client.md": f"---\nstatus: accepted\n{front}---\n\n# Use the client\n\n{CLIENT}",
                                     "src/payments/client.py": "", "src/payments/retry.py": ""})


@needs_git
@pytest.mark.parametrize("form", [*RULE_FORMS, "waivers, block list", "rule block then comments and blank lines", "rule block, then an empty code_ref"])
def test_suggest_refs_patch_inserts_code_ref_beside_a_yaml_block_and_init_reads_it_back(tmp_path, form):
    if form == "waivers, block list":
        front, expected = RULE_FORMS["block mapping"][0] + WAIVER_FORMS["block list"][0], {"rule": RULE, "waivers": WAIVERS}
    elif form == "rule block then comments and blank lines":
        front, expected = RULE_FORMS["block list"][0] + "\n  # a trailing note\n\n", {"rule": RULES}
    elif form == "rule block, then an empty code_ref":
        front, expected = RULE_FORMS["block mapping"][0] + "code_ref: []\n", {"rule": RULE}
    else:
        front, expected = RULE_FORMS[form][0], {"rule": RULE_FORMS[form][1]}
    repo = patched_repo(tmp_path, front)
    before = (repo / "docs/adr/0001-client.md").read_text(encoding="utf-8")
    diff = tmp_path / "suggest.diff"
    assert cli.main(["init", "--repo-dir", str(repo), "--repo", "Shop", "--suggest-refs", "--out", str(tmp_path / "snapshot.json"), "--patch", str(diff)]) == 0
    text = diff.read_text(encoding="utf-8")
    assert [line for line in text.split("\n") if line.startswith("-") and not line.startswith("--- a/")] == (
        ["-code_ref: []"] if form.endswith("empty code_ref") else [])
    assert git_apply(repo, diff, "--check").returncode == 0 and git_apply(repo, diff).returncode == 0
    after = (repo / "docs/adr/0001-client.md").read_text(encoding="utf-8")
    assert after.replace("code_ref: []\n", "").count("code_ref:\n") == 1 and after.startswith("---\nstatus: accepted\n")
    snap = init.build(repo, "Shop")
    [node] = [n for n in snap["nodes"] if n["kind"] == "decision"]
    assert {k: node["props"][k] for k in expected} == expected
    assert node["props"]["code_ref"] == ["Shop:src/payments/client.py", "Shop:src/payments/retry.py"] and "code_ref_source" not in node["props"]
    assert snap["meta"]["problems"] == [] and rules.of(node).problems == ()
    again = init.build(repo, "Shop", suggest_refs=True)
    assert again["nodes"] == snap["nodes"] and before != after


def test_new_adr_keeps_writing_inline_json(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "docs" / "adr").mkdir(parents=True)
    capsys.readouterr()
    waiver = {"reason": "legacy", "expires": "2099-12-31", "approved_by": "@shop/security", "path": "src/payments/**"}
    assert cli.main(["new-adr", "Payments review", "--repo-dir", str(root), "--rule", json.dumps(REVIEW), "--waiver", json.dumps(waiver),
                     "--date", "2026-11-25"]) == 0
    text = Path(json.loads(capsys.readouterr().out)["out"]).read_text(encoding="utf-8")
    assert f"\nrule: {json.dumps(REVIEW)}\nwaivers: {json.dumps([waiver])}\n---\n" in text
    [node] = [n for n in init.build(root, "Shop")["nodes"] if n["kind"] == "decision"]
    assert node["props"]["rule"] == REVIEW and node["props"]["waivers"] == [waiver]


def docs_blocks() -> list[str]:
    start = DATA_MODEL.index("### The front matter subset")
    section = DATA_MODEL[start:DATA_MODEL.index("\n## ", start)]
    return re.findall(r"```yaml\n(.*?)```", section, re.S)


def test_the_documented_yaml_front_matter_reads_as_the_documented_json_beside_it():
    blocks = [b for b in docs_blocks() if b.startswith("---\n")]
    assert len(blocks) == 2
    read = []
    for block in blocks:
        lines, _ = init.split_front_matter(block)
        read.append(init.typed(init.front_matter(lines)))
    assert read[0] == read[1] and isinstance(read[0]["rule"], list) and isinstance(read[0]["waivers"], list)
    node = {"id": "decision:docs", "kind": "decision", "title": "t", "props": read[0]}
    assert rules.of(node).problems == () and rules.of(node).waiver_problems == () and len(rules.of(node).rules) >= 2
