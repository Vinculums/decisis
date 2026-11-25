from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from test_adr_subfolders import both
from test_audit import no_network
from decisis import cli, init

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
LOCK = FIX / "audit" / "demo-lockfile.json"
CACHE = FIX / "audit" / "osv-cache.json"
IMPORT_RULE = {"imports_forbidden": {"from": ["src/shop/ui/**"], "to": ["src/shop/db/**"]}}
REVIEW_RULE = {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}
WAIVER = {"path": "src/payments/**", "reason": "legacy", "expires": "2099-12-31", "approved_by": "@shop/security"}
CHANGED = ["src/shop/ui/view.py", "src/payments/charge.py"]

RULES_TYPO = "docs/adr/0001-ui-does-not-import-db.md"
WAIVER_TYPO = "docs/adr/0002-payments-need-a-review.md"
OTHER_KEYS = "docs/adr/0003-madr-keys.md"
NESTED = "docs/adr/ui/0004-ui-does-not-import-db.md"
DEEPER = "docs/adr/area/2026/0005-payments-reviewed.md"
UNKNOWN_KIND = "docs/decisions/0010-no-gpl.md"
WRONG_SHAPE = "docs/decisions/0011-license-shape.md"
WRONG_SUBJECT = "docs/decisions/0012-wrong-subject-waiver.md"


def adr(title: str, *front: str) -> str:
    return "\n".join(["---", *front, "---", "", f"# {title}", ""])


ADRS = {
    RULES_TYPO: adr("UI does not import the database", "code_ref: src/shop/ui/", "rules: " + json.dumps(IMPORT_RULE)),
    WAIVER_TYPO: adr("Payments need a review", "code_ref: src/payments/", "rule: " + json.dumps(REVIEW_RULE),
                     "waiver: " + json.dumps([WAIVER])),
    OTHER_KEYS: adr("MADR keys", "status: accepted", "consulted: [ana]", "informed: [bo]", "tags: [ui]", "statuses: accepted",
                    "code_ref: src/shop/"),
    NESTED: adr("UI does not import the database, nested", "code_ref: src/shop/ui/", "rule: " + json.dumps(IMPORT_RULE)),
    DEEPER: adr("Payments are reviewed", "code_ref: src/payments/", "rule: " + json.dumps(REVIEW_RULE)),
    "docs/adr/ui/README.md": "# About these ADRs\n",
    "docs/adr/templates/0000-adr.md": adr("A template", 'rule: {"licence_denied": ["GPL-3.0-only"]}'),
    UNKNOWN_KIND: adr("No GPL", "code_ref: docs/", 'rule: {"licence_denied": ["GPL-3.0-only"]}'),
    WRONG_SHAPE: adr("License shape", "code_ref: docs/", 'rule: {"license_denied": "MIT"}'),
    WRONG_SUBJECT: adr("Wrong subject waiver", "code_ref: docs/", 'rule: {"license_denied": ["GPL-3.0-only"]}',
                       "waivers: " + json.dumps([{"package": {"ecosystem": "npm", "name": "lodash"}, "rule": "review_required",
                                                  "reason": "r", "expires": "2099-12-31", "approved_by": "@a"}])),
}
RULES_REASON = "front matter key rules is not a key decisis reads, so a rule or waiver written there is not judged; it may mean rule"
WAIVER_REASON = "front matter key waiver is not a key decisis reads, so a rule or waiver written there is not judged; it may mean waivers"
UNREAD = [(RULES_TYPO, RULES_REASON), (WAIVER_TYPO, WAIVER_REASON)]


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(FIX / "check" / "repo", root)
    shutil.copy(LOCK, root / "package-lock.json")
    return write(root, ADRS)


def node_id(rel: str) -> str:
    return "decision:shop-" + init.slug(rel[:-3])


def decisions(snap: dict) -> dict[str, dict]:
    return {n["props"]["source_file"]: n for n in snap["nodes"] if n["kind"] == "decision"}


def about(snap: dict, rel: str) -> list[dict]:
    return [p for p in snap["meta"]["problems"] if p["file"] == rel]


def unread(entries: list[dict]) -> list[tuple[str, str]]:
    return [(u["file"], u["reason"]) for u in entries]


def built(repo: Path, capsys) -> Path:
    out = repo.parent / "snapshot.json"
    capsys.readouterr()
    assert cli.main(["init", "--repo-dir", str(repo), "--repo", "Shop", "--out", str(out)]) == 0
    capsys.readouterr()
    return out


def run(capsys, *args: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = cli.main(list(args))
    return code, json.loads(capsys.readouterr().out)


def check_report(capsys, snap: Path, repo: Path, changed: list[str]) -> tuple[int, dict]:
    return run(capsys, "check", str(snap), "--repo-dir", str(repo), "--changed", *changed, "--repo", "Shop", "--today", "2026-11-25")


def audit_report(capsys, snap: Path, repo: Path) -> tuple[int, dict]:
    return run(capsys, "audit", str(snap), str(repo / "package-lock.json"), "--repo", "Shop", "--osv-cache", str(CACHE))


def test_an_unknown_front_matter_key_is_listed_with_the_keys_it_may_mean(repo):
    snap = init.build(repo, "Shop")
    assert about(snap, RULES_TYPO) == [{"file": RULES_TYPO, "reason": RULES_REASON, "action": "not read", "kind": "decision",
                                        "key": "rules", "may_mean": ["rule"]}]
    assert about(snap, WAIVER_TYPO) == [{"file": WAIVER_TYPO, "reason": WAIVER_REASON, "action": "not read", "kind": "decision",
                                         "key": "waiver", "may_mean": ["waivers"]}]
    other = {p["key"]: (p["action"], p["may_mean"]) for p in about(snap, OTHER_KEYS)}
    assert other == {"tags": ("ignored", []), "statuses": ("ignored", ["status"])}
    assert "consulted" not in str(about(snap, OTHER_KEYS)) and "informed" not in str(about(snap, OTHER_KEYS))
    by = decisions(snap)
    assert "rule" not in by[RULES_TYPO]["props"] and "waivers" not in by[WAIVER_TYPO]["props"]
    assert unread(init.unread_decisions(snap["meta"])) == UNREAD


@pytest.mark.parametrize("key,close", [("Rule", ["rule"]), ("rulez", ["rule"]), ("WAIVERS", ["waivers"]), ("wavers", ["waivers"]),
                                       ("waive", ["waivers"]), ("ruel", ["rule"]), ("code-ref", ["code_ref"]), ("author", []),
                                       ("role", []), ("Role", []), ("roles", []), ("tags", []), ("xrule", ["rule"]), ("unrule", ["rule"])])
def test_each_misspelling_names_the_known_keys_and_only_rule_or_waivers_ones_are_unread(tmp_path, key, close):
    write(tmp_path, {"docs/adr/0001-a.md": adr("A", f"{key}: x")})
    (p,) = [p for p in init.build(tmp_path)["meta"]["problems"] if "key" in p]
    assert p["key"] == key and p["may_mean"] == close and key in p["reason"] and all(c in p["reason"] for c in close)
    assert p["action"] == ("not read" if {"rule", "waivers"} & set(close) else "ignored")


COMPOUNDS = {"ruleset": "rule", "rule_set": "rule", "rules-v2": "rule", "my_rule": "rule", "decisis_rule": "rule",
             "waivers_list": "waivers", "waiver-list": "waivers", "myRule": "rule", "RuleSet": "rule", "RULESET": "rule",
             "decisisRule": "rule", "XMLRule": "rule", "rule2": "rule", "ruleSets": "rule", "waiverList": "waivers",
             "WAIVER_LIST": "waivers", "waiverlist": "waivers", "my-waivers-file": "waivers", "RULEset": "rule", "RULEsets": "rule",
             "RULEbook": "rule", "RULEfile": "rule", "WAIVERfile": "waivers", "myRULEset": "rule", "my_RULEset": "rule"}
REAL_WORDS = ["ruler", "rulers", "ruled", "Ruler", "schedule", "unruled", "ruling", "scheduler", "my_ruler", "ruler-set", "rulerSet",
              "wavier_list", "ruler2", "ruler1", "ruled2", "Ruler2", "rulers3", "RULERSet", *init.COMMON_KEYS]


def front_matter_problem(root: Path, key: str) -> dict:
    write(root, {"docs/adr/0001-a.md": adr("A", f"{key}: x")})
    (p,) = [p for p in init.build(root)["meta"]["problems"] if "key" in p]
    return p


@pytest.mark.parametrize("key,named", list(COMPOUNDS.items()))
def test_a_key_spelled_as_a_compound_of_rule_or_waiver_makes_the_decision_unread(tmp_path, key, named):
    p = front_matter_problem(tmp_path, key)
    assert p["key"] == key and p["may_mean"] == [named] and p["action"] == "not read"
    assert p["reason"] == f"front matter key {key} is not a key decisis reads, so a rule or waiver written there is not judged; it may mean {named}"
    assert unread(init.unread_decisions(init.build(tmp_path)["meta"])) == [("docs/adr/0001-a.md", p["reason"])]


@pytest.mark.parametrize("key", REAL_WORDS)
def test_a_real_word_that_holds_rule_inside_another_word_stays_ignored(tmp_path, key):
    p = front_matter_problem(tmp_path, key)
    assert p["key"] == key and p["may_mean"] == [] and p["action"] == "ignored"
    assert p["reason"] == f"front matter key {key} is not a key decisis reads, so it is ignored; it is close to no key decisis reads"
    assert init.unread_decisions(init.build(tmp_path)["meta"]) == []


def test_a_key_that_holds_both_words_names_both_keys(tmp_path):
    p = front_matter_problem(tmp_path, "rule_waivers")
    assert p["may_mean"] == ["rule", "waivers"] and p["action"] == "not read" and p["reason"].endswith("it may mean rule or waivers")


@pytest.mark.parametrize("key", [*COMPOUNDS, *REAL_WORDS])
def test_the_base_commit_reader_lists_a_compound_key_as_init_does(tmp_path, key):
    write(tmp_path, {"docs/adr/0001-a.md": adr("A", f"{key}: x"), "docs/adr/0002-b.md": adr("B", "code_ref: src/")})
    local, base = both(tmp_path)
    assert local == base
    assert local["unread"] == ([("docs/adr/0001-a.md", "not read")] if key in COMPOUNDS else [])
    (found,) = [(a, r) for f, a, r, k in local["problems"] if f == "docs/adr/0001-a.md" and f"front matter key {key} " in r]
    assert found[0] == ("not read" if key in COMPOUNDS else "ignored")


def re_named(reason: str) -> bool:
    return reason.endswith(("it may mean rule", "it may mean waivers"))


def test_fail_on_unresolved_fails_for_each_compound_key_and_not_for_a_real_word(tmp_path, capsys, no_network):
    files = {f"docs/adr/{i:04d}-a.md": adr(f"A{i}", "code_ref: src/", f"{key}: x") for i, key in enumerate(COMPOUNDS, start=1)}
    write(tmp_path, files | {"src/x.py": "X = 1\n"})
    snap = built(tmp_path, capsys)
    code, report = run(capsys, "check", str(snap), "--repo-dir", str(tmp_path), "--changed", "src/x.py", "--fail-on-unresolved")
    assert code == 1 and sorted(u["file"] for u in report["unread_decisions"]) == sorted(files)
    assert all(re_named(u["reason"]) for u in report["unread_decisions"])
    clean = tmp_path / "clean"
    write(clean, {f"docs/adr/{i:04d}-a.md": adr(f"A{i}", "code_ref: src/", f"{key}: x") for i, key in enumerate(REAL_WORDS, start=1)}
          | {"src/x.py": "X = 1\n"})
    snap = built(clean, capsys)
    code, report = run(capsys, "check", str(snap), "--repo-dir", str(clean), "--changed", "src/x.py", "--fail-on-unresolved")
    assert code == 0 and "unread_decisions" not in report


def test_a_postmortem_with_an_unknown_key_is_not_listed(tmp_path):
    write(tmp_path, {"docs/postmortems/2026-01-01-outage.md": adr("Outage", "code_ref: src/", "rules: x")})
    assert [p for p in init.build(tmp_path)["meta"]["problems"] if "key" in p] == []


def test_check_and_audit_list_a_rule_or_waiver_under_a_misspelled_key_as_unread(repo, capsys, no_network):
    snap = built(repo, capsys)
    code, report = check_report(capsys, snap, repo, CHANGED)
    assert unread(report["unread_decisions"]) == UNREAD
    assert {r["decision"] for r in report["violations"]} == {node_id(WAIVER_TYPO)}
    assert report["waived"] == []
    listed = [(p["file"], p["action"], p["reason"]) for p in json.loads(snap.read_text())["meta"]["problems"] if p["file"] in (NESTED, DEEPER)]
    assert listed == [(DEEPER, "ignored", init.SUBFOLDER), (NESTED, "ignored", init.SUBFOLDER)]
    code, report = audit_report(capsys, snap, repo)
    assert code == 0 and unread(report["unread_decisions"]) == UNREAD


def test_check_lists_a_rule_that_cannot_be_read_whatever_the_adr_governs(repo, capsys, no_network):
    snap = built(repo, capsys)
    code, report = check_report(capsys, snap, repo, ["src/shop/ui/view.py"])
    found = {(p["decision"], p["rule"]) for p in report["rule_problems"]}
    assert found == {(node_id(UNKNOWN_KIND), "licence_denied"), (node_id(WRONG_SHAPE), "license_denied"),
                     (node_id(WRONG_SUBJECT), "waivers")}
    assert not {node_id(UNKNOWN_KIND), node_id(WRONG_SHAPE), node_id(WRONG_SUBJECT)} & {g["decision"] for g in report["governing"]}
    why = {p["decision"]: p["problem"] for p in report["rule_problems"]}
    assert why[node_id(UNKNOWN_KIND)].startswith("unknown rule kind licence_denied")
    assert "review_required" in why[node_id(WRONG_SUBJECT)] and "package waiver" in why[node_id(WRONG_SUBJECT)]


def test_audit_lists_the_same_rule_problems_for_the_decisions_that_govern_the_repository(repo, capsys, no_network):
    snap = built(repo, capsys)
    whole = json.loads(snap.read_text(encoding="utf-8"))
    ruled = [node_id(UNKNOWN_KIND), node_id(WRONG_SHAPE), node_id(WRONG_SUBJECT)]
    whole["nodes"].append({"id": "concept:shop", "kind": "concept", "title": "Shop", "props": {"code_ref": "Shop"}})
    whole["edges"] += [{"source": d, "target": "concept:shop", "type": "ABOUT", "evidence": "governs the shop"} for d in ruled]
    whole["meta"].update(nodes=len(whole["nodes"]), edges=len(whole["edges"]))
    snap.write_text(json.dumps(whole), encoding="utf-8")
    code, report = audit_report(capsys, snap, repo)
    assert unread(report["unread_decisions"]) == UNREAD
    assert {(p["decision"], p["rule"]) for p in report["rule_problems"]} == {
        (node_id(UNKNOWN_KIND), "licence_denied"), (node_id(WRONG_SHAPE), "license_denied"), (node_id(WRONG_SUBJECT), "waivers")}
