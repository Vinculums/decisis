from __future__ import annotations

import copy
import datetime
import json
import types
from pathlib import Path

import pytest

from test_audit import advisories, lock, no_network
from test_rules import LOCK, no_advisories, snapshot
from decisis import action, audit, check, checker, cli, compact, compare, demo, init, madr, render, rules
from decisis import checkout as co
from decisis import commit as wb

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
CHECK_REPO = FIX / "check" / "repo"
DAY = "2026-11-25"
TODAY = datetime.date(2026, 11, 25)
NEXT = datetime.date(2026, 11, 26)
ADVISORY_RULE = "decision:no-high-advisories-in-shipped-dependencies"
IMPORT_RULE = "decision:ui-does-not-import-db"
REVIEW_RULE = "decision:payments-need-a-payments-review"
CHANGED = ["src/shop/ui/view.py", "web/src/ui/page.ts", "src/payments/charge.py", "crates/shop/src/ui.rs"]
LODASH = {"ecosystem": "npm", "name": "lodash"}


def waiver(expires: str = DAY, **covers) -> dict:
    return {"reason": "no patched release yet", "expires": expires, "approved_by": "@shop/security", **covers}


def with_waivers(path: Path, waivers: dict[str, object]) -> dict:
    snap = json.loads(path.read_text(encoding="utf-8"))
    for n in snap["nodes"]:
        if n["id"] in waivers:
            n["props"]["waivers"] = waivers[n["id"]]
    return snap


def audited(waivers: list, day=TODAY) -> dict:
    snap = with_waivers(FIX / "audit" / "vinc.json", {ADVISORY_RULE: waivers})
    return audit.run(co.load(json.dumps(snap)), lock(), "Demo", advisories=advisories(), day=day)


def checked(waivers: dict[str, object], day=TODAY, reviewers=("bob",)) -> dict:
    snap = with_waivers(FIX / "check" / "vinc.json", waivers)
    return check.run(co.load(json.dumps(snap)), CHANGED, CHECK_REPO, list(reviewers), day=day)


def advisory_verdicts(report: dict) -> dict[tuple[str, str], str]:
    return {(f["package"], f["advisory"]): p["verdict"] for f in report["findings"] for p in f["policies"]
            if p["decision"] == ADVISORY_RULE}


def results(report: dict, key: str) -> set[tuple]:
    return {(r["file"], r["line"], r["decision"], r.get("import")) for r in report[key]}


def test_a_readable_waiver_carries_its_fields_and_what_it_covers():
    found, problems = rules.waivers([waiver(package={**LODASH, "versions": ["4.17.15"]}, advisory="GHSA-p6mc-m468-83gw"),
                                     waiver(path="crates/shop/src/ui.rs", to="crates/shop/src/db/**"),
                                     waiver(path="src/payments/**", rule="review_required")])
    assert problems == ()
    a, b, c = found
    assert (a.index, a.reason, a.expires, a.approved_by) == (1, "no patched release yet", TODAY, "@shop/security")
    assert (a.ecosystem, a.name, a.versions, a.advisory, a.path) == ("npm", "lodash", ("4.17.15",), "GHSA-p6mc-m468-83gw", None)
    assert (b.path, b.to, b.rule, b.ecosystem) == ("crates/shop/src/ui.rs", "crates/shop/src/db/**", None, None)
    assert (c.path, c.rule) == ("src/payments/**", "review_required")
    assert rules.waivers(json.dumps([waiver(path="src/**")]))[0][0].path == "src/**"


BAD = [
    ({"expires": DAY, "approved_by": "@a", "path": "src/**"}, "it has no reason"),
    (waiver(expires="2026-02-30", path="src/**"), "expires must be a date"),
    (waiver(expires="20261125", path="src/**"), "expires must be a date"),
    (waiver(expires="2026-11-25T00:00:00", path="src/**"), "expires must be a date"),
    ({**waiver(path="src/**"), "approved_by": ""}, "approved_by must be one line of text"),
    ({**waiver(path="src/**"), "reason": "two\nlines"}, "reason must be one line of text"),
    (waiver(path="src/**", until="2027-01-01"), "unknown key until"),
    (waiver(), "exactly one of them"),
    (waiver(path="src/**", package=LODASH), "exactly one of them"),
    (waiver(path="src/**", advisory="GHSA-p6mc-m468-83gw"), "advisory goes with a package waiver"),
    (waiver(package=LODASH, to="db/**"), "to goes with a path waiver"),
    (waiver(package={"ecosystem": "npm"}), "package must be a mapping"),
    (waiver(package={**LODASH, "versions": []}), "non-empty list of exact versions"),
    (waiver(package=LODASH, advisory="adv:GHSA-p6mc-m468-83gw"), "without adv:"),
    (waiver(package=LODASH, rule="review_required"), "rule must name a rule kind a package waiver can cover"),
    (waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gw", rule="license_denied"), "package and advisory waiver"),
    (waiver(path="src/**", rule="package_denied"), "rule must name a rule kind a path waiver can cover"),
    (waiver(path="src/**", to="db/**", rule="review_required"), "path and to waiver"),
    (waiver(path="src/[ab]/**"), "path:"),
    (waiver(path="src/**", to="!db"), "to:"),
    ("src/**", "a waiver must be a mapping"),
]


@pytest.mark.parametrize("entry,reason", BAD)
def test_a_waiver_with_a_missing_or_unreadable_field_is_a_problem_and_waives_nothing(entry, reason):
    found, problems = rules.waivers([entry])
    assert found == ()
    (p,) = problems
    assert p.kind == rules.WAIVERS and p.reason.startswith("waiver 1 waives nothing: ") and reason in p.reason


@pytest.mark.parametrize("raw", ["[{", {"path": "src/**"}, [], "plain text"])
def test_waivers_that_are_not_a_list_are_one_problem(raw):
    found, problems = rules.waivers(raw)
    assert found == () and len(problems) == 1 and problems[0].kind == rules.WAIVERS


def test_an_unreadable_waiver_is_listed_under_rule_problems_in_audit_and_check_and_waives_nothing():
    bad = {**waiver(package=LODASH), "expires": "soon"}
    rep = audited([bad, waiver(package={"ecosystem": "npm", "name": "left-pad"})])
    assert rep["violations"] == 3 and rep["waived"] == 0
    assert rep["rule_problems"] == [{"decision": ADVISORY_RULE, "rule": "waivers",
                                     "problem": "waiver 1 waives nothing: expires must be a date such as 2026-01-31, not 'soon'"}]
    assert all(p["verdict"] != "relevant" or p["decision"] != ADVISORY_RULE for f in rep["findings"] for p in f["policies"])
    rep = checked({IMPORT_RULE: [{**waiver(path="**"), "approved_by": None}]})
    assert {p["decision"] for p in rep["rule_problems"]} == {IMPORT_RULE} and rep["waived"] == []
    assert len(rep["violations"]) == 9


def test_a_covered_advisory_violation_is_waived_through_its_expiry_date_and_violated_the_next_day():
    covers = waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gw")
    rep = audited([covers])
    key = ("pkg:npm/lodash@4.17.15", "adv:GHSA-p6mc-m468-83gw")
    assert advisory_verdicts(rep)[key] == "waived"
    assert rep["violations"] == 2 and rep["waived"] == 1 and rep["today"] == DAY
    [p] = [p for f in rep["findings"] if (f["package"], f["advisory"]) == key for p in f["policies"] if p["decision"] == ADVISORY_RULE]
    assert p["waiver"] == {"waiver": 1, "reason": "no patched release yet", "expires": DAY, "approved_by": "@shop/security"}
    assert p["why"].startswith("severity HIGH is at or above HIGH")
    assert advisory_verdicts(audited([covers], datetime.date(2025, 1, 1)))[key] == "waived"
    later = audited([covers], NEXT)
    assert advisory_verdicts(later)[key] == "violated" and later["violations"] == 3 and later["waived"] == 0
    [p] = [p for f in later["findings"] if (f["package"], f["advisory"]) == key for p in f["policies"] if p["decision"] == ADVISORY_RULE]
    assert p["expired_waiver"]["expires"] == DAY and "waiver" not in p
    assert p["why"].endswith(f"; waiver 1 (no patched release yet, approved by @shop/security) expired at the end of {DAY}")


def test_an_advisory_waiver_covers_only_that_advisory_and_a_package_waiver_every_advisory_of_that_package():
    only = advisory_verdicts(audited([waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gw")]))
    assert sorted(k[1] for k, v in only.items() if v == "waived") == ["adv:GHSA-p6mc-m468-83gw"]
    assert sorted(k[1] for k, v in only.items() if v == "violated") == ["adv:GHSA-35jh-r3h4-6jhm", "adv:GHSA-r5fr-rjxr-66jc"]
    every = audited([waiver(package=LODASH)])
    assert every["violations"] == 0 and every["waived"] == 3
    assert audited([waiver(package={**LODASH, "versions": ["4.17.21"]})])["waived"] == 0
    assert audited([waiver(package={**LODASH, "versions": ["v4.17.15"]})])["waived"] == 3
    assert audited([waiver(package={"ecosystem": "PyPI", "name": "lodash"})])["waived"] == 0
    assert audited([waiver(package={"ecosystem": "npm", "name": "lodash-es"})])["waived"] == 0
    assert audited([waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gx")])["waived"] == 0
    assert audited([waiver(package=LODASH, rule="license_denied")])["waived"] == 0
    assert audited([waiver(path="**")])["waived"] == 0
    assert audited([waiver(package=LODASH, advisory="ghsa-p6mc-m468-83gw")])["waived"] == 0


def package_audit(decisions: list[tuple[str, object, list]], day=TODAY) -> dict:
    vinc = snapshot(*[(d, r) for d, r, _ in decisions])
    for n in vinc.nodes:
        for d, _, w in decisions:
            if n["id"] == d and w:
                n["props"]["waivers"] = w
    return audit.run(vinc, json.dumps(LOCK), "Shop", advisories=no_advisories, day=day)


def verdicts_by(report: dict) -> dict[tuple[str, str, str], str]:
    return {(f["package"], f.get("kind"), p["decision"]): p["verdict"] for f in report["findings"] for p in f["policies"]}


def test_a_package_waiver_covers_every_version_of_that_one_package_and_only_the_decision_that_holds_it():
    deny = {"package_denied": [{"ecosystem": "npm", "name": "event-stream"}, {"ecosystem": "npm", "name": "gpl-lib"}]}
    rep = package_audit([("decision:deny", deny, [waiver(package={"ecosystem": "npm", "name": "event-stream"})]),
                         ("decision:deny-too", deny, []),
                         ("decision:no-gpl", {"license_denied": ["GPL-3.0-only"]}, [waiver(package={"ecosystem": "npm", "name": "event-stream"})])])
    v = verdicts_by(rep)
    assert v[("pkg:npm/event-stream@3.3.6", "package", "decision:deny")] == "waived"
    assert v[("pkg:npm/gpl-lib@1.0.0", "package", "decision:deny")] == "violated"
    assert v[("pkg:npm/event-stream@3.3.6", "package", "decision:deny-too")] == "violated"
    assert v[("pkg:npm/gpl-lib@1.0.0", "license", "decision:no-gpl")] == "violated"
    assert rep["waived"] == 1 and rep["violations"] == sum(1 for x in v.values() if x == "violated")
    narrow = package_audit([("decision:deny", deny, [waiver(package={"ecosystem": "npm", "name": "gpl-lib"}, rule="license_denied")]),
                            ("decision:no-gpl", {"license_denied": ["GPL-3.0-only"]}, [waiver(package={"ecosystem": "npm", "name": "gpl-lib"}, rule="license_denied")])])
    v = verdicts_by(narrow)
    assert v[("pkg:npm/gpl-lib@1.0.0", "package", "decision:deny")] == "violated"
    assert v[("pkg:npm/gpl-lib@1.0.0", "license", "decision:no-gpl")] == "waived"


def test_a_covered_check_violation_is_waived_and_does_not_count_for_the_exit_code(tmp_path, capsys, no_network):
    snap = with_waivers(FIX / "check" / "vinc.json", {IMPORT_RULE: [waiver(path="**")], REVIEW_RULE: [waiver(path="src/payments/**")]})
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    run = lambda day: (cli.main(["check", str(path), "--repo-dir", str(CHECK_REPO), "--changed", *CHANGED, "--today", day]),
                       json.loads(capsys.readouterr().out))
    capsys.readouterr()
    code, rep = run(DAY)
    assert code == 0 and rep["violations"] == [] and len(rep["waived"]) == 9 and rep["summary"]["waived"] == 9
    assert rep["today"] == DAY and len(rep["unresolved"]) == 5
    assert all(r["verdict"] == "waived" and r["waiver"]["expires"] == DAY for r in rep["waived"])
    code, later = run("2026-11-26")
    assert code == 1 and later["waived"] == [] and len(later["violations"]) == 9
    assert all(r["expired_waiver"]["expires"] == DAY and r["why"].endswith(f"expired at the end of {DAY}") for r in later["violations"])


def test_a_path_waiver_uses_the_rules_globs_and_covers_no_more_than_it_names():
    rep = checked({IMPORT_RULE: [waiver(path="src/shop/ui/**")]})
    assert {r["file"] for r in rep["waived"]} == {"src/shop/ui/view.py"}
    assert {r["file"] for r in rep["violations"] if r["decision"] == IMPORT_RULE} == {"crates/shop/src/ui.rs", "web/src/ui/page.ts"}
    rep = checked({IMPORT_RULE: [waiver(path="ui")]})
    assert {r["file"] for r in rep["waived"]} == {"src/shop/ui/view.py", "web/src/ui/page.ts"}
    rep = checked({IMPORT_RULE: [waiver(path="/ui")]})
    assert rep["waived"] == []
    rep = checked({IMPORT_RULE: [waiver(path="*.py")]})
    assert {r["file"] for r in rep["waived"]} == {"src/shop/ui/view.py"}
    for glob in ("src/shop/ui/**", "ui", "/ui", "*.py", "src/", "**/ui.rs", "crates/shop/src/ui.rs", "src/shop/ui/*.py"):
        w = rules.waivers([waiver(path=glob)])[0][0]
        rule = rules.parse({"review_required": {"paths": ["**"], "reviewers": ["@a"]}}).rules[0]
        for f in ("src/shop/ui/view.py", "web/src/ui/page.ts", "crates/shop/src/ui.rs", "src/payments/charge.py", "ui"):
            assert rules.covers(w, rule, {"file": f}) == (rules.matches((glob,), f) is not None)


def test_a_to_glob_covers_only_imports_whose_forbidden_targets_it_names_and_never_a_review():
    rep = checked({IMPORT_RULE: [waiver(path="crates/shop/src/ui.rs", to="crates/shop/src/db/**")]})
    assert sorted((r["line"], r["import"]) for r in rep["waived"]) == [
        (4, "use crate::db::models::Order"), (5, "use super::db"), (5, "use super::db::models"), (18, "use crate::db::models::Total")]
    assert [(r["file"], r["line"]) for r in rep["violations"] if r["file"] == "crates/shop/src/ui.rs"] == [("crates/shop/src/ui.rs", 6)]
    rep = checked({IMPORT_RULE: [waiver(path="crates/shop/src/ui.rs", to="crates/shop/src/db/models.rs")]})
    assert sorted(r["line"] for r in rep["waived"]) == [4, 5, 18] and {r["import"] for r in rep["waived"]} == {
        "use crate::db::models::Order", "use super::db::models", "use crate::db::models::Total"}
    rep = checked({IMPORT_RULE: [waiver(path="crates/shop/src/ui.rs", to="crates/shop/src/db/models/**")]})
    assert sorted(r["line"] for r in rep["waived"]) == [4, 5, 18]
    rep = checked({IMPORT_RULE: [waiver(path="crates/shop/src/ui.rs", to="crates/shop/src/db/mod.rs")]})
    assert [(r["line"], r["import"]) for r in rep["waived"]] == [(5, "use super::db")]
    rep = checked({REVIEW_RULE: [waiver(path="src/payments/**", to="**")], IMPORT_RULE: [waiver(path="**", rule="review_required")]})
    assert rep["waived"] == [] and len(rep["violations"]) == 9
    rep = checked({REVIEW_RULE: [waiver(path="src/payments/**", rule="review_required")], IMPORT_RULE: [waiver(path="**", rule="imports_forbidden")]})
    assert len(rep["waived"]) == 9 and rep["violations"] == []


def test_a_to_glob_must_name_every_file_an_import_is_forbidden_through():
    rule = rules.parse({"imports_forbidden": {"from": ["src/**"], "to": ["src/db/**", "src/secret/**"]}}).rules[0]
    both = {"file": "src/lib.rs", "specifier": "crate::db", "resolution": "repository", "target": "src/db/unix.rs", "also": ("src/db/unix/", "src/secret/win.rs")}
    one = rules.waivers([waiver(path="src/**", to="src/db/**")])[0][0]
    every = rules.waivers([waiver(path="src/**", to="src/**")])[0][0]
    assert rules.outcome(rule, both)[0] == rules.MATCH
    assert not rules.covers(one, rule, both) and rules.covers(every, rule, both)
    go = {"file": "src/a.go", "specifier": "x/db", "resolution": "repository", "target": "src/db/", "also": ("src/db", "src/db/db.go")}
    assert rules.covers(rules.waivers([waiver(path="src/**", to="src/db/*.go")])[0][0], rule, go)
    assert not rules.covers(rules.waivers([waiver(path="src/**", to="src/dbx/**")])[0][0], rule, go)
    pkg = rules.parse({"imports_forbidden": {"from": ["web/**"], "to": ["node_modules/left-pad"]}}).rules[0]
    ext = {"file": "web/a.ts", "specifier": "left-pad", "resolution": "external", "target": "node_modules/left-pad", "also": ()}
    assert rules.outcome(pkg, ext)[0] == rules.MATCH
    assert rules.covers(rules.waivers([waiver(path="web/**", to="node_modules/left-pad")])[0][0], pkg, ext)
    assert not rules.covers(rules.waivers([waiver(path="web/**", to="node_modules/right-pad")])[0][0], pkg, ext)
    assert not rules.covers(rules.waivers([waiver(path="web/**", to="src/**")])[0][0], pkg, ext)


def test_a_waiver_never_turns_an_unresolved_result_into_waived():
    rep = checked({IMPORT_RULE: [waiver(path="**")]})
    assert len(rep["unresolved"]) == 5 and all(r["verdict"] == "unresolved" for r in rep["unresolved"])
    assert all("waiver" not in r for r in rep["unresolved"])


def test_of_two_waivers_the_one_that_lasts_longest_is_shown():
    rep = audited([waiver(package=LODASH, expires="2026-12-01"), waiver(package=LODASH, expires="2026-11-01")])
    assert {p["waiver"]["waiver"] for f in rep["findings"] for p in f["policies"] if p["verdict"] == "waived"} == {1}
    rep = audited([waiver(package=LODASH, expires="2026-10-01"), waiver(package=LODASH, expires="2026-11-01")])
    assert rep["waived"] == 0 and {p["expired_waiver"]["waiver"] for f in rep["findings"] for p in f["policies"] if "expired_waiver" in p} == {2}


def test_today_is_the_utc_date_unless_given(monkeypatch, tmp_path, capsys):
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.datetime(2026, 11, 26, 7, 30, tzinfo=datetime.timezone.utc).astimezone(tz)
    monkeypatch.setattr(rules, "datetime", types.SimpleNamespace(datetime=Clock, timezone=datetime.timezone, date=datetime.date))
    assert rules.today() == NEXT and rules.today(DAY) == TODAY
    with pytest.raises(ValueError):
        rules.today("26/11/2026")
    assert check.run(co.load((FIX / "check" / "vinc.json").read_text()), CHANGED, CHECK_REPO, [])["today"] == "2026-11-26"
    with pytest.raises(SystemExit) as e:
        cli.main(["check", str(FIX / "check" / "vinc.json"), "--changed", "a.py", "--today", "2026-13-01"])
    assert e.value.code == 2 and "is not a date such as 2026-01-31" in capsys.readouterr().err


def test_the_demo_and_the_benchmark_judge_waivers_on_a_fixed_date(monkeypatch, tmp_path):
    def no_clock(text=None):
        if text is None:
            raise AssertionError("read the clock")
        return datetime.date.fromisoformat(text)
    monkeypatch.setattr(rules, "today", no_clock)
    seen = []
    real = audit.analyze
    monkeypatch.setattr(audit, "analyze", lambda *a, **k: seen.append(k.get("day")) or real(*a, **k))
    assert demo.run(tmp_path / "demo", yes=True)[0] == 0
    cache = json.loads((FIX / "audit" / "osv-cache.json").read_text())
    assert seen == [datetime.date.fromisoformat(cache["fetched_at"][:10])]
    result = compare.run(ROOT, ROOT / "bench" / "tasks.json")
    assert result and isinstance(compare.DAY, datetime.date)


def adr(root: Path, name: str, front: list[str]) -> None:
    (root / "docs" / "adr").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "adr" / name).write_text("\n".join(["---", *front, "---", "", "# Title", ""]), encoding="utf-8")


def test_init_reads_waivers_from_adr_front_matter_as_it_reads_rule(tmp_path):
    root = tmp_path / "repo"
    (root / "src" / "payments").mkdir(parents=True)
    (root / "src" / "payments" / "charge.py").write_text("x = 1\n")
    w = [waiver(path="src/payments/**", rule="review_required")]
    adr(root, "0001-review.md", ["code_ref: [src/payments/]", 'rule: {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@a"]}}',
                                 "waivers: " + json.dumps(w)])
    adr(root, "0002-bad.md", ["code_ref: [src/payments/]", 'rule: {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@b"]}}',
                              'waivers: [{"path": "src/**"}]'])
    snap = init.build(root, "Shop")
    by = {n["props"]["source_file"]: n for n in snap["nodes"] if n["kind"] == "decision"}
    assert by["docs/adr/0001-review.md"]["props"]["waivers"] == w
    rep = check.run(co.load(init.dump(snap)), ["src/payments/charge.py"], root, [], 3, "Shop", day=TODAY)
    assert [r["decision"] for r in rep["waived"]] == [by["docs/adr/0001-review.md"]["id"]]
    assert [r["decision"] for r in rep["violations"]] == [by["docs/adr/0002-bad.md"]["id"]]
    assert [p["decision"] for p in rep["rule_problems"]] == [by["docs/adr/0002-bad.md"]["id"]]


def test_new_adr_writes_waivers_that_init_reads_back_and_refuses_an_unreadable_one(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "docs" / "adr").mkdir(parents=True)
    rule = {"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}
    w = [waiver(path="src/payments/legacy/**", rule="review_required"), waiver(path="src/payments/**", expires="2027-01-31")]
    capsys.readouterr()
    assert cli.main(["new-adr", "Payments review", "--repo-dir", str(root), "--rule", json.dumps(rule), "--date", DAY,
                     "--waiver", json.dumps(w[0]), "--waiver", json.dumps(w[1])]) == 0
    path = Path(json.loads(capsys.readouterr().out)["out"])
    assert "waivers: " + json.dumps(w) in path.read_text()
    [node] = [n for n in init.build(root, "Shop")["nodes"] if n["kind"] == "decision"]
    assert node["props"]["waivers"] == w and rules.of(node).waiver_problems == ()
    for bad, reason in (({**w[0], "expires": "2027-02-30"}, "expires must be a date"), ([w[0]], "must be one JSON object"),
                        ("{", "is not valid JSON")):
        with pytest.raises(SystemExit) as e:
            cli.main(["new-adr", "Another", "--repo-dir", str(root), "--waiver", bad if isinstance(bad, str) else json.dumps(bad)])
        assert e.value.code == 2 and reason in capsys.readouterr().err
    assert len(list((root / "docs" / "adr").iterdir())) == 1
    with pytest.raises(ValueError, match="waives nothing"):
        madr.write(root, "Third", waivers=[json.dumps(waiver())])


def test_the_text_mermaid_and_html_check_views_show_waived_results_apart_with_their_expiry():
    rep = checked({REVIEW_RULE: [waiver(path="src/payments/**")], IMPORT_RULE: [waiver(path="web/**", expires="2027-01-31")]})
    text = check.render(rep)
    head, _, tail = text.partition("waived, not counted as violations")
    assert "violations: 7" in head and f"(today is {DAY}): 2" in tail
    assert "src/payments/charge.py  decision:payments-need-a-payments-review  review_required" in tail and f"until {DAY}" in tail
    assert "web/src/ui/page.ts:1" in tail and "until 2027-01-31, approved by @shop/security: no patched release yet" in tail
    md = render.mermaid("check", rep)
    assert "review_required waived until 2026-11-25" in md and "imports_forbidden waived until 2027-01-31" in md
    assert "classDef waived" in md
    page = render.html("check", rep)
    assert "<h2>Waived, not counted as violations</h2>" in page and '<tr class="waived">' in page
    assert "waiver 1 until 2027-01-31, approved by @shop/security: no patched release yet" in page
    violations = page.split("<h2>Violations</h2>")[1].split("</section>")[0]
    assert "web/src/ui/page.ts" not in violations and "src/payments/charge.py" not in violations
    plain = checked({})
    assert "waived" not in check.render(plain) and "Waived" not in render.html("check", plain)


def test_the_mermaid_and_html_audit_views_show_waived_findings_apart_with_their_expiry():
    rep = audited([waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gw", expires="2027-01-31")])
    md = render.mermaid("audit", rep)
    assert "waived until 2027-01-31" in md and "classDef waived" in md
    page = render.html("audit", rep)
    assert '<li class="item waived">' in page and '<span class="badge waived">waived until 2027-01-31</span>' in page
    assert "waiver 1 until 2027-01-31, approved by @shop/security: no patched release yet" in page
    assert "<dt>waived</dt><dd>1</dd>" in page and f"<dt>waivers judged on</dt><dd>{DAY}</dd>" in page
    assert page.count('<li class="item violated">') == 2


@pytest.mark.parametrize("kind", ["audit", "check"])
@pytest.mark.parametrize("fmt,suffix", [("mermaid", "md"), ("html", "html")])
@pytest.mark.parametrize("name,warn", [("waived", ["--warn-days", "0"]), ("expiring", [])])
def test_waived_views_render_to_the_committed_golden_output_on_a_fixed_date(kind, fmt, suffix, name, warn, tmp_path, capsys, no_network):
    import os
    if kind == "audit":
        snap = with_waivers(FIX / "audit" / "vinc.json", {ADVISORY_RULE: [waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gw")]})
        args = [str(FIX / "audit" / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(FIX / "audit" / "osv-cache.json")]
    else:
        snap = with_waivers(FIX / "check" / "vinc.json", {REVIEW_RULE: [waiver(path="src/payments/**")],
                                                          IMPORT_RULE: [waiver(path="web/**", expires="2026-11-24")]})
        args = ["--repo-dir", str(CHECK_REPO), "--changed", *CHANGED]
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    capsys.readouterr()
    cli.main([kind, str(path), *args, "--format", fmt, "--today", DAY, *warn, *(["--no-signature"] if fmt == "html" else [])])
    out = capsys.readouterr().out
    golden = ROOT / "tests" / "golden" / f"{kind}-{name}.{suffix}"
    if os.environ.get("DECISIS_GOLDEN") == "write":
        golden.write_text(out, encoding="utf-8")
    assert out == golden.read_text(encoding="utf-8")


def test_the_mcp_check_and_audit_replies_show_waived_results_apart(tmp_path, no_network):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    from test_serve import over_mcp
    snap = with_waivers(FIX / "check" / "vinc.json", {REVIEW_RULE: [waiver(path="src/payments/**")]})
    path = tmp_path / "check.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    _, (short, full, bad) = over_mcp(serve.load_tools(path, CHECK_REPO, None, False),
                                     ("check", {"changed": CHANGED, "today": DAY}), ("check", {"changed": CHANGED, "today": DAY, "detail": "full"}),
                                     ("check", {"changed": CHANGED, "today": "tomorrow"}))
    s = short.structured_content
    assert s["today"] == DAY and s["summary"]["waived"] == 1 and s["waived_count"] == 1
    assert s["waived"][0]["file"] == "src/payments/charge.py" and s["waived"][0]["waiver"]["expires"] == DAY
    assert all(v["file"] != "src/payments/charge.py" for v in s["violations"])
    assert full.structured_content["waived"][0]["verdict"] == "waived" and bad.is_error
    snap = with_waivers(FIX / "audit" / "vinc.json", {ADVISORY_RULE: [waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gw")]})
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    _, (au, late) = over_mcp(serve.load_tools(path, FIX / "audit", FIX / "audit" / "osv-cache.json", False),
                             ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo", "today": DAY}),
                             ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo", "today": "2026-11-26"}))
    a = au.structured_content
    assert (a["violations"], a["waived"], a["today"]) == (2, 1, DAY)
    assert [f["waived"] for f in a["findings"] if "waived" in f] == [[{"decision": ADVISORY_RULE, "expires": DAY}]]
    assert (late.structured_content["violations"], late.structured_content["waived"]) == (3, 0)


def test_the_action_comment_shows_waived_findings_apart_and_fail_on_violation_ignores_them(tmp_path, no_network):
    from test_action import FakeGitHub, audit_env, outputs, shop, DEMO_LOCK
    root, base = shop(tmp_path)
    snap = with_waivers(FIX / "check" / "vinc.json", {})
    extra = json.loads((FIX / "action" / "vinc.json").read_text(encoding="utf-8"))
    ids = {n["id"] for n in snap["nodes"]}
    snap["nodes"] += [n for n in extra["nodes"] if n["id"] not in ids]
    snap["edges"] += extra["edges"]
    snap["meta"] = {k: v for k, v in snap.get("meta", {}).items() if k not in ("nodes", "edges")}
    for n in snap["nodes"]:
        if n["kind"] == "decision":
            n["props"]["waivers"] = [waiver(path="**"), waiver(package=LODASH)]
    path = tmp_path / "waived.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    fake = FakeGitHub()
    env = {**audit_env(tmp_path, root, base, str(DEMO_LOCK), DECISIS_FAIL_ON_VIOLATION="true", DECISIS_TODAY=DAY), "DECISIS_SNAPSHOT": str(path)}
    assert action.main(env, fake) == 0
    (_, _, data), = fake.writes()
    body = data["body"]
    assert outputs(tmp_path)["violations"] == "0"
    assert "#### Waived, not counted as violations (" in body and "Waived until" in body
    assert action.text(f"{DAY}, approved by @shop/security: no patched release yet") in body
    assert "Waived, not counted as violations (3):" in body and "0 violation(s), 0 audit violation(s)" in body
    late = tmp_path / "late"
    late.mkdir()
    env = {**audit_env(late, root, base, str(DEMO_LOCK), DECISIS_FAIL_ON_VIOLATION="true", DECISIS_TODAY="2026-11-26"), "DECISIS_SNAPSHOT": str(path)}
    assert action.main(env, FakeGitHub()) == 1 and int(outputs(late)["violations"]) > 0


def test_propose_records_a_waived_finding_and_the_checker_re_derives_its_scope(no_network):
    deny = {"package_denied": [{"ecosystem": "npm", "name": "event-stream"}]}
    vinc = snapshot(("decision:deny", deny))
    vinc.nodes[-1]["props"]["waivers"] = [waiver(package={"ecosystem": "npm", "name": "event-stream"})]
    rep = audit.run(vinc, json.dumps(LOCK), "Shop", advisories=no_advisories, day=TODAY)
    plan = wb.propose(rep, "Shop", "space", today=DAY)
    [node] = [n for n in plan["nodes"] if n["props"]["predicate"] == "uses_denied_package"]
    assert node["props"]["violates"] == [] and node["props"]["waived"] == ["decision:deny"]
    assert [e["evidence"].split(":")[0] for e in plan["edges"] if e["from"] == node["id"]] == ["waived"]
    plan, checked_ = checker.rederive(plan, vinc, json.dumps(LOCK), "Shop", no_advisories)
    assert not any(c["problems"] for c in checked_) and node["id"] in [n["id"] for n in plan["nodes"]]
    bad = copy.deepcopy(plan)
    [n] = [n for n in bad["nodes"] if n["id"] == node["id"]]
    n["props"]["scope"] = "development"
    _, again = checker.rederive(bad, vinc, json.dumps(LOCK), "Shop", no_advisories)
    [c] = [c for c in again if c["record"] == node["id"]]
    assert any("does not match scope development" in p for p in c["problems"])
    other = snapshot(("decision:deny", {"license_denied": ["GPL-3.0-only"]}))
    _, again = checker.rederive(plan, other, json.dumps(LOCK), "Shop", no_advisories)
    [c] = [c for c in again if c["record"] == node["id"]]
    assert c["problems"] == ["decision:deny has no package rule that event-stream 3.3.6 violates"]


def test_an_advisory_record_of_a_waived_finding_is_re_derived_like_any_other(no_network):
    snap = with_waivers(FIX / "audit" / "vinc.json", {ADVISORY_RULE: [waiver(package=LODASH)]})
    vinc = co.load(json.dumps(snap))
    rep = audit.run(vinc, lock(), "Demo", advisories=advisories(), day=TODAY)
    plan = wb.propose(rep, "Demo", "space", today=DAY)
    waived = [n for n in plan["nodes"] if n["props"].get("waived") == [ADVISORY_RULE]]
    assert waived and all(n["props"]["violates"] == [] for n in waived)
    plan, checked_ = checker.rederive(plan, vinc, lock(), "Demo", advisories())
    assert not any(c["problems"] for c in checked_)
    n = copy.deepcopy(waived[0])
    n["props"]["dependency_paths"] = [p[:1] + p[2:] for p in n["props"]["dependency_paths"]]
    _, again = checker.rederive({**plan, "nodes": [n], "edges": []}, vinc, lock(), "Demo", advisories())
    assert again[0]["problems"]


def test_a_hostile_waiver_reaches_the_views_and_the_comment_only_as_escaped_text():
    hostile = "<script>alert(1)</script> | **x** [y](javascript:alert(1)) @everyone"
    rep = checked({REVIEW_RULE: [{**waiver(path="src/payments/**"), "reason": hostile, "approved_by": hostile}]})
    assert rep["waived"][0]["waiver"]["reason"] == hostile
    assert "<script" not in render.html("check", rep) and "<script" not in render.mermaid("check", rep)
    from test_action import pull
    comment = action.body(action.Outcome(rep, pull(), [], "0.1.1", "snap.json"))
    assert "<script" not in comment and "@everyone" not in comment and "javascript:alert" not in comment.replace("javascript\\:alert", "")
    assert "#### Waived, not counted as violations (1)" in comment
