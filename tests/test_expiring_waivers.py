from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

import pytest
import yaml

from test_audit import advisories, lock, no_network
from test_waivers import (ADVISORY_RULE, CHANGED, CHECK_REPO, DAY, FIX, IMPORT_RULE, LODASH, REVIEW_RULE, TODAY, waiver, with_waivers)
from decisis import action, audit, check, cli, compact, render, rules
from decisis import checkout as co
from decisis import serve

ROOT = Path(__file__).resolve().parents[1]
PAYMENTS = "src/payments/**"
P6MC = "GHSA-p6mc-m468-83gw"
G35J = "GHSA-35jh-r3h4-6jhm"
SOON = "expiring_soon"


def days(n: int) -> str:
    return (TODAY + datetime.timedelta(days=n)).isoformat()


def entry(decision: str, number: int, left: int, **extra) -> dict:
    return {"decision": decision, "waiver": number, "reason": "no patched release yet", "approved_by": "@shop/security",
            "expires": days(left), "days_left": left, **extra}


def check_report(waivers: dict, reviewers=("bob",), **kw) -> dict:
    snap = with_waivers(FIX / "check" / "vinc.json", waivers)
    return check.run(co.load(json.dumps(snap)), CHANGED, CHECK_REPO, list(reviewers), day=TODAY, **kw)


def audit_report(waivers: list, **kw) -> dict:
    snap = with_waivers(FIX / "audit" / "vinc.json", {ADVISORY_RULE: waivers})
    return audit.run(co.load(json.dumps(snap)), lock(), "Demo", advisories=advisories(), day=TODAY, **kw)


def without_soon(report: dict) -> dict:
    return {k: v for k, v in report.items() if k != SOON}


def snapshot_file(tmp_path: Path, kind: str, waivers) -> Path:
    snap = with_waivers(FIX / kind / "vinc.json", waivers)
    path = tmp_path / f"{kind}.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    return path


@pytest.mark.parametrize("warn", [None, 14, 7, 1])
def test_check_lists_a_waiver_ending_in_exactly_warn_days_and_not_one_ending_a_day_later(warn):
    n = rules.WARN_DAYS if warn is None else warn
    kw = {} if warn is None else {"warn_days": warn}
    rep = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(n))], IMPORT_RULE: [waiver(path="web/**", expires=days(n + 1))]}, **kw)
    assert rep[SOON] == [entry(REVIEW_RULE, 1, n)]
    assert {r["decision"] for r in rep["waived"]} == {REVIEW_RULE, IMPORT_RULE}


@pytest.mark.parametrize("warn", [None, 14, 7, 1])
def test_audit_lists_a_waiver_ending_in_exactly_warn_days_and_not_one_ending_a_day_later(warn):
    n = rules.WARN_DAYS if warn is None else warn
    kw = {} if warn is None else {"warn_days": warn}
    rep = audit_report([waiver(package=LODASH, advisory=P6MC, expires=days(n)), waiver(package=LODASH, advisory=G35J, expires=days(n + 1))], **kw)
    assert rep[SOON] == [entry(ADVISORY_RULE, 1, n)]
    assert rep["waived"] == 2


def test_the_default_window_is_fourteen_days_and_a_waiver_ending_today_has_no_days_left():
    assert rules.WARN_DAYS == 14
    assert check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=DAY)]})[SOON] == [entry(REVIEW_RULE, 1, 0)]
    assert SOON not in check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(15))]})
    assert audit_report([waiver(package=LODASH, expires=days(14))])[SOON] == [entry(ADVISORY_RULE, 1, 14)]
    assert SOON not in audit_report([waiver(package=LODASH, expires=days(15))])


def test_a_waiver_that_covers_nothing_in_this_run_is_not_listed_in_check():
    tomorrow = days(1)
    rep = check_report({REVIEW_RULE: [waiver(path="docs/**", expires=tomorrow), waiver(path=PAYMENTS, rule="imports_forbidden", expires=tomorrow),
                                      waiver(path=PAYMENTS, to="src/shop/db/**", expires=tomorrow)],
                        IMPORT_RULE: [waiver(path="web/**", rule="review_required", expires=tomorrow)]})
    assert rep["waived"] == [] and SOON not in rep
    clear = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=tomorrow)], "decision:payments-reviewed-by-carol": [waiver(path=PAYMENTS, expires=tomorrow)]},
                         reviewers=("@alice", "@carol"))
    assert clear["waived"] == [] and SOON not in clear


def test_a_waiver_that_covers_nothing_in_this_run_is_not_listed_in_audit():
    tomorrow = days(1)
    rep = audit_report([waiver(package={"ecosystem": "npm", "name": "left-pad"}, expires=tomorrow),
                        waiver(package={**LODASH, "versions": ["4.17.21"]}, expires=tomorrow),
                        waiver(package=LODASH, advisory="GHSA-p6mc-m468-83gx", expires=tomorrow)])
    assert rep["waived"] == 0 and SOON not in rep


def test_a_waiver_that_already_ended_is_not_listed_because_its_result_is_a_violation_again():
    rep = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(-1))]})
    assert SOON not in rep and rep["waived"] == []
    assert audit_report([waiver(package=LODASH, expires=days(-1))]).get(SOON) is None


def test_a_waiver_that_covers_many_results_is_listed_once():
    rep = check_report({IMPORT_RULE: [waiver(path="**", expires=days(5))]})
    assert len(rep["waived"]) == 8
    assert rep[SOON] == [entry(IMPORT_RULE, 1, 5)]
    found = audit_report([waiver(package=LODASH, expires=days(5))])
    assert found["waived"] == 3 and found[SOON] == [entry(ADVISORY_RULE, 1, 5)]


def test_when_two_waivers_cover_a_result_the_one_that_lasts_longest_decides_whether_it_is_listed():
    longer = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(3)), waiver(path=PAYMENTS, expires=days(90))]})
    assert [r["waiver"]["waiver"] for r in longer["waived"]] == [2] and SOON not in longer
    soon = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(5)), waiver(path=PAYMENTS, expires=days(10))]})
    assert soon[SOON] == [entry(REVIEW_RULE, 2, 10)]


def test_the_entries_are_ordered_by_expiry_then_decision_then_waiver_number():
    rep = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(9))], IMPORT_RULE: [waiver(path="web/**", expires=days(2)), waiver(path="src/shop/**", expires=days(2))]})
    assert [(e["decision"], e["waiver"], e["days_left"]) for e in rep[SOON]] == [(IMPORT_RULE, 1, 2), (IMPORT_RULE, 2, 2), (REVIEW_RULE, 1, 9)]


def test_zero_turns_the_list_off_and_the_window_is_at_most_ten_years():
    waivers = {REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(1))]}
    assert SOON not in check_report(waivers, warn_days=0) and SOON in check_report(waivers, warn_days=1)
    assert SOON not in audit_report([waiver(package=LODASH, expires=days(1))], warn_days=0)
    today = {REVIEW_RULE: [waiver(path=PAYMENTS, expires=DAY)]}
    assert SOON in check_report(today) and SOON not in check_report(today, warn_days=0)
    assert SOON in audit_report([waiver(package=LODASH, expires=DAY)]) and SOON not in audit_report([waiver(package=LODASH, expires=DAY)], warn_days=0)
    assert rules.MAX_WARN_DAYS == 3650


def test_expiring_soon_never_changes_a_verdict_or_a_count_in_check_or_audit():
    waivers = {REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(2))], IMPORT_RULE: [waiver(path="web/**", expires=days(40))]}
    on, off = check_report(waivers), check_report(waivers, warn_days=0)
    assert SOON in on and SOON not in off and without_soon(on) == off
    assert check.failed(on, True) == check.failed(off, True) and check.failed(on, False) == check.failed(off, False)
    found = [waiver(package=LODASH, advisory=P6MC, expires=days(2)), waiver(package=LODASH, advisory=G35J, expires=days(40))]
    on, off = audit_report(found), audit_report(found, warn_days=0)
    assert SOON in on and SOON not in off and without_soon(on) == off
    assert (on["violations"], on["waived"]) == (off["violations"], off["waived"]) == (1, 2)


@pytest.mark.parametrize("flag", [[], ["--fail-on-unresolved"]])
def test_the_check_exit_code_is_the_same_with_the_list_on_and_off(flag, tmp_path, capsys):
    clean = snapshot_file(tmp_path, "check", {IMPORT_RULE: [waiver(path="**", expires=days(3))], REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(3))]})
    base = ["check", str(clean), "--repo-dir", str(CHECK_REPO), "--changed", *CHANGED, "--today", DAY, *flag]
    capsys.readouterr()
    code_on = cli.main(base)
    on = json.loads(capsys.readouterr().out)
    code_off = cli.main([*base, "--warn-days", "0"])
    off = json.loads(capsys.readouterr().out)
    assert SOON in on and SOON not in off and code_on == code_off
    assert without_soon(on) == off
    snap = snapshot_file(tmp_path, "check", {IMPORT_RULE: [waiver(path="web/**", expires=days(3))]})
    base[1] = str(snap)
    assert cli.main(base) == 1 and cli.main([*base, "--warn-days", "0"]) == 1


@pytest.mark.parametrize("bad", ["-1", "abc", "1.5", "3651", ""])
def test_a_bad_warn_days_flag_is_refused_by_check_and_audit(bad, tmp_path, capsys):
    snap = snapshot_file(tmp_path, "check", {})
    with pytest.raises(SystemExit) as e:
        cli.main(["check", str(snap), "--changed", "a.py", "--warn-days", bad])
    assert e.value.code == 2 and "--warn-days" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", str(snap), str(FIX / "audit" / "demo-lockfile.json"), "--repo", "Demo", "--warn-days", bad])
    assert e.value.code == 2 and "--warn-days" in capsys.readouterr().err


def test_the_audit_flag_lists_the_waiver_in_the_report_and_counts_it_in_the_out_summary(tmp_path, capsys, no_network):
    snap = snapshot_file(tmp_path, "audit", {ADVISORY_RULE: [waiver(package=LODASH, advisory=P6MC, expires=days(6))]})
    args = ["audit", str(snap), str(FIX / "audit" / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(FIX / "audit" / "osv-cache.json"),
            "--today", DAY]
    capsys.readouterr()
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)[SOON] == [entry(ADVISORY_RULE, 1, 6)]
    assert cli.main([*args, "--warn-days", "5"]) == 0
    assert SOON not in json.loads(capsys.readouterr().out)
    assert cli.main([*args, "--out", str(tmp_path / "r.json")]) == 0
    assert json.loads(capsys.readouterr().out)[SOON] == 1
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))[SOON] == [entry(ADVISORY_RULE, 1, 6)]
    assert cli.main([*args, "--out", str(tmp_path / "r.json"), "--warn-days", "0"]) == 0
    assert SOON not in json.loads(capsys.readouterr().out)


def test_the_text_mermaid_and_html_check_views_show_expiring_waivers_apart_from_the_waived_results():
    rep = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(6))], IMPORT_RULE: [waiver(path="web/**", expires=days(60))]})
    text = check.render(rep)
    head, _, tail = text.partition("waivers that expire soon")
    assert "waived, not counted as violations" in head and f"(today is {DAY}): 1" in tail
    assert f"decision:payments-need-a-payments-review  waiver 1 until {days(6)} (6 day(s) left), approved by @shop/security: no patched release yet" in tail
    assert "web/src/ui/page.ts" not in tail
    md = render.mermaid("check", rep)
    assert f"waiver 1 expires {days(6)}, 6 day(s) left" in md and "expires soon" in md and "classDef expiring" in md
    assert md.count("expires soon") == 1
    page = render.html("check", rep)
    soon = page.split("<h2>Waivers that expire soon</h2>")[1].split("</section>")[0]
    assert "<td>6</td>" in soon and days(6) in soon and "payments-need-a-payments-review" in soon and "web/src/ui/page.ts" not in soon
    waived = page.split("<h2>Waived, not counted as violations</h2>")[1].split("</section>")[0]
    assert "days left" not in waived and "Waivers that expire soon" not in waived
    assert page.index("Waivers that expire soon") < page.index("<h2>Violations</h2>")
    plain = check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(60))]})
    assert "expire soon" not in check.render(plain) and "expire soon" not in render.html("check", plain)
    assert "expires soon" not in render.mermaid("check", plain)


def test_the_mermaid_and_html_audit_views_show_expiring_waivers_apart_from_the_waived_findings():
    rep = audit_report([waiver(package=LODASH, advisory=P6MC, expires=days(9)), waiver(package=LODASH, advisory=G35J, expires=days(90))])
    md = render.mermaid("audit", rep)
    assert f"waiver 1 expires {days(9)}, 9 day(s) left" in md and "expires soon" in md and "classDef expiring" in md
    page = render.html("audit", rep)
    soon = page.split("<h2>Waivers that expire soon</h2>")[1].split("</section>")[0]
    assert "<td>9</td>" in soon and days(9) in soon and ADVISORY_RULE in soon and days(90) not in soon
    assert page.count('<li class="item waived">') == 2
    assert page.index("Waivers that expire soon") < page.index("<h2>Governing decisions</h2>")
    plain = audit_report([waiver(package=LODASH, expires=days(90))])
    assert "expire soon" not in render.html("audit", plain) and "expires soon" not in render.mermaid("audit", plain)


def test_a_hostile_waiver_reaches_the_expiring_views_only_as_escaped_text():
    hostile = "<script>alert(1)</script> | **x** [y](javascript:alert(1)) @everyone"
    rep = check_report({REVIEW_RULE: [{**waiver(path=PAYMENTS, expires=days(3)), "reason": hostile, "approved_by": hostile}]})
    assert rep[SOON][0]["reason"] == hostile
    assert "<script" not in render.html("check", rep) and "<script" not in render.mermaid("check", rep)
    assert hostile not in render.mermaid("check", rep) and "@everyone" not in render.mermaid("check", rep)
    from test_action import pull
    comment = action.body(action.Outcome(rep, pull(), [], "0.1.1", "snap.json"))
    assert "<script" not in comment and "@everyone" not in comment and "javascript:alert" not in comment.replace("javascript\\:alert", "")
    assert "#### Waivers that expire soon (1)" in comment


def test_the_mcp_check_and_audit_replies_show_expiring_waivers_apart_and_take_warn_days(tmp_path, no_network):
    from test_serve import over_mcp
    path = snapshot_file(tmp_path, "check", {REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(4))]})
    _, (short, full, off, bad, text) = over_mcp(
        serve.load_tools(path, CHECK_REPO, None, False),
        ("check", {"changed": CHANGED, "today": DAY}), ("check", {"changed": CHANGED, "today": DAY, "detail": "full"}),
        ("check", {"changed": CHANGED, "today": DAY, "warn_days": 0}), ("check", {"changed": CHANGED, "today": DAY, "warn_days": -1}),
        ("check", {"changed": CHANGED, "today": DAY, "warn_days": "7"}))
    s = short.structured_content
    assert s["expiring_soon_count"] == 1 and s[SOON] == [entry(REVIEW_RULE, 1, 4)]
    assert s["waived_count"] == 1 and s["summary"]["waived"] == 1 and all(SOON not in w for w in s["waived"])
    assert full.structured_content[SOON] == [entry(REVIEW_RULE, 1, 4)]
    assert SOON not in off.structured_content and "expiring_soon_count" not in off.structured_content
    assert bad.is_error and text.is_error
    path = snapshot_file(tmp_path, "audit", {ADVISORY_RULE: [waiver(package=LODASH, advisory=P6MC, expires=days(4))]})
    _, (au, none) = over_mcp(serve.load_tools(path, FIX / "audit", FIX / "audit" / "osv-cache.json", False),
                             ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo", "today": DAY}),
                             ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo", "today": DAY, "warn_days": 3}))
    a = au.structured_content
    assert a["expiring_soon_count"] == 1 and a[SOON] == [entry(ADVISORY_RULE, 1, 4)] and a["waived"] == 1
    assert SOON not in none.structured_content
    assert SOON in compact.shape("check", {**check_report({REVIEW_RULE: [waiver(path=PAYMENTS, expires=days(4))]})})


def test_the_mcp_tool_schemas_bound_warn_days_as_the_cli_does():
    for name in ("audit", "check"):
        prop = serve.SCHEMAS[name]["properties"]["warn_days"]
        assert (prop["type"], prop["minimum"], prop["maximum"], prop["default"]) == ("integer", 0, rules.MAX_WARN_DAYS, rules.WARN_DAYS)
        assert "expiring_soon" in serve.DESCRIPTIONS[name]


def action_snapshot(tmp_path: Path, waivers: dict) -> Path:
    snap = with_waivers(FIX / "check" / "vinc.json", waivers)
    path = tmp_path / "soon.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    return path


def comment_of(tmp_path: Path, waivers: dict, **extra) -> tuple[int, str, dict]:
    from test_action import FakeGitHub, environment, outputs, shop
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    env = environment(tmp_path, root, base, DECISIS_SNAPSHOT=str(action_snapshot(tmp_path, waivers)), DECISIS_TODAY=DAY, **extra)
    code = action.main(env, fake)
    writes = fake.writes()
    return code, (writes[0][2]["body"] if writes else ""), (outputs(tmp_path) if (tmp_path / "output.txt").exists() else {})


def test_the_action_comment_has_its_own_section_above_the_violations_with_the_date_and_days_left(tmp_path, no_network):
    code, body, out = comment_of(tmp_path, {IMPORT_RULE: [waiver(path="web/**", expires=days(5))]})
    assert code == 0 and "#### Waivers that expire soon (1)" in body
    section = body.split("#### Waivers that expire soon (1)")[1].split("####")[0]
    assert action.code(IMPORT_RULE) in section and action.text(days(5)) in section and " | 5 | " in section
    assert action.text("@shop/security") in section and action.text("no patched release yet") in section
    assert body.index("#### Waivers that expire soon") < body.index("#### Violations") < body.index("#### Waived, not counted as violations")
    assert body.index("#### Waivers that expire soon") < body.index("#### Decisions touched")
    assert int(out["violations"]) > 0


def test_the_action_comment_has_no_section_when_nothing_expires_soon_or_warn_days_is_zero(tmp_path, no_network):
    waivers = {IMPORT_RULE: [waiver(path="web/**", expires=days(5))]}
    for name, extra, waived in (("far", {}, {IMPORT_RULE: [waiver(path="web/**", expires=days(15))]}),
                                ("off", {"DECISIS_WARN_DAYS": "0"}, waivers), ("narrow", {"DECISIS_WARN_DAYS": "4"}, waivers),
                                ("offtoday", {"DECISIS_WARN_DAYS": "0"}, {IMPORT_RULE: [waiver(path="web/**", expires=DAY)]})):
        sub = tmp_path / name
        sub.mkdir()
        code, body, _ = comment_of(sub, waived, **extra)
        assert code == 0 and "Waivers that expire soon" not in body and "#### Waived, not counted as violations" in body
    sub = tmp_path / "exact"
    sub.mkdir()
    code, body, _ = comment_of(sub, waivers, DECISIS_WARN_DAYS="5")
    assert code == 0 and "#### Waivers that expire soon (1)" in body
    sub = tmp_path / "blank"
    sub.mkdir()
    code, body, _ = comment_of(sub, {IMPORT_RULE: [waiver(path="web/**", expires=days(14))]}, DECISIS_WARN_DAYS=" ")
    assert code == 0 and "#### Waivers that expire soon (1)" in body


@pytest.mark.parametrize("flags", [{"DECISIS_FAIL_ON_VIOLATION": "true"}, {"DECISIS_FAIL_ON_VIOLATION": "true", "DECISIS_FAIL_ON_UNRESOLVED": "true"}])
def test_the_action_comment_lists_each_check_and_audit_waiver_once_and_the_fail_flags_ignore_them(flags, tmp_path, no_network):
    import shutil
    from test_action import DEMO_LOCK, FakeGitHub, audit_env, outputs, shop
    root, base = shop(tmp_path)
    second = tmp_path / "second" / DEMO_LOCK.name
    second.parent.mkdir()
    shutil.copy(DEMO_LOCK, second)
    snap = with_waivers(FIX / "check" / "vinc.json", {})
    extra = json.loads((FIX / "action" / "vinc.json").read_text(encoding="utf-8"))
    ids = {n["id"] for n in snap["nodes"]}
    snap["nodes"] += [n for n in extra["nodes"] if n["id"] not in ids]
    snap["edges"] += extra["edges"]
    snap["meta"] = {k: v for k, v in snap.get("meta", {}).items() if k not in ("nodes", "edges")}
    for n in snap["nodes"]:
        if n["kind"] == "decision":
            n["props"]["waivers"] = [waiver(path="**", expires=days(3)), waiver(package=LODASH, expires=days(3))]
    path = tmp_path / "waived.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    done = []
    for name, warn in (("on", "14"), ("off", "0")):
        sub = tmp_path / name
        sub.mkdir()
        fake = FakeGitHub()
        env = {**audit_env(sub, root, base, f"{DEMO_LOCK}\n{second}", DECISIS_TODAY=DAY, DECISIS_WARN_DAYS=warn, **flags), "DECISIS_SNAPSHOT": str(path)}
        done.append((action.main(env, fake), fake.writes()[0][2]["body"], outputs(sub)))
    (code_on, on, out_on), (code_off, off, out_off) = done
    assert code_on == code_off and out_on == out_off
    if "DECISIS_FAIL_ON_UNRESOLVED" not in flags:
        assert code_on == 0 and out_on["violations"] == "0"
    assert on.count("#### Audit of") == 2 and "Waivers that expire soon" not in off
    section = re.search(r"#### Waivers that expire soon \((\d+)\)\n.*?(?=#### )", on, re.S)
    rows = [line.split(" | ")[:2] for line in section.group(0).splitlines() if line.startswith("| <code>")]
    assert len(rows) == int(section.group(1)) and len({tuple(r) for r in rows}) == len(rows)
    assert {r[1] for r in rows} == {"1", "2"}
    prose = lambda body: body.split("<details>")[0]
    assert re.sub(r"#### Waivers that expire soon.*?(?=#### )", "", prose(on), flags=re.S) == prose(off)


def test_the_input_is_warn_days_with_default_14_and_reaches_python_only_through_the_environment():
    doc = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["warn-days"]["default"] == "14"
    step, = (s for s in doc["runs"]["steps"] if s.get("id") == "check")
    assert step["env"]["DECISIS_WARN_DAYS"] == "${{ inputs.warn-days }}"
    assert "${{" not in step["run"] and "warn-days" not in step["run"]


def test_warn_days_reads_a_whole_number_or_falls_back_to_the_default():
    assert action.warn_days({}) == 14 and action.warn_days({"DECISIS_WARN_DAYS": ""}) == 14 and action.warn_days({"DECISIS_WARN_DAYS": "  "}) == 14
    assert [action.warn_days({"DECISIS_WARN_DAYS": v}) for v in ("0", "7", " 30 ", "3650")] == [0, 7, 30, 3650]


@pytest.mark.parametrize("bad", ["abc", "-1", "+5", "1.5", "1e1", "0x10", "14 days", "3651", "٣", "True"])
@pytest.mark.parametrize("mode", ["head", "base"])
def test_a_bad_warn_days_value_stops_the_step_before_any_request(bad, mode, tmp_path, capsys, no_network):
    from test_action import FakeGitHub, environment, shop
    root, base = shop(tmp_path)
    fake = FakeGitHub()
    env = environment(tmp_path, root, base, DECISIS_WARN_DAYS=bad, DECISIS_DECISIONS_FROM=mode)
    assert action.main(env, fake) == 2 and fake.sent == []
    assert "DECISIS_WARN_DAYS must be a whole number from 0 to 3650" in capsys.readouterr().out
    assert not (tmp_path / "output.txt").exists()


def test_the_docs_describe_the_field_and_the_input():
    model = (ROOT / "docs" / "data-model.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "action.md").read_text(encoding="utf-8")
    assert "`expiring_soon`" in model and "`--warn-days N`" in model and "`days_left`" in model
    assert "| `warn-days` | `14` |" in guide and "Waivers that expire soon" in guide
