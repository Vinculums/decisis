from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from test_audit import advisories, lock, no_network
from test_audit_init import ADR_0010, SHIPPED, node, snapshot, violated
from test_checker_governs import PINNED, RULE, assert_held_for, hand, hand_report, propose
from decisis import action, audit, check, cli, compact, cycles, impact
from decisis import checkout as co

ROOT = Path(__file__).resolve().parents[1]
DAY = datetime.date(2026, 11, 26)
TODAY = DAY.isoformat()
FILE = "src/pay/a.py"
PAY = {"id": "concept:pay", "kind": "concept", "title": "Payments", "props": {"code_ref": "src/pay/"}}
A, B, C = "decision:a", "decision:b", "decision:c"


def decision(nid: str, until: str | None = None, column: str | None = None, **props) -> dict:
    rule = {"review_required": {"paths": ["src/pay/**"], "reviewers": ["@" + nid.split(":")[1]]}}
    return {"id": nid, "kind": "decision", "title": nid.split(":")[1].upper(),
            **({"valid_until": column} if column is not None else {}),
            "props": {"rule": rule, **({"valid_until": until} if until is not None else {}), **props}}


def graph(*decisions: dict, supersedes: tuple[tuple[str, str], ...] = ()):
    edges = [{"source": d["id"], "target": PAY["id"], "type": "ABOUT", "evidence": "test"} for d in decisions]
    edges += [{"source": a, "target": b, "type": "SUPERSEDES", "evidence": "test"} for a, b in supersedes]
    return co.load(json.dumps({"nodes": [PAY, *decisions], "edges": edges}))


def ids(items: list[dict]) -> list[str]:
    return [i["id"] for i in items]


def at(g, day: datetime.date = DAY) -> dict:
    return impact.run(g, [FILE], day=day)["impact"][0]


def checked(g, tmp_path: Path, day: datetime.date = DAY, **kw) -> dict:
    return check.run(g, [FILE], tmp_path, [], day=day, **kw)


def violators(report: dict) -> list[str]:
    return sorted({v["decision"] for v in report["violations"] if v["rule"] == "review_required"})


@pytest.mark.parametrize("value,want", [
    ("2026-11-26", datetime.date(2026, 11, 26)), ("2026-11", datetime.date(2026, 11, 1)), ("2026", datetime.date(2026, 1, 1)),
    ("  2026-11-26  ", datetime.date(2026, 11, 26)), ("2026-11-25T15:11:23.862Z", datetime.date(2026, 11, 25)),
    ("2026-11-25 15:11", datetime.date(2026, 11, 25)), ("2026-11-25T15:11:23+09:00", datetime.date(2026, 11, 25)),
    ("", None), ("   ", None), (None, None), (2026, None), ("soon", None), ("26-11-26", None), ("2026-13-01", None),
    ("2026-02-30", None), ("2026-11-26<script>", None), ("2026-11-26T10:00junk", None), ("٢٠٢٦-٠١-٠١", None),
], ids=repr)
def test_a_valid_until_is_read_as_the_first_day_it_names_and_anything_else_is_no_date(value, want):
    assert impact.until_of(value) == want


@pytest.mark.parametrize("today,closed", [("2026-11-25", False), ("2026-11-26", True), ("2026-11-27", True)])
def test_a_decision_is_closed_on_the_day_its_valid_until_names_and_after_it(today, closed):
    result = at(graph(decision(A, "2026-11-26"), decision(B)), datetime.date.fromisoformat(today))
    assert (ids(result.get("closed", [])), [i for i in ids(result["governing"]) if i.startswith("decision:")]) == (
        ([A], [B]) if closed else ([], [A, B]))


@pytest.mark.parametrize("name,node_a,written", [
    ("props", decision(A, "2026-11-01"), "2026-11-01"),
    ("the node's own field", decision(A, column="2026-11-01"), "2026-11-01"),
    ("both, the same", decision(A, "2026-11-01", "2026-11-01"), "2026-11-01"),
    ("both, the column earlier", decision(A, "2027-06-01", "2026-11-01"), "2026-11-01"),
    ("both, the props earlier", decision(A, "2026-11-01", "2027-06-01"), "2026-11-01"),
    ("a month", decision(A, "2026-11"), "2026-11"),
    ("a timestamp", decision(A, "2026-11-01T09:30:00Z"), "2026-11-01T09:30:00Z"),
])
def test_a_valid_until_in_the_column_or_in_props_closes_a_decision_and_the_earlier_of_two_wins(name, node_a, written):
    result = at(graph(node_a))
    assert ids(result["closed"]) == [A] and A not in ids(result["governing"]) and "superseded" not in result
    assert result["closed"][0]["valid_until"] == written


def test_a_closed_decision_is_listed_with_its_date_beside_what_still_governs():
    g = graph(decision(A, "2026-11-01"), decision(B, "2027-01-01"), decision(C))
    report = impact.run(g, [FILE], day=DAY)
    result = report["impact"][0]
    assert ids(result["closed"]) == [A] and [i["valid_until"] for i in result["closed"]] == ["2026-11-01"]
    assert result["closed"][0]["path"] == [{"source": A, "type": "ABOUT", "target": "concept:pay", "evidence": "test"}]
    assert [(i["id"], i.get("valid_until")) for i in result["governing"]] == [("concept:pay", None), (B, "2027-01-01"), (C, None)]
    assert report["today"] == TODAY and "superseded" not in result


def test_a_snapshot_with_no_valid_until_gives_the_output_it_gave_before(tmp_path):
    g = graph(decision(A), decision(B))
    report = impact.run(g, [FILE], day=DAY)
    assert "today" not in report and set(report["impact"][0]) == {"path", "matched_as", "governing"}
    assert all("valid_until" not in i for i in report["impact"][0]["governing"])
    assert "closed" not in checked(g, tmp_path)


def test_a_value_that_is_not_a_date_closes_nothing():
    g = graph(decision(A, "soon"), decision(B, ""), decision(C, "2026-13-45", column="never"))
    assert ids(at(g)["governing"]) == ["concept:pay", A, B, C] and "closed" not in at(g)


def test_only_a_decision_is_closed_by_a_valid_until():
    g = co.load(json.dumps({"nodes": [{**PAY, "valid_until": "2026-01-01"}, {"id": "record:r", "kind": "record", "title": "R",
                                                                            "valid_until": "2026-01-01", "props": {}}],
                            "edges": [{"source": "record:r", "target": "concept:pay", "type": "RELATED_TO", "evidence": "test"}]}))
    result = at(g)
    assert ids(result["governing"]) == ["concept:pay", "record:r"] and "closed" not in result


def test_a_decision_that_is_superseded_and_closed_is_listed_as_superseded(tmp_path):
    g = graph(decision(A, "2026-11-01"), decision(B), supersedes=((B, A),))
    result = at(g)
    assert ids(result["superseded"]) == [A] and result["superseded"][0]["superseded_by"] == [B] and "closed" not in result
    assert impact.closed_by(g, DAY) == {}
    assert "closed" not in checked(g, tmp_path) and violators(checked(g, tmp_path)) == [B]


def test_the_text_view_names_a_closed_decision_and_its_date(capsys, tmp_path):
    snap = tmp_path / "snap.json"
    snap.write_text(co.dump(graph(decision(A, "2026-11-01"), decision(B))), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["impact", str(snap), FILE, "--today", TODAY, "--format", "text"]) == 0
    out = capsys.readouterr().out
    assert f"{FILE}: 2 node(s) within 3 hop(s), and 1 closed decision(s)" in out
    assert "closed by valid_until, listed for the record:" in out
    assert "[1] decision decision:a  via concept:pay  valid_until 2026-11-01  (closed)" in out
    assert "decision:b" in out.split("closed by valid_until")[0]


# check

def test_check_does_not_judge_a_closed_decision_and_lists_it_with_its_date(tmp_path):
    g = graph(decision(A, "2026-11-01"), decision(B, "2026-11-26"), decision(C, "2026-11-27"))
    report = checked(g, tmp_path)
    assert report["closed"] == [{"decision": A, "title": "A", "files": [FILE], "valid_until": "2026-11-01"},
                                {"decision": B, "title": "B", "files": [FILE], "valid_until": "2026-11-26"}]
    assert [d["decision"] for d in report["governing"]] == [C] and report["governing"][0]["valid_until"] == "2026-11-27"
    assert violators(report) == [C] and [r["decision"] for r in report["rules"]] == [C]
    assert report["today"] == TODAY and report["summary"]["violated"] == 1
    assert check.failed(report, False)


def test_the_same_decision_is_judged_the_day_before_its_valid_until(tmp_path):
    g = graph(decision(A, "2026-11-01"))
    before = checked(g, tmp_path, datetime.date(2026, 10, 31))
    assert violators(before) == [A] and "closed" not in before and [d["decision"] for d in before["governing"]] == [A]
    after = checked(g, tmp_path, datetime.date(2026, 11, 1))
    assert violators(after) == [] and [c["decision"] for c in after["closed"]] == [A] and not check.failed(after, True)


def test_a_rule_problem_of_a_closed_decision_is_not_reported(tmp_path):
    broken = {**decision(A, "2026-11-01"), "props": {"valid_until": "2026-11-01", "rule": {"no_such_rule": 1}}}
    assert "rule_problems" in checked(graph(broken), tmp_path, datetime.date(2026, 10, 1))
    assert "rule_problems" not in checked(graph(broken), tmp_path)


def test_the_check_text_view_lists_the_closed_decisions(tmp_path):
    text = check.render(checked(graph(decision(A, "2026-11-01"), decision(B)), tmp_path))
    assert f"closed by valid_until (today is {TODAY}), not judged:\n  decision:a  valid_until 2026-11-01" in text
    assert "governing decisions: 1\n  decision:b" in text


def test_the_check_command_takes_today_and_closes_on_it(tmp_path, capsys):
    snap = tmp_path / "snap.json"
    snap.write_text(co.dump(graph(decision(A, "2026-11-01"))), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["check", str(snap), "--repo-dir", str(tmp_path), "--changed", FILE, "--today", "2026-10-31"]) == 1
    assert json.loads(capsys.readouterr().out)["summary"]["violated"] == 1
    assert cli.main(["check", str(snap), "--repo-dir", str(tmp_path), "--changed", FILE, "--today", "2026-11-01"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["violated"] == 0 and out["closed"][0]["valid_until"] == "2026-11-01"


# a SUPERSEDES cycle

def cycled(until_a: str | None = "2026-11-01", until_b: str | None = None):
    return graph(decision(A, until_a), decision(B, until_b), supersedes=((A, B), (B, A)))


def test_a_closed_decision_in_a_supersedes_cycle_stays_in_force_because_the_cycle_rule_wins(tmp_path):
    g = cycled()
    assert [c.members for c in cycles.find(g.nodes, g.edges)] == [(A, B)]
    result = at(g)
    assert ids(result["governing"]) == ["concept:pay", A, B] and "closed" not in result and "superseded" not in result
    assert impact.closed_by(g, DAY) == {} and impact.superseded_by(g) == {}
    report = checked(g, tmp_path)
    assert "closed" not in report and [d["decision"] for d in report["governing"]] == [A, B]
    assert violators(report) == [A, B]


def test_the_cycle_result_says_which_member_a_valid_until_would_have_closed(tmp_path):
    report = checked(cycled(), tmp_path)
    [result] = report["unresolved"]
    assert result["rule"] == cycles.RULE and result["decisions"] == [A, B]
    assert result["why"].endswith(". Fix the supersedes and superseded_by lines. decision:a (valid_until 2026-11-01) would be closed by its "
                                  "valid_until, but stays in force while the cycle holds")
    both = checked(cycled("2026-11-01", "2026-11-02"), tmp_path)["unresolved"][0]["why"]
    assert both.endswith("decision:a (valid_until 2026-11-01), decision:b (valid_until 2026-11-02) would be closed by their valid_until, "
                         "but stay in force while the cycle holds")
    assert "valid_until" not in checked(cycled(None), tmp_path)["unresolved"][0]["why"]
    before = checked(cycled(), tmp_path, datetime.date(2026, 10, 31))
    assert "valid_until" not in before["unresolved"][0]["why"]


def test_a_decision_closed_and_in_a_cycle_closes_once_the_cycle_is_fixed(tmp_path):
    assert checked(cycled(), tmp_path)["summary"]["violated"] == 2
    fixed = graph(decision(A, "2026-11-01"), decision(B))
    assert ids(at(fixed)["closed"]) == [A] and violators(checked(fixed, tmp_path)) == [B]


def test_a_decision_closed_outside_a_cycle_closes_while_the_cycle_holds_its_members(tmp_path):
    g = graph(decision(A), decision(B), decision(C, "2026-11-01"), supersedes=((A, B), (B, A)))
    result = at(g)
    assert ids(result["closed"]) == [C] and ids(result["governing"]) == ["concept:pay", A, B]
    assert violators(checked(g, tmp_path)) == [A, B]


# audit

def audit_init(snap: dict, day: datetime.date = DAY, repo: str = "Shop") -> dict:
    return audit.run(co.load(json.dumps(snap)), lock(), repo, advisories=advisories(), day=day)


def test_audit_does_not_judge_an_init_decision_that_its_valid_until_closed(no_network):
    snap = snapshot()
    node(snap, ADR_0010)["props"]["valid_until"] = "2026-11-01"
    open_ = audit_init(snap, datetime.date(2026, 10, 31))
    assert violated(open_) == SHIPPED and open_["violations"] == 3 and "not_governing" not in open_
    report = audit_init(snap)
    assert report["governing"] == [] and report["violations"] == 0 and violated(report) == set()
    assert report["not_governing"] == [{"decision": ADR_0010, "title": "No high advisories in shipped dependencies",
                                        "reason": "it is closed by its valid_until 2026-11-01, and a closed decision is not judged"}]
    assert report["meta"]["recorded_links"] == 0 and report["today"] == TODAY
    assert not any(e["type"] == audit.RECORDS for e in audit.recorded_links(co.load(json.dumps(snap)), "Shop", DAY))


def test_audit_reads_the_node_field_as_well_as_props(no_network):
    snap = snapshot()
    node(snap, ADR_0010)["valid_until"] = "2026-11-26"
    assert audit_init(snap)["violations"] == 0
    assert audit_init(snap, datetime.date(2026, 11, 25))["violations"] == 3


def test_a_decision_with_a_later_valid_until_or_none_still_governs_an_audit(no_network):
    snap = snapshot()
    node(snap, ADR_0010)["props"]["valid_until"] = "2026-11-27"
    report = audit_init(snap)
    assert violated(report) == SHIPPED and report["violations"] == 3 and "not_governing" not in report
    assert audit_init(snapshot())["violations"] == 3


def test_audit_does_not_judge_a_hand_written_decision_that_its_valid_until_closed(no_network):
    snap = hand()
    node(snap, RULE)["props"]["valid_until"] = "2026-11-01"
    open_ = audit.run(co.load(json.dumps(snap)), lock(), "Demo", advisories=advisories(), day=datetime.date(2026, 10, 31))
    report = audit.run(co.load(json.dumps(snap)), lock(), "Demo", advisories=advisories(), day=DAY)
    assert [g["decision"] for g in report["governing"]] == [PINNED] and report["violations"] == 0
    assert open_["violations"] > 0 and RULE in {g["decision"] for g in open_["governing"]}
    [idle] = report["not_governing"]
    assert idle["decision"] == RULE and idle["reason"] == "it is closed by its valid_until 2026-11-01, and a closed decision is not judged"


def test_audit_keeps_a_closed_decision_in_a_supersedes_cycle_in_force(no_network):
    snap = snapshot()
    node(snap, ADR_0010)["props"]["valid_until"] = "2026-11-01"
    other = "decision:shop-docs-decisions-0099-other"
    snap["nodes"].append({"id": other, "kind": "decision", "title": "Other", "props": {"rule": {"review_required": {"paths": ["src/**"], "reviewers": ["@x"]}}}})
    snap["edges"] += [{"source": ADR_0010, "target": other, "type": "SUPERSEDES", "evidence": "test"},
                      {"source": other, "target": ADR_0010, "type": "SUPERSEDES", "evidence": "test"}]
    snap["meta"].update(nodes=len(snap["nodes"]), edges=len(snap["edges"]))
    report = audit_init(snap)
    assert violated(report) == SHIPPED and report["violations"] == 3 and "not_governing" not in report


def test_the_audit_command_takes_today(tmp_path, capsys, no_network):
    snap = tmp_path / "snap.json"
    shipped = snapshot()
    node(shipped, ADR_0010)["props"]["valid_until"] = "2026-11-01"
    snap.write_text(json.dumps(shipped), encoding="utf-8")
    args = ["audit", str(snap), str(ROOT / "fixtures" / "audit" / "demo-lockfile.json"), "--repo", "Shop",
            "--osv-cache", str(ROOT / "fixtures" / "audit" / "osv-cache.json")]
    capsys.readouterr()
    assert cli.main([*args, "--today", "2026-10-31"]) == 0
    assert json.loads(capsys.readouterr().out)["violations"] == 3
    assert cli.main([*args, "--today", "2026-11-01"]) == 0
    assert json.loads(capsys.readouterr().out)["violations"] == 0


# propose

def closed(snap: dict, old: str) -> dict:
    node(snap, old)["props"]["valid_until"] = "2020-01-01"
    return snap


@pytest.mark.parametrize("decision", [RULE, PINNED], ids=["violated", "relevant"])
def test_a_record_citing_a_closed_decision_is_held(tmp_path, capsys, no_network, decision):
    report = hand_report()
    code, base, _ = propose(tmp_path, capsys, report, hand(), "Demo")
    assert code == 0 and base["held"] == []
    reason = "it is closed by its valid_until 2020-01-01, and a closed decision is not judged"
    assert_held_for(tmp_path, capsys, report, closed(hand(), decision), "Demo", decision, reason, base)


def test_propose_judges_on_the_date_of_the_audit_report_and_not_on_the_day_it_runs(tmp_path, capsys, no_network):
    snap = closed(hand(), RULE)
    for today, held_records in (("2019-12-31", False), ("2020-01-01", True)):
        report = {**hand_report(), "today": today}
        code, plan, _ = propose(tmp_path, capsys, report, snap, "Demo")
        assert (code, bool(plan["held"])) == ((1, True) if held_records else (0, False))


# the other views

def test_the_html_and_mermaid_views_set_a_closed_decision_apart(tmp_path, capsys):
    snap = tmp_path / "snap.json"
    snap.write_text(co.dump(graph(decision(A, "2026-11-01"), decision(B))), encoding="utf-8")
    capsys.readouterr()
    cli.main(["impact", str(snap), FILE, "--today", TODAY, "--format", "html"])
    page = capsys.readouterr().out
    assert "<h3>Closed by valid_until, listed for the record</h3>" in page and "<span class=\"badge\">closed</span>" in page
    cli.main(["impact", str(snap), FILE, "--today", TODAY, "--format", "mermaid"])
    assert "closed 2026-11-01" in capsys.readouterr().out
    cli.main(["check", str(snap), "--repo-dir", str(tmp_path), "--changed", FILE, "--today", TODAY, "--format", "html"])
    assert "<h2>Closed by valid_until, not judged</h2><p>Judged on 2026-11-26.</p>" in capsys.readouterr().out
    cli.main(["impact", str(snap), FILE, "--today", "2026-10-31", "--format", "html"])
    assert "Closed by valid_until" not in capsys.readouterr().out


def test_the_action_comment_names_the_closed_decisions(tmp_path):
    report = checked(graph(decision(A, "2026-11-01"), decision(B)), tmp_path)
    lines = action.decisions(report, 10)
    named = f"Closed by valid_until, not judged (today is {action.text(TODAY)}): {action.code(A)} ({action.code('2026-11-01')})"
    assert named in lines
    assert not any("Closed by" in line for line in action.decisions(checked(graph(decision(B)), tmp_path), 10))


def test_the_summary_view_of_an_agent_counts_the_closed_decisions(tmp_path):
    g = graph(decision(A, "2026-11-01"), decision(B))
    short = compact.impact(impact.run(g, [FILE], day=DAY))
    assert short["today"] == TODAY and short["impact"][0]["closed_count"] == 1
    assert short["impact"][0]["closed"] == [{"id": A, "title": "A", "valid_until": "2026-11-01"}]
    assert compact.check(checked(g, tmp_path))["closed"] == [{"decision": A, "valid_until": "2026-11-01"}]
    assert "closed" not in compact.check(checked(graph(decision(B)), tmp_path))


def test_the_mcp_tools_take_today(tmp_path):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    path = tmp_path / "snap.json"
    path.write_text(co.dump(graph(decision(A, "2026-11-01"), decision(B))), encoding="utf-8")
    tools = serve.load_tools(path, tmp_path)
    full = tools.call("impact", {"code_paths": [FILE], "today": TODAY, "detail": "full"})
    assert ids(full["impact"][0]["closed"]) == [A]
    earlier = tools.call("impact", {"code_paths": [FILE], "today": "2026-10-31", "detail": "full"})
    assert ids(earlier["impact"][0]["governing"])[1:] == [A, B] and "closed" not in earlier["impact"][0]
    assert tools.call("impact", {"code_paths": [FILE], "today": TODAY})["impact"][0]["closed_count"] == 1
    for bad in ("2026-02-30", "yesterday"):
        with pytest.raises(serve.Refused):
            tools.call("impact", {"code_paths": [FILE], "today": bad})
