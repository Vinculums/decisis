from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_audit import advisories, lock, no_network
from test_audit_init import ADR_0010, CACHE, LOCK, audited, node, snapshot
from decisis import audit, checker, cli
from decisis import checkout as co
from decisis import commit as wb

HAND = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "vinc.json"
RULE = "decision:no-high-advisories-in-shipped-dependencies"
PINNED = "decision:dependencies-are-pinned-by-a-lockfile"
NEWER = "decision:newer-policy"
NEWER_INIT = "decision:shop-docs-decisions-0011-card-numbers-never-reach-logs"
SUPERSEDED = "it is superseded by {}, and a superseded decision is not judged"
UNLINKED = ("nothing links it to repo:Demo: the snapshot does not come from decisis init, and no edge runs "
            "repo:Demo -DESCRIBED_BY-> a node it is ABOUT")
OTHER = "decisis init read it from the repository Other, and this audit is of Shop"
NO_RULE = "decisis init links only a decision whose rule holds a kind audit judges, and this one has none"


def hand() -> dict:
    return json.loads(HAND.read_text(encoding="utf-8"))


def load(snap: dict):
    return co.load(json.dumps(snap))


def replaced(snap: dict, old: str, newer: str = NEWER) -> dict:
    if not any(n["id"] == newer for n in snap["nodes"]):
        snap["nodes"].append({"id": newer, "kind": "decision", "title": "Newer policy", "props": {}})
    snap["edges"].append({"source": newer, "target": old, "type": "SUPERSEDES", "evidence": "test"})
    if "edges" in snap["meta"]:
        snap["meta"]["edges"] += 1
    return snap


def retired(snap: dict, old: str) -> dict:
    node(snap, old)["props"]["status"] = "superseded"
    return snap


def unlinked(snap: dict, old: str) -> dict:
    snap["edges"] = [e for e in snap["edges"] if not (e["source"] == old and e["type"] == "ABOUT")]
    return snap


def other_repository(snap: dict) -> dict:
    snap["meta"]["repo"] = "Other"
    return snap


def without_audit_rule(snap: dict) -> dict:
    node(snap, ADR_0010)["props"]["rule"] = {"review_required": {"paths": ["src/**"], "reviewers": ["@shop/team"]}}
    return snap


def hand_report() -> dict:
    return audit.run(load(hand()), lock(), "Demo", advisories=advisories())


def propose(tmp_path: Path, capsys, report: dict, snap: dict, repo: str) -> tuple[int, dict, str]:
    for name, body in (("report", report), ("snapshot", snap)):
        (tmp_path / f"{name}.json").write_text(json.dumps(body), encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["propose", str(tmp_path / "report.json"), str(tmp_path / "snapshot.json"), str(LOCK), "--repo", repo,
                     "--space", "demo-space", "--osv-cache", str(CACHE), "--out", str(tmp_path / "plan.json")])
    return code, json.loads((tmp_path / "plan.json").read_text(encoding="utf-8")), capsys.readouterr().out


def held(plan: dict) -> dict[str, list[str]]:
    return {h["record"]: h["failed"] for h in plan["held"]}


def citing(plan: dict, decision: str) -> set[str]:
    return {e["from"] for e in plan["edges"] if e["to"] == decision}


def assert_held_for(tmp_path, capsys, report: dict, snap: dict, repo: str, decision: str, reason: str, base: dict) -> None:
    code, plan, out = propose(tmp_path, capsys, report, snap, repo)
    wanted = citing(base, decision)
    message = f"{decision} does not govern repo:{repo}: {reason}"
    assert wanted and code == 1
    assert held(plan) == {rid: [message] for rid in sorted(wanted)}
    assert {n["id"] for n in plan["nodes"]} == {n["id"] for n in base["nodes"]} - wanted
    assert all(e["from"] not in wanted for e in plan["edges"]) and plan["digest"] == wb.digest(plan)
    assert f" {len(wanted)} failed." in out and all(f"{rid}: {message}" in out for rid in wanted)


HAND_CASES = {
    "superseded by an edge": (lambda s, d: replaced(s, d), SUPERSEDED.format(NEWER)),
    "superseded by its status": (retired, SUPERSEDED.format("a later decision")),
    "the link removed": (unlinked, UNLINKED),
}


@pytest.mark.parametrize("decision", [RULE, PINNED], ids=["violated", "relevant"])
@pytest.mark.parametrize("name", sorted(HAND_CASES))
def test_a_record_of_a_hand_written_snapshot_is_held_when_its_decision_no_longer_governs(tmp_path, capsys, no_network, name, decision):
    change, reason = HAND_CASES[name]
    report = hand_report()
    code, base, _ = propose(tmp_path, capsys, report, hand(), "Demo")
    assert code == 0 and base["held"] == [] and len(base["nodes"]) == 7
    assert_held_for(tmp_path, capsys, report, change(hand(), decision), "Demo", decision, reason, base)


INIT_CASES = {
    "superseded": (lambda s: replaced(s, ADR_0010, NEWER_INIT), SUPERSEDED.format(NEWER_INIT)),
    "another repository": (other_repository, OTHER),
    "no rule audit judges": (without_audit_rule, NO_RULE),
}


@pytest.mark.parametrize("name", sorted(INIT_CASES))
def test_a_record_of_an_init_snapshot_is_held_when_its_decision_no_longer_governs(tmp_path, capsys, no_network, name):
    change, reason = INIT_CASES[name]
    report = audited(snapshot())
    code, base, _ = propose(tmp_path, capsys, report, snapshot(), "Shop")
    assert code == 0 and base["held"] == [] and citing(base, ADR_0010)
    assert_held_for(tmp_path, capsys, report, change(snapshot()), "Shop", ADR_0010, reason, base)


def own_plan(report: dict) -> tuple[dict, dict]:
    plan = wb.propose(report, "Demo", "demo-space")
    record = next(n for n in plan["nodes"] if RULE in n["props"]["violates"])
    return plan, record


def cite(plan: dict, record: dict, field: str, edge: bool) -> None:
    record["props"]["violates"] = [d for d in record["props"]["violates"] if d != RULE]
    record["props"].pop("waived", None)
    record["props"][field] = [*record["props"].get(field, []), RULE]
    if not edge:
        plan["edges"] = [e for e in plan["edges"] if not (e["from"] == record["id"] and e["to"] == RULE)]


def problems_of(checked: list[dict], rid: str) -> list[str]:
    return next(c["problems"] for c in checked if c["record"] == rid)


@pytest.mark.parametrize("edge", [True, False], ids=["with-edge", "without-edge"])
@pytest.mark.parametrize("field", ["violates", "waived"])
def test_a_decision_named_under_violates_or_waived_must_govern_even_when_the_record_has_no_edge_to_it(field, edge, no_network):
    plan, record = own_plan(hand_report())
    cite(plan, record, field, edge)
    _, checked = checker.rederive(plan, load(hand()), lock(), "Demo", advisories())
    assert problems_of(checked, record["id"]) == []
    _, checked = checker.rederive(plan, load(replaced(hand(), RULE)), lock(), "Demo", advisories())
    assert problems_of(checked, record["id"]) == [f"{RULE} does not govern repo:Demo: {SUPERSEDED.format(NEWER)}"]
    _, checked = checker.rederive(plan, load(unlinked(hand(), RULE)), lock(), "Demo", advisories())
    assert problems_of(checked, record["id"]) == [f"{RULE} does not govern repo:Demo: {UNLINKED}"]


def test_a_decision_the_snapshot_does_not_hold_is_named_once_whether_it_is_cited_by_an_edge_or_a_field(no_network):
    plan, record = own_plan(hand_report())
    record["props"]["violates"] = [*record["props"]["violates"], "decision:ghost"]
    plan["edges"].append({"from": record["id"], "to": "decision:ghost", "type": "relates_to", "evidence": "violated: made up"})
    _, checked = checker.rederive(plan, load(hand()), lock(), "Demo", advisories())
    assert problems_of(checked, record["id"]) == ["decision:ghost is not a decision in the snapshot"]
    plan["edges"].pop()
    _, checked = checker.rederive(plan, load(hand()), lock(), "Demo", advisories())
    assert problems_of(checked, record["id"]) == ["decision:ghost is not a decision in the snapshot"]


def test_the_demo_counts_of_checks_do_not_grow_with_the_governing_check(tmp_path, capsys, no_network):
    code, plan, out = propose(tmp_path, capsys, hand_report(), hand(), "Demo")
    assert code == 0 and "Re-derived 7 records with 31 checks; 0 failed." in out


def test_the_audit_does_not_judge_a_superseded_decision_of_a_hand_written_snapshot_and_says_why():
    before = hand_report()
    assert RULE in {g["decision"] for g in before["governing"]} and before["violations"] == 3 and "not_governing" not in before
    report = audit.run(load(replaced(hand(), RULE)), lock(), "Demo", advisories=advisories())
    assert RULE not in {g["decision"] for g in report["governing"]} and report["violations"] == 0
    assert report["not_governing"] == [{"decision": RULE, "title": "No high advisories in shipped dependencies",
                                        "reason": SUPERSEDED.format(NEWER)}]


AGREEMENT = {
    "hand-written, unchanged": (hand, lambda s: s, "Demo", {RULE, PINNED}),
    "hand-written, superseded": (hand, lambda s: replaced(s, RULE), "Demo", {PINNED}),
    "hand-written, status superseded": (hand, lambda s: retired(s, PINNED), "Demo", {RULE}),
    "hand-written, link removed": (hand, lambda s: unlinked(s, RULE), "Demo", {PINNED}),
    "init, unchanged": (snapshot, lambda s: s, "Shop", {ADR_0010}),
    "init, superseded": (snapshot, lambda s: replaced(s, ADR_0010, NEWER_INIT), "Shop", set()),
    "init, another repository": (snapshot, other_repository, "Shop", set()),
    "init, no rule audit judges": (snapshot, without_audit_rule, "Shop", set()),
}


@pytest.mark.parametrize("name", sorted(AGREEMENT))
def test_the_checker_turns_away_exactly_the_decisions_the_audit_does_not_judge(name, no_network):
    make, change, repo, expected = AGREEMENT[name]
    snap = change(make())
    judged = {g["decision"] for g in audit.run(load(snap), lock(), repo, advisories=advisories())["governing"]}
    plan = wb.propose(audit.run(load(make()), lock(), repo, advisories=advisories()), repo, "demo-space")
    first = plan["nodes"][0]
    every = sorted(n["id"] for n in snap["nodes"] if n["kind"] == "decision")
    plan["edges"] = [{"from": first["id"], "to": d, "type": "relates_to", "evidence": "test"} for d in every]
    _, checked = checker.rederive(plan, load(snap), lock(), repo, advisories())
    turned = {p.split(" does not govern ")[0] for p in problems_of(checked, first["id"]) if " does not govern " in p}
    assert judged == expected and turned == set(every) - judged
