from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_action import HOSTILE, HOSTILE_PATH, FakeGitHub, hostile_outcome, outputs
from test_audit import no_network
from test_base_decisions import env_for, repository, summary
from test_supersedes_cycle import FILE, adr, did, link, path, tree
from decisis import action, check, committed, cycles, init, signature
from decisis import checkout as co

HEADING = "#### Decision changes that take effect once merged"
NOTHING_CHANGED = "No decision or waiver is added, changed or removed."
ARRIVING = "once this pull request is merged"
RING = [adr(1, f"superseded_by: {link(2)}"), adr(2)]
CLOSED = [adr(2, f"superseded_by: {link(1)}")]
BOTH = [adr(1, f"superseded_by: {link(2)}"), adr(2, f"superseded_by: {link(1)}")]


def run(tmp_path: Path, base: list[tuple[str, str]], head: list[tuple[str, str | None]], strict: bool = False,
        approved: tuple[str, ...] = (), **extra) -> tuple[int, str]:
    root, sha = repository(tmp_path, {**dict(base), FILE: "A = 1\n"}, {FILE: "A = 2\n", **dict(head)})
    flags = {"DECISIS_FAIL_ON_UNRESOLVED": "true"} if strict else {}
    env = env_for(tmp_path, root, sha, DECISIS_REPO="Shop", GITHUB_WORKSPACE=str(root), **flags, **extra)
    reviews = [{"user": {"login": who}, "state": "APPROVED"} for who in approved]
    return action.main(env, FakeGitHub(reviews=reviews)), summary(tmp_path)


def section(body: str) -> str:
    start = body.index(HEADING)
    end = body.find("\n#### ", start + len(HEADING))
    return body[start:end if end != -1 else len(body)]


def edge_row(source: int, target: int, change: str) -> str:
    return f"| {action.code(did(source))} | {action.code(did(target))} | {change} |"


def cycle_row(change: str, *members: int) -> str:
    return (f"| {change} | {', '.join(action.code(did(n)) for n in members)} | "
            f"{', '.join(action.code(path(n)) for n in members)} |")


def node(nid: str, kind: str = "decision", **props) -> dict:
    return {"id": nid, "kind": kind, "title": nid, "props": props}


def edge(source: str, target: str) -> dict:
    return {"source": source, "target": target, "type": "SUPERSEDES"}


def graph(nodes: list[dict], edges: list[dict]):
    return co.load(json.dumps({"meta": {}, "nodes": nodes, "edges": edges}))


@pytest.mark.parametrize("strict", [False, True])
def test_a_pull_request_that_closes_a_supersedes_cycle_names_the_edge_the_decision_that_returns_and_the_cycle(strict, tmp_path, no_network):
    code, out = run(tmp_path, RING, CLOSED, strict)
    block = section(out)
    assert code == (1 if strict else 0)
    assert NOTHING_CHANGED not in out
    assert "`SUPERSEDES` edges this pull request adds or removes (1):" in block
    assert edge_row(1, 2, "added") in block
    assert "Decisions that return to force once merged (1)" in block
    assert f"- {action.code(did(1))}: superseded by {action.code(did(2))} now" in block
    assert "Decisions that become superseded" not in block
    assert "`SUPERSEDES` cycles this pull request adds or removes (1):" in block
    assert cycle_row("added", 1, 2) in block
    assert 'This run lists each added cycle under "Cannot be judged".' in block
    assert "#### Cannot be judged (1)" in out and "#### Violations (1)" in out
    assert action.text(f"{did(1)} and {did(2)} supersede each other ({path(1)}, {path(2)}) {ARRIVING}; neither is treated as superseded") in out
    assert outputs(tmp_path)["unresolved"] == "1" and outputs(tmp_path)["violations"] == "1"
    assert ("This check fails: fail-on-unresolved is on and the run found 1 check result(s) that cannot be judged." in out) is strict


def test_the_reported_scenario_gives_the_exact_section_and_fails_with_fail_on_unresolved(tmp_path, no_network):
    code, out = run(tmp_path, RING, CLOSED, True)
    one, two = action.code(did(1)), action.code(did(2))
    assert code == 1
    assert section(out) == "\n".join([
        f"{HEADING} (1)",
        "",
        "This pull request changes files the decisions come from. This run read the decisions from the base commit, so these changes "
        "take effect once the pull request is merged and change no verdict here.",
        "",
        f"- {action.code(path(2))}",
        "",
        "`SUPERSEDES` edges this pull request adds or removes (1):",
        "",
        "| Decision | Supersedes | Change |",
        "|---|---|---|",
        f"| {one} | {two} | added |",
        "",
        "Decisions that return to force once merged (1), so their rules are judged again:",
        "",
        f"- {one}: superseded by {two} now",
        "",
        "`SUPERSEDES` cycles this pull request adds or removes (1):",
        "",
        "| Change | Decisions | Files |",
        "|---|---|---|",
        f"| added | {one}, {two} | {action.code(path(1))}, {action.code(path(2))} |",
        "",
        'No decision in an added cycle is treated as superseded once merged, so their rules are judged. '
        'This run lists each added cycle under "Cannot be judged".',
        "",
    ])


def test_the_added_cycle_is_one_result_that_cannot_be_judged_in_the_report_the_signature_covers(tmp_path, monkeypatch, no_network):
    seen = []
    real = action.publish
    monkeypatch.setattr(action, "publish", lambda env, client, outcome: (seen.append(outcome), real(env, client, outcome))[1])
    code, out = run(tmp_path, RING, CLOSED, True, DECISIS_SARIF="true")
    [outcome] = seen
    [found] = outcome.report["unresolved"]
    assert code == 1 and outcome.report["summary"]["unresolved"] == 1
    assert found["rule"] == cycles.RULE and found["verdict"] == "unresolved" and found["line"] is None
    assert found["decisions"] == [did(1), did(2)] and found["files"] == [path(1), path(2)]
    assert found["file"] == path(1) and found["decision"] == did(1) and ARRIVING in found["why"]
    digest = signature.digest(action.result_reports(outcome))
    bare = {**outcome.report, "unresolved": []}
    assert f"digest: {action.code(digest)}" in out
    assert digest != signature.digest([bare])
    log = json.loads(Path(outputs(tmp_path)["sarif-file"]).read_text())
    [result] = [r for r in log["runs"][0]["results"] if r["ruleId"] == cycles.RULE]
    assert result["level"] == "warning" and result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == path(1)


def test_head_mode_keeps_judging_the_cycle_from_the_checkout_and_names_no_pending_change(tmp_path, no_network):
    code, out = run(tmp_path, RING, CLOSED, True, DECISIS_DECISIONS_FROM="head")
    assert code == 1
    assert "take effect once merged" not in out and ARRIVING not in out
    assert "#### Cannot be judged (1)" in out and "#### Violations (2)" in out
    assert action.text(f"{did(1)} and {did(2)} supersede each other ({path(1)}, {path(2)}); neither is treated as superseded") in out
    assert outputs(tmp_path)["unresolved"] == "1"


def test_a_pull_request_that_removes_a_cycle_names_the_removed_edge_and_cycle_and_the_decision_that_becomes_superseded(tmp_path, no_network):
    code, out = run(tmp_path, BOTH, [adr(2)])
    block = section(out)
    assert code == 0
    assert NOTHING_CHANGED not in out
    assert "`SUPERSEDES` edges this pull request adds or removes (1):" in block
    assert edge_row(1, 2, "removed") in block
    assert "Decisions that become superseded once merged (1):" in block
    assert f"- {action.code(did(1))}: superseded by {action.code(did(2))}" in block
    assert "return to force" not in block
    assert "`SUPERSEDES` cycles this pull request adds or removes (1):" in block
    assert cycle_row("removed once merged", 1, 2) in block
    assert "added cycle" not in block
    assert 'A cycle removed once merged is not listed under "Cannot be judged" in this run' in block
    assert action.text(f"{did(1)} and {did(2)} supersede each other") not in out
    assert ARRIVING not in out and "Cannot be judged" not in out.replace(block, "")
    assert outputs(tmp_path)["unresolved"] == "0"


@pytest.mark.parametrize("strict", [False, True])
def test_the_pull_request_that_removes_a_base_cycle_passes_fail_on_unresolved_when_its_rules_pass(strict, tmp_path, no_network):
    code, out = run(tmp_path, BOTH, [adr(2)], strict, approved=("alice", "bob"), DECISIS_FAIL_ON_VIOLATION="true")
    assert code == 0
    assert "#### Violations" not in out and "Cannot be judged" not in out.replace(section(out), "")
    assert cycle_row("removed once merged", 1, 2) in section(out)
    assert outputs(tmp_path)["unresolved"] == "0" and outputs(tmp_path)["violations"] == "0"
    assert "This check fails" not in out


@pytest.mark.parametrize("approved, missing", [(("alice",), 1), ((), 2)])
def test_the_pull_request_that_removes_a_base_cycle_still_gets_the_rule_violations_when_reviewers_are_missing(approved, missing, tmp_path, no_network):
    code, out = run(tmp_path, BOTH, [adr(2)], True, approved=approved, DECISIS_FAIL_ON_VIOLATION="true")
    assert code == 1
    assert f"#### Violations ({missing})" in out and f"| {action.code(did(2))} | {action.code('review_required')} |" in out
    assert (f"| {action.code(did(1))} | {action.code('review_required')} |" in out) is (missing == 2)
    assert "Cannot be judged" not in out.replace(section(out), "")
    assert outputs(tmp_path)["violations"] == str(missing) and outputs(tmp_path)["unresolved"] == "0"


@pytest.mark.parametrize("strict", [False, True])
def test_a_pull_request_that_adds_a_supersession_without_a_cycle_names_the_edge_and_the_decision_that_becomes_superseded(strict, tmp_path, no_network):
    code, out = run(tmp_path, [adr(1), adr(2)], [adr(2, f"supersedes: {link(1)}")], strict)
    block = section(out)
    assert code == 0
    assert NOTHING_CHANGED not in out
    assert edge_row(2, 1, "added") in block
    assert "Decisions that become superseded once merged (1):" in block
    assert f"- {action.code(did(1))}: superseded by {action.code(did(2))}" in block
    assert "return to force" not in block and "cycle" not in block
    assert "Cannot be judged" not in out and outputs(tmp_path)["unresolved"] == "0"


def test_a_pull_request_that_removes_a_supersession_without_a_cycle_names_the_edge_and_the_decision_that_returns(tmp_path, no_network):
    code, out = run(tmp_path, RING, [adr(1)], True)
    block = section(out)
    assert code == 0
    assert edge_row(2, 1, "removed") in block
    assert f"- {action.code(did(1))}: superseded by {action.code(did(2))} now" in block
    assert "become superseded" not in block and "cycle" not in block and NOTHING_CHANGED not in out
    assert "Cannot be judged" not in out


def test_a_status_that_turns_to_superseded_names_the_decision_without_an_edge(tmp_path, no_network):
    code, out = run(tmp_path, [adr(1, "status: accepted"), adr(2)], [adr(1, "status: superseded")])
    block = section(out)
    assert code == 0
    assert f"| {action.code(did(1))} |  | changed |" in block
    assert f"- {action.code(did(1))}: its status says it is superseded" in block
    assert "`SUPERSEDES` edges" not in block and "cycle" not in block


def test_the_sentence_that_nothing_changed_appears_only_when_nothing_in_the_section_applies(tmp_path, no_network):
    code, out = run(tmp_path, [adr(1), adr(2)], [(path(2), adr(2)[1] + "\nA note.\n")], True)
    block = section(out)
    assert code == 0
    assert block.rstrip().endswith(NOTHING_CHANGED)
    assert "`SUPERSEDES`" not in block and "return to force" not in block and "become superseded" not in block


def test_a_cycle_the_base_already_has_is_listed_once_as_before_and_not_as_a_change(tmp_path, no_network):
    code, out = run(tmp_path, [*BOTH, adr(3)], [adr(3, "status: accepted")], True)
    block = section(out)
    assert code == 1
    assert f"| {action.code(did(3))} |  | changed |" in block
    assert "`SUPERSEDES`" not in block and ARRIVING not in out
    assert "#### Cannot be judged (1)" in out and outputs(tmp_path)["unresolved"] == "1"


@pytest.mark.parametrize("approved", [(), ("alice", "bob")])
def test_a_pull_request_that_leaves_the_base_cycle_in_place_still_fails_under_fail_on_unresolved(approved, tmp_path, no_network):
    code, out = run(tmp_path, BOTH, [adr(1, f"superseded_by: {link(2)}", "status: accepted")], True, approved=approved)
    block = section(out)
    assert code == 1
    assert f"| {action.code(did(1))} |  | changed |" in block
    assert "`SUPERSEDES`" not in block and "removed once merged" not in out and ARRIVING not in out
    assert "#### Cannot be judged (1)" in out
    assert action.text(f"{did(1)} and {did(2)} supersede each other ({path(1)}, {path(2)}); neither is treated as superseded") in out
    assert outputs(tmp_path)["unresolved"] == "1"
    assert "This check fails: fail-on-unresolved is on and the run found 1 check result(s) that cannot be judged." in out


def test_a_cycle_that_grows_stays_a_result_that_cannot_be_judged_next_to_the_one_it_becomes(tmp_path, no_network):
    grown = [adr(2, f"superseded_by: {link(1)}", f"supersedes: {link(3)}"), adr(3, f"supersedes: {link(1)}")]
    code, out = run(tmp_path, [*BOTH, adr(3)], grown, True, approved=("alice", "bob", "carol"))
    block = section(out)
    assert code == 1
    assert cycle_row("added", 1, 2, 3) in block and "removed once merged" not in out
    assert "#### Cannot be judged (2)" in out and outputs(tmp_path)["unresolved"] == "2"
    assert action.text(f"{did(1)} and {did(2)} supersede each other ({path(1)}, {path(2)}); neither is treated as superseded") in out
    assert action.text(f"{did(1)}, {did(2)} and {did(3)} supersede one another in a cycle") in out and ARRIVING in out


RING3 = [adr(1, f"supersedes: {link(2)}"), adr(2, f"supersedes: {link(3)}"), adr(3, f"supersedes: {link(1)}")]
EVERYONE = ("alice", "bob", "carol")


def test_a_pull_request_that_breaks_a_ring_removes_it_once_merged_and_passes_when_its_rules_pass(tmp_path, no_network):
    code, out = run(tmp_path, RING3, [adr(3)], True, approved=EVERYONE)
    block = section(out)
    assert code == 0
    assert cycle_row("removed once merged", 1, 2, 3) in block and "added cycle" not in block
    assert "Cannot be judged" not in out.replace(block, "") and outputs(tmp_path)["unresolved"] == "0"


def test_a_pull_request_that_shrinks_a_ring_to_a_smaller_cycle_removes_the_old_one_and_adds_the_one_that_is_left(tmp_path, no_network):
    left = [adr(1, f"supersedes: {link(2)}"), adr(2, f"supersedes: {link(1)}"), adr(3)]
    code, out = run(tmp_path, RING3, left, True, approved=EVERYONE)
    block = section(out)
    assert code == 1
    assert cycle_row("added", 1, 2) in block and cycle_row("removed once merged", 1, 2, 3) in block
    assert "#### Cannot be judged (1)" in out and ARRIVING in out and outputs(tmp_path)["unresolved"] == "1"
    assert action.text(f"{did(1)}, {did(2)} and {did(3)} supersede one another in a cycle") not in out


@pytest.mark.parametrize("strict", [False, True])
def test_a_pull_request_that_adds_the_first_decisions_as_a_cycle_names_it_and_fails_with_fail_on_unresolved(strict, tmp_path, no_network):
    code, out = run(tmp_path, [], BOTH, strict, DECISIS_SARIF="true")
    block = section(out)
    assert code == (1 if strict else 0)
    assert "No decisions exist on the base commit" in out
    assert cycle_row("added", 1, 2) in block and edge_row(2, 1, "added") in block and edge_row(1, 2, "added") in block
    assert "#### Cannot be judged (1)" in out and ARRIVING in out
    assert outputs(tmp_path)["unresolved"] == "1" and outputs(tmp_path)["violations"] == "0"
    assert ("This check fails: fail-on-unresolved is on and the run found 1 check result(s) that cannot be judged." in out) is strict
    log = json.loads(Path(outputs(tmp_path)["sarif-file"]).read_text())
    assert [r["ruleId"] for r in log["runs"][0]["results"]] == [cycles.RULE]


def test_the_first_decisions_without_a_cycle_still_judge_nothing_and_do_not_fail(tmp_path, no_network):
    code, out = run(tmp_path, [], [adr(1), adr(2, f"supersedes: {link(1)}")], True)
    assert code == 0
    assert "No decisions exist on the base commit" in out and "Cannot be judged" not in out and "cycle" not in section(out)
    assert outputs(tmp_path)["unresolved"] == "0"


def test_supersession_names_edges_and_the_states_they_change_between_two_snapshots():
    a, b, c = "decision:a", "decision:b", "decision:c"
    old = graph([node(a), node(b), node(c)], [edge(b, a)])
    new = graph([node(a), node(b), node(c)], [edge(c, a), edge(c, b)])
    moved = committed.supersession(old, new)
    assert list(moved.edges) == [{"source": b, "target": a, "change": "removed"}, {"source": c, "target": a, "change": "added"},
                                 {"source": c, "target": b, "change": "added"}]
    assert list(moved.superseded) == [{"decision": b, "by": [c]}]
    assert list(moved.restored) == [] and moved.added == () and moved.removed == ()
    assert bool(moved) and not committed.supersession(old, old)


def test_a_cycle_that_grows_is_one_added_cycle_and_not_a_removed_one_and_a_ring_that_shrinks_or_loses_a_decision_is_removed():
    a, b, c = "decision:a", "decision:b", "decision:c"
    two = graph([node(a), node(b), node(c)], [edge(a, b), edge(b, a)])
    ring = graph([node(a), node(b), node(c)], [edge(a, b), edge(b, c), edge(c, a)])
    moved = committed.supersession(two, ring)
    assert [x.members for x in moved.added] == [(a, b, c)] and moved.removed == ()
    shrunk = committed.supersession(ring, two)
    assert [x.members for x in shrunk.added] == [(a, b)] and [x.members for x in shrunk.removed] == [(a, b, c)]
    gone = committed.supersession(two, graph([node(a), node(c)], []))
    assert gone.added == () and [x.members for x in gone.removed] == [(a, b)]
    twin = graph([node(a), node(b), node(c)], [edge(a, b), edge(b, a), edge(c, c)])
    assert [x.members for x in committed.supersession(two, twin).added] == [(c,)] and committed.supersession(two, twin).removed == ()
    alone = committed.supersession(graph([node(a)], []), graph([node(a)], [edge(a, a)]))
    assert [x.members for x in alone.added] == [(a,)] and alone.removed == ()
    assert list(alone.edges) == [{"source": a, "target": a, "change": "added"}]
    assert list(alone.superseded) == [] and list(alone.restored) == []


def test_edges_between_nodes_that_are_not_decisions_are_not_named_and_decisions_that_leave_or_arrive_are_not_states():
    a, b, x, y = "decision:a", "decision:b", "concept:x", "concept:y"
    old = graph([node(a), node(b), node(x, "concept"), node(y, "concept")], [edge(b, a), edge(x, y)])
    new = graph([node(a), node(x, "concept"), node(y, "concept"), node("decision:d", status="superseded")], [edge(y, x)])
    moved = committed.supersession(old, new)
    assert list(moved.edges) == [{"source": b, "target": a, "change": "removed"}]
    assert list(moved.restored) == [{"decision": a, "by": [b]}]
    assert list(moved.superseded) == []


def test_check_lists_each_arriving_cycle_next_to_the_cycles_of_the_snapshot_and_counts_it(tmp_path):
    root = tree(tmp_path / "repo", [adr(1), adr(2)])
    found = co.load(init.dump(init.build(root, "Shop")))
    loop = cycles.Cycle((did(1), did(2)), (did(1), did(2)), (path(1), path(2)))
    report = check.run(found, [FILE], root, ["@alice", "@bob"], repo="Shop", arriving=[loop])
    [entry] = report["unresolved"]
    assert entry["why"] == loop.arriving and entry["rule"] == cycles.RULE and entry["decisions"] == [did(1), did(2)]
    assert report["summary"]["unresolved"] == 1 and report["violations"] == []
    assert check.run(found, [FILE], root, ["@alice", "@bob"], repo="Shop")["unresolved"] == []


def test_check_leaves_a_leaving_cycle_out_of_the_results_that_cannot_be_judged_and_still_judges_its_rules(tmp_path):
    root = tree(tmp_path / "repo", BOTH)
    found = co.load(init.dump(init.build(root, "Shop")))
    [loop] = cycles.find(found.nodes, found.edges)
    kept = check.run(found, [FILE], root, ["@alice"], repo="Shop")
    left = check.run(found, [FILE], root, ["@alice"], repo="Shop", leaving=[loop])
    assert [u["rule"] for u in kept["unresolved"]] == [cycles.RULE] and kept["summary"]["unresolved"] == 1
    assert left["unresolved"] == [] and left["summary"]["unresolved"] == 0
    assert left["violations"] == kept["violations"] and [v["decision"] for v in left["violations"]] == [did(2)]
    assert [g["decision"] for g in left["governing"]] == [g["decision"] for g in kept["governing"]]


@pytest.mark.parametrize("members, existing, arriving", [
    (("decision:a",), "decision:a supersedes itself (a.md); it is not treated as superseded, so its rules are judged. Fix the supersedes and superseded_by lines",
     "decision:a supersedes itself (a.md) once this pull request is merged; it is not treated as superseded, so its rules are judged. "
     "Fix the supersedes and superseded_by lines"),
    (("decision:a", "decision:b"),
     "decision:a and decision:b supersede each other (a.md); neither is treated as superseded, so their rules are judged. Fix the supersedes and superseded_by lines",
     "decision:a and decision:b supersede each other (a.md) once this pull request is merged; neither is treated as superseded, so their rules are judged. "
     "Fix the supersedes and superseded_by lines"),
    (("decision:a", "decision:b", "decision:c"),
     "decision:a, decision:b and decision:c supersede one another in a cycle (a.md); none of them is treated as superseded, so their rules are judged. "
     "Fix the supersedes and superseded_by lines",
     "decision:a, decision:b and decision:c supersede one another in a cycle (a.md) once this pull request is merged; "
     "none of them is treated as superseded, so their rules are judged. Fix the supersedes and superseded_by lines"),
])
def test_a_cycle_the_pull_request_adds_is_worded_like_one_on_the_base_with_the_time_it_takes_effect(members, existing, arriving):
    loop = cycles.Cycle(members, members, ("a.md",))
    assert loop.reason == existing and loop.arriving == arriving


def test_the_supersession_text_escapes_every_name_and_path(no_network):
    outcome = hostile_outcome()
    loop = cycles.Cycle((HOSTILE,), (HOSTILE,), (HOSTILE_PATH,))
    moved = committed.Supersession(
        edges=({"source": HOSTILE, "target": HOSTILE, "change": "added"},),
        superseded=({"decision": HOSTILE, "by": [HOSTILE]},), restored=({"decision": HOSTILE, "by": [HOSTILE]},),
        added=(loop,), removed=(loop,))
    outcome = action.Outcome(outcome.report, outcome.pull, outcome.approved, outcome.version, outcome.snapshot,
                             pending=action.Pending([HOSTILE_PATH], [], moved))
    out = "\n".join(action.pending(outcome, 50))
    for raw in ("<script", "<img", "<!--", "@everyone", "](", "**bold**", "‮", "\x00", ":shipit:", "$x$"):
        assert raw not in out
    assert all(not line.startswith("#") or line.startswith("#### ") for line in out.splitlines())


def test_the_supersession_lists_are_cut_to_the_rows_the_comment_has_room_for(no_network):
    outcome = hostile_outcome()
    loops = tuple(cycles.Cycle((f"decision:c{i}",), (f"decision:c{i}",), (f"docs/adr/{i}.md",)) for i in range(3))
    moved = committed.Supersession(
        edges=tuple({"source": f"decision:s{i}", "target": f"decision:t{i}", "change": "added"} for i in range(3)),
        superseded=tuple({"decision": f"decision:u{i}", "by": [f"decision:s{i}"]} for i in range(3)),
        restored=tuple({"decision": f"decision:r{i}", "by": []} for i in range(3)), added=loops, removed=())
    outcome = action.Outcome(outcome.report, outcome.pull, outcome.approved, outcome.version, outcome.snapshot,
                             pending=action.Pending(["docs/adr/0001-a.md"], [], moved))
    one = "\n".join(action.pending(outcome, 1))
    assert one.count("2 more SUPERSEDES edge changes not shown here") == 1
    assert one.count("2 more decisions that become superseded not shown here") == 1
    assert one.count("2 more decisions that return to force not shown here") == 1
    assert one.count("2 more cycles not shown here") == 1
    assert "decision:s1" not in one and "decision:u1" not in one and "decision:r1" not in one and "c1" not in one
    none = "\n".join(action.pending(outcome, 0))
    assert "| added |" not in none and "decision:s0" not in none and "3 more SUPERSEDES edge changes not shown here" in none
