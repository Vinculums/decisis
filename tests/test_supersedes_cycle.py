from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple

import pytest

from test_action import FakeGitHub, outputs
from test_audit import no_network
from test_base_decisions import env_for, repository, summary
from test_sarif import validate
from decisis import action, cli, committed, compact, cycles, impact, init
from decisis import checkout as co

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "fixtures" / "audit" / "demo-lockfile.json"
CACHE = ROOT / "fixtures" / "audit" / "osv-cache.json"
NAMES = {1: "a", 2: "b", 3: "c", 4: "d"}
REVIEWERS = {1: "@alice", 2: "@bob", 3: "@carol", 4: "@dave"}
FILE = "src/pay/a.py"


def did(n: int) -> str:
    return f"decision:shop-docs-adr-{n:04d}-{NAMES[n]}"


def path(n: int) -> str:
    return f"docs/adr/{n:04d}-{NAMES[n]}.md"


def link(n: int) -> str:
    return f"{n:04d}-{NAMES[n]}.md"


def adr(n: int, *front: str, rule: dict | None = None, status_line: str | None = None) -> tuple[str, str]:
    kind = rule or {"review_required": {"paths": ["src/pay/**"], "reviewers": [REVIEWERS[n]]}}
    lines = ["---", f"title: {NAMES[n].upper()}", "code_ref: src/pay/", f"rule: {json.dumps(kind)}", *front, "---", f"# {NAMES[n].upper()}"]
    if status_line:
        lines += ["", "## Status", "", status_line]
    return path(n), "\n".join(lines) + "\n"


class Case(NamedTuple):
    files: list[tuple[str, str]]
    cycles: list[tuple[int, ...]]
    superseded: dict[int, list[int]]
    edges: int

    @property
    def governing(self) -> set[int]:
        return {int(Path(f).name[:4]) for f, _ in self.files} - set(self.superseded)


CASES = {
    "a decision that supersedes itself": Case([adr(1, f"supersedes: {link(1)}")], [(1,)], {}, 1),
    "a decision that is superseded by itself": Case([adr(1, f"superseded_by: {link(1)}")], [(1,)], {}, 1),
    "a decision whose status says it is superseded by itself": Case([adr(1, "status: superseded by ADR-0001")], [(1,)], {}, 1),
    "two ADRs that name each other as superseded_by": Case([adr(1, f"superseded_by: {link(2)}"), adr(2, f"superseded_by: {link(1)}")],
                                                         [(1, 2)], {}, 2),
    "two ADRs whose status lines say superseded by each other": Case(
        [adr(1, status_line="Superseded by [ADR-0002](0002-b.md)"), adr(2, status_line="Superseded by [ADR-0001](0001-a.md)")],
        [(1, 2)], {}, 2),
    "three ADRs that supersede each other in a ring": Case(
        [adr(1, f"supersedes: {link(2)}"), adr(2, f"supersedes: {link(3)}"), adr(3, f"supersedes: {link(1)}")], [(1, 2, 3)], {}, 3),
    "a chain into a cycle and a decision the cycle supersedes": Case(
        [adr(1, f"superseded_by: {link(2)}", f"supersedes: {link(3)}"), adr(2, f"superseded_by: {link(1)}"), adr(3),
         adr(4, f"supersedes: {link(1)}")], [(1, 2)], {3: [1]}, 4),
    "two separate cycles": Case(
        [adr(1, f"superseded_by: {link(2)}"), adr(2, f"superseded_by: {link(1)}"), adr(3, f"supersedes: {link(4)}"),
         adr(4, f"supersedes: {link(3)}")], [(1, 2), (3, 4)], {}, 4),
}
NAMED = list(CASES)


def tree(tmp_path: Path, files: list[tuple[str, str]]) -> Path:
    for rel, body in files:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body, encoding="utf-8")
    return tmp_path


def snapshot_file(tmp_path: Path, case: Case) -> tuple[Path, Path]:
    root = tree(tmp_path / "repo", case.files)
    snap = tmp_path / "snapshot.json"
    snap.write_text(init.dump(init.build(root, "Shop")), encoding="utf-8")
    return root, snap


def run(capsys, *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(list(args))
    return code, capsys.readouterr().out


def check_args(root: Path, snap: Path, *extra: str) -> list[str]:
    return ["check", str(snap), "--repo-dir", str(root), "--changed", FILE, "--repo", "Shop", *extra]


def everyone(case: Case) -> list[str]:
    return [REVIEWERS[n] for n in sorted(case.governing)]


def cycle_entries(report: dict) -> list[dict]:
    return [u for u in report["unresolved"] if u["rule"] == cycles.RULE]


def graph_of(case: Case, tmp_path: Path):
    return co.load(init.dump(init.build(tree(tmp_path / "repo", case.files), "Shop")))


@pytest.mark.parametrize("name", NAMED)
def test_init_lists_each_cycle_under_problems_names_every_decision_and_file_and_keeps_the_edges(name, tmp_path):
    case = CASES[name]
    snap = init.build(tree(tmp_path, case.files), "Shop")
    found = snap["meta"]["problems"]
    assert [p["action"] for p in found] == ["in force"] * len(case.cycles)
    for problem, cycle in zip(found, case.cycles):
        assert problem["kind"] == "decision" and problem["file"] == path(cycle[0])
        assert all(did(n) in problem["reason"] and path(n) in problem["reason"] for n in cycle)
        assert not any(did(n) in problem["reason"] or path(n) in problem["reason"] for n in set(NAMES) - set(cycle))
    assert [e["type"] for e in snap["edges"]] == ["SUPERSEDES"] * case.edges and snap["meta"]["edges"] == case.edges
    assert init.unread_decisions(snap["meta"]) == []


def test_a_chain_without_a_cycle_has_no_problem_and_the_old_decision_stays_superseded(tmp_path):
    files = [adr(1, f"superseded_by: {link(2)}"), adr(2, f"superseded_by: {link(3)}"), adr(3)]
    snap = init.build(tree(tmp_path / "repo", files), "Shop")
    assert snap["meta"]["problems"] == []
    (tmp_path / "box").mkdir()
    [result] = impact.run(co.load(init.dump(snap)), [FILE], repo="Shop", root=tmp_path / "box")["impact"]
    assert [g["id"] for g in result["governing"]] == [did(3)]
    assert {g["id"]: g["superseded_by"] for g in result["superseded"]} == {did(1): [did(2)], did(2): [did(3)]}


@pytest.mark.parametrize("name", NAMED)
def test_impact_judges_every_cycle_member_as_in_force_and_keeps_what_a_member_supersedes_superseded(name, tmp_path):
    case = CASES[name]
    box = tmp_path / "box"
    box.mkdir()
    [result] = impact.run(graph_of(case, tmp_path), [FILE], repo="Shop", root=box)["impact"]
    assert {g["id"] for g in result["governing"]} == {did(n) for n in case.governing}
    assert {g["id"]: g["superseded_by"] for g in result.get("superseded", [])} == {did(n): [did(m) for m in by] for n, by in case.superseded.items()}


@pytest.mark.parametrize("name", NAMED)
def test_check_fails_closed_on_each_cycle_with_one_violation_per_member_rule(name, tmp_path, capsys, no_network):
    case = CASES[name]
    root, snap = snapshot_file(tmp_path, case)
    code, out = run(capsys, *check_args(root, snap))
    report = json.loads(out)
    assert code == 1
    assert {v["decision"] for v in report["violations"]} == {did(n) for n in case.governing}
    assert {g["decision"] for g in report["governing"]} == {did(n) for n in case.governing}
    assert {s["decision"]: s["superseded_by"] for s in report["superseded"]} == {did(n): [did(m) for m in by] for n, by in case.superseded.items()}
    assert all(r["verdict"] == "violated" and r["rule"] == "review_required" for r in report["violations"])


@pytest.mark.parametrize("name", NAMED)
def test_check_lists_each_cycle_as_a_result_that_cannot_be_judged_even_with_every_reviewer_given(name, tmp_path, capsys, no_network):
    case = CASES[name]
    root, snap = snapshot_file(tmp_path, case)
    given = ["--reviewers", *everyone(case)]
    code, out = run(capsys, *check_args(root, snap, *given))
    report = json.loads(out)
    assert code == 0 and report["violations"] == []
    found = cycle_entries(report)
    assert [e["decisions"] for e in found] == [[did(n) for n in c] for c in case.cycles]
    assert [e["files"] for e in found] == [[path(n) for n in c] for c in case.cycles]
    assert all(e["verdict"] == "unresolved" and e["line"] is None and e["import"] is None and e["target"] is None for e in found)
    assert all(e["decision"] == e["decisions"][0] and e["file"] == e["files"][0] for e in found)
    assert all(all(did(n) in e["why"] and path(n) in e["why"] for n in c) for e, c in zip(found, case.cycles))
    assert report["summary"]["unresolved"] == len(case.cycles) == len(report["unresolved"])
    assert run(capsys, *check_args(root, snap, *given, "--fail-on-unresolved"))[0] == 1


def test_the_reported_case_end_to_end_gives_two_violations_and_exit_1_where_it_gave_none(tmp_path, capsys, no_network):
    case = CASES["two ADRs that name each other as superseded_by"]
    root = tree(tmp_path / "repo", case.files)
    out = tmp_path / "snap.json"
    code, printed = run(capsys, "init", "--repo-dir", str(root), "--repo", "Shop", "--out", str(out))
    shown = json.loads(printed)
    assert code == 0 and shown["edges"] == 2 and [p["action"] for p in shown["problems"]] == ["in force"]
    assert [p["file"] for p in shown["problems"]] == [path(1)]
    code, text = run(capsys, *check_args(root, out, "--format", "text"))
    assert code == 1
    assert "governing decisions: 2" in text and "superseded, not judged" not in text and "violations: 2" in text
    assert "cannot be judged: 1" in text and f"{did(1)} and {did(2)} supersede each other ({path(1)}, {path(2)})" in text
    both = ["--reviewers", "@alice", "@bob"]
    assert run(capsys, *check_args(root, out, *both))[0] == 0
    assert run(capsys, *check_args(root, out, *both, "--fail-on-unresolved"))[0] == 1
    assert run(capsys, *check_args(root, out, "--reviewers", "@alice"))[0] == 1


def test_the_html_view_and_the_mcp_summary_and_full_replies_show_the_cycle(tmp_path, capsys, no_network):
    case = CASES["three ADRs that supersede each other in a ring"]
    root, snap = snapshot_file(tmp_path, case)
    given = ["--reviewers", *everyone(case)]
    page = run(capsys, *check_args(root, snap, *given, "--format", "html"))[1]
    assert "<h2>Cannot be judged</h2>" in page and "<code>supersedes_cycle</code>" in page
    assert f"{did(1)}, {did(2)} and {did(3)} supersede one another in a cycle" in page
    report = json.loads(run(capsys, *check_args(root, snap, *given))[1])
    short = compact.shape("check", report)
    assert short["unresolved_count"] == 1 and short["summary"]["unresolved"] == 1
    assert short["unresolved"][0]["rule"] == "supersedes_cycle" and did(3) in short["unresolved"][0]["why"]
    assert compact.shape("check", report, "full")["unresolved"][0]["decisions"] == [did(1), did(2), did(3)]


def test_the_sarif_log_gives_the_cycle_as_one_warning_located_at_the_first_adr(tmp_path, capsys, no_network):
    case = CASES["two ADRs that name each other as superseded_by"]
    root, snap = snapshot_file(tmp_path, case)
    code, out = run(capsys, *check_args(root, snap, "--reviewers", "@alice", "@bob", "--format", "sarif"))
    log = json.loads(out)
    [result] = log["runs"][0]["results"]
    assert code == 0 and result["level"] == "warning" and result["ruleId"] == "supersedes_cycle"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == path(1)
    assert did(1) in result["message"]["text"] and did(2) in result["message"]["text"]
    assert [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]] == ["review_required", "supersedes_cycle"]
    assert result["partialFingerprints"]["decisis/v1"]
    validate(log)


def test_a_decision_in_a_cycle_keeps_its_rules_even_when_its_status_says_superseded(tmp_path):
    case = CASES["two ADRs whose status lines say superseded by each other"]
    graph = graph_of(case, tmp_path)
    assert {n["props"]["status"] for n in graph.nodes} == {"superseded"}
    assert impact.superseded_by(graph) == {}


def test_a_status_that_says_superseded_with_no_edge_stays_superseded_and_a_cycle_elsewhere_does_not_free_it():
    nodes = [{"id": f"decision:{i}", "kind": "decision", "title": i, "props": p} for i, p in
             (("a", {"status": "Superseded"}), ("b", {}), ("c", {}), ("d", {"status": "superseded"}))]
    edges = [{"source": "decision:b", "target": "decision:c", "type": "SUPERSEDES"},
             {"source": "decision:c", "target": "decision:b", "type": "SUPERSEDES"}]
    held = impact.superseded_by(co.load(json.dumps({"nodes": nodes, "edges": edges})))
    assert held == {"decision:a": [], "decision:d": []}


def test_find_ignores_a_cycle_among_non_decisions_and_an_edge_to_a_node_that_is_not_in_the_snapshot():
    nodes = [{"id": f"concept:{i}", "kind": "concept", "title": i, "props": {}} for i in "xy"]
    nodes += [{"id": "decision:a", "kind": "decision", "title": "a", "props": {}}]
    edges = [{"source": "concept:x", "target": "concept:y", "type": "SUPERSEDES"}, {"source": "concept:y", "target": "concept:x", "type": "SUPERSEDES"},
             {"source": "decision:a", "target": "decision:gone", "type": "SUPERSEDES"}, {"source": "decision:gone", "target": "decision:a", "type": "SUPERSEDES"},
             {"source": "decision:a", "target": "concept:x", "type": "RELATED_TO"}]
    assert cycles.find(nodes, edges) == []


def test_find_reports_a_cycle_that_mixes_a_decision_with_another_kind_and_names_every_member():
    nodes = [{"id": "decision:a", "kind": "decision", "title": "a", "props": {"source_file": "docs/adr/0001-a.md"}},
             {"id": "concept:b", "kind": "concept", "title": "b", "props": {}}]
    edges = [{"source": "decision:a", "target": "concept:b", "type": "SUPERSEDES"}, {"source": "concept:b", "target": "decision:a", "type": "SUPERSEDES"}]
    [found] = cycles.find(nodes, edges)
    assert found.members == ("concept:b", "decision:a") and found.decisions == ("decision:a",) and found.files == ("docs/adr/0001-a.md",)
    held = impact.superseded_by(co.load(json.dumps({"nodes": nodes, "edges": edges})))
    assert held == {}


def test_find_walks_a_long_ring_and_a_long_chain_without_recursion():
    size = 5000
    nodes = [{"id": f"decision:{i}", "kind": "decision", "title": str(i), "props": {}} for i in range(size)]
    ring = [{"source": f"decision:{i}", "target": f"decision:{(i + 1) % size}", "type": "SUPERSEDES"} for i in range(size)]
    [found] = cycles.find(nodes, ring)
    assert len(found.members) == size
    assert cycles.find(nodes, ring[:-1]) == []


def test_paths_still_walks_the_cycle_edges_that_stay_in_the_snapshot(tmp_path, capsys):
    case = CASES["two ADRs that name each other as superseded_by"]
    _, snap = snapshot_file(tmp_path, case)
    code, out = run(capsys, "paths", str(snap), did(1), did(2), "--hops", "2")
    found = json.loads(out)["paths"]
    assert code == 0 and [did(1), did(2)] in [p["ids"] for p in found]
    assert all(set(p["rels"]) == {"SUPERSEDES"} for p in found)
    _, loop = snapshot_file(tmp_path / "self", CASES["a decision that supersedes itself"])
    code, out = run(capsys, "paths", str(loop), did(1), did(1))
    assert code == 0 and all(set(p["rels"]) == {"SUPERSEDES"} for p in json.loads(out)["paths"])


def audit_files(extra: list[tuple[str, str]]) -> list[tuple[str, str]]:
    severe = {"advisory_severity_at_least": "HIGH"}
    return [adr(1, f"superseded_by: {link(2)}", f"supersedes: {link(3)}", rule=severe), adr(2, f"superseded_by: {link(1)}", rule=severe),
            adr(3, rule=severe), *extra]


def test_audit_judges_a_cycle_member_and_keeps_what_it_supersedes_out(tmp_path, capsys, no_network):
    root = tree(tmp_path / "repo", audit_files([]))
    snap = tmp_path / "snapshot.json"
    snap.write_text(init.dump(init.build(root, "Shop")), encoding="utf-8")
    code, out = run(capsys, "audit", str(snap), str(LOCK), "--repo", "Shop", "--osv-cache", str(CACHE))
    report = json.loads(out)
    assert code == 0
    assert {g["decision"] for g in report["governing"]} == {did(1), did(2)}
    assert [(d["decision"], d["reason"]) for d in report["not_governing"]] == [
        (did(3), f"it is superseded by {did(1)}, and a superseded decision is not judged")]
    assert report["violations"] > 0


def test_superseded_by_holds_only_what_a_cycle_member_supersedes(tmp_path):
    graph = co.load(init.dump(init.build(tree(tmp_path / "repo", audit_files([])), "Shop")))
    assert impact.superseded_by(graph) == {did(3): [did(1)]}


def stored(tmp_path: Path, case: Case, head: dict[str, str | None]) -> tuple[Path, str]:
    return repository(tmp_path, {**dict(case.files), FILE: "A = 1\n"}, {FILE: "A = 2\n", **head})


def test_the_action_reads_the_cycle_from_the_base_commit_and_comments_and_fails_on_it(tmp_path, no_network):
    case = CASES["two ADRs that name each other as superseded_by"]
    root, base = stored(tmp_path, case, {})
    built = committed.built(root, base, "Shop", *action.listing(root, base))
    found = [p for p in built.meta["problems"] if p["action"] == "in force"]
    assert [p["file"] for p in found] == [path(1)] and did(2) in found[0]["reason"] and path(2) in found[0]["reason"]
    reviews = [{"user": {"login": "alice"}, "state": "APPROVED"}, {"user": {"login": "bob"}, "state": "APPROVED"}]

    fake = FakeGitHub(reviews=reviews)
    env = env_for(tmp_path, root, base, DECISIS_REPO="Shop", DECISIS_FAIL_ON_UNRESOLVED="true", DECISIS_SARIF="true", GITHUB_WORKSPACE=str(root))
    assert action.main(env, fake) == 1
    out = summary(tmp_path)
    assert "**This check fails: fail-on-unresolved is on and the run found 1 check result(s) that cannot be judged.**" in out
    assert "#### Cannot be judged (1)" in out and "#### Violations" not in out
    assert action.text(f"{did(1)} and {did(2)} supersede each other ({path(1)}, {path(2)})") in out
    assert "2 decision(s) touched, 0 violation(s), 1 that cannot be judged" in out
    assert outputs(tmp_path)["unresolved"] == "1" and outputs(tmp_path)["violations"] == "0"
    (_, _, data), = fake.writes()
    assert data["body"] == out
    log = json.loads(Path(outputs(tmp_path)["sarif-file"]).read_text())
    [result] = [r for r in log["runs"][0]["results"] if r["ruleId"] == "supersedes_cycle"]
    assert result["level"] == "warning" and result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == path(1)


def test_the_action_judges_both_rules_when_nobody_has_approved(tmp_path, no_network):
    case = CASES["two ADRs that name each other as superseded_by"]
    root, base = stored(tmp_path, case, {})
    env = env_for(tmp_path, root, base, DECISIS_REPO="Shop", DECISIS_FAIL_ON_VIOLATION="true")
    assert action.main(env, FakeGitHub()) == 1
    out = summary(tmp_path)
    assert "#### Violations (2)" in out and "Superseded, not judged" not in out
    assert outputs(tmp_path)["violations"] == "2" and outputs(tmp_path)["unresolved"] == "1"


def test_the_action_without_fail_on_unresolved_reports_the_cycle_and_passes_when_both_reviewers_approved(tmp_path, no_network):
    case = CASES["two ADRs that name each other as superseded_by"]
    root, base = stored(tmp_path, case, {})
    reviews = [{"user": {"login": "alice"}, "state": "APPROVED"}, {"user": {"login": "bob"}, "state": "APPROVED"}]
    env = env_for(tmp_path, root, base, DECISIS_REPO="Shop", DECISIS_FAIL_ON_VIOLATION="true")
    assert action.main(env, FakeGitHub(reviews=reviews)) == 0
    assert "#### Cannot be judged (1)" in summary(tmp_path) and outputs(tmp_path)["unresolved"] == "1"
