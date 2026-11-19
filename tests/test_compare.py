from __future__ import annotations

import json
from pathlib import Path

import pytest

from vinc_relate import cli, compare

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "bench" / "tasks.json"


@pytest.fixture(scope="module")
def result():
    return compare.run(ROOT, TASKS)


def by_id(result, task_id):
    return next(t for t in result["tasks"] if t["id"] == task_id)


def test_the_committed_results_are_what_the_command_gives(result):
    committed = json.loads((ROOT / "bench" / "results.json").read_text(encoding="utf-8"))
    assert compare.without_latency(committed) == compare.without_latency(result)
    assert (ROOT / "bench" / "results.md").read_text(encoding="utf-8").splitlines()[3].startswith("| B | 9/13 | 15/17 |")


def test_two_runs_give_the_same_numbers_apart_from_latency(result):
    assert compare.without_latency(compare.run(ROOT, TASKS)) == compare.without_latency(result)


def test_the_graph_finds_every_expected_path_and_policy_link(result):
    c = result["total"]["C"]
    assert c["paths"] == [13, 13] and c["policy_links"] == [17, 17] and c["covered"] == [37, 37]


def test_a_transitive_chain_is_found_only_by_the_graph(result):
    t = by_id(result, "audit-transitive-shipped")["results"]
    assert t["C"]["paths"] == [2, 2] and t["B"]["paths"] == [0, 2] and t["A"]["paths"] == [0, 2]
    wrong = [c for c in t["B"]["claims"] if c["type"] == "path"]
    assert [c["key"] for c in wrong] == [["repo:Demo", "pkg:npm/test-kit@1.0.3", "pkg:npm/url-parse-lite@1.0.2", "adv:DEMO-2026-0001"]]
    assert wrong[0]["covered"] is False


def test_the_report_says_where_the_graph_does_not_help(result):
    assert result["c_vs_b"]["better"] == ["audit-transitive-shipped", "impact-two-hop-decision"]
    assert result["c_vs_b"]["worse"] == ["impact-overreach-decoy"]
    over = by_id(result, "impact-overreach-decoy")["results"]["C"]
    assert over["unsupported"] == [2, 4]
    assert ["reports_archive/index.py", "decision:demo-logs-are-kept-thirty-days"] in [c["key"] for c in over["claims"]]


def test_scope_and_range_decoys_are_judged_by_text_and_graph_alike(result):
    for task_id in ("audit-dev-only-direct", "audit-version-outside-range"):
        r = by_id(result, task_id)["results"]
        assert r["B"]["policy_links"] == r["C"]["policy_links"] == [2, 2]
        assert r["B"]["unsupported"][0] == r["C"]["unsupported"][0] == 0


def test_a_claim_is_covered_only_by_a_connected_chain_of_input_facts():
    known = {("a", "R", "b"), ("b", "R", "c")}
    claim = lambda steps: {"evidence": steps, "from": "a", "to": "c"}
    assert compare.covered(claim([["a", "R", "b"], ["b", "R", "c"]]), known)
    assert not compare.covered(claim([["a", "R", "b"]]), known)
    assert not compare.covered(claim([["a", "R", "b"], ["b", "R", "x"], ["x", "R", "c"]]), known)
    assert not compare.covered(claim([]), known)


def test_retrieval_reports_an_advisory_already_recorded_in_vinc():
    inp = compare.load_inputs(ROOT, json.loads(TASKS.read_text(encoding="utf-8")))
    record = {"id": "record:demo-chart-kit-advisory", "kind": "record", "title": "chart-kit advisory",
              "props": {"entity": "npm:chart-kit", "value": "DEMO-2026-0004", "versions": ["1.2.0"], "severity": "MODERATE"}}
    inp["vinc"] = compare.Subgraph(inp["vinc"].nodes + [record], inp["vinc"].edges, {})
    keys = [c["key"] for c in compare.method_a_audit(inp, "pkg:npm/chart-kit@1.2.0")]
    assert ["pkg:npm/chart-kit@1.2.0", "adv:DEMO-2026-0004", "affected"] in keys
    assert compare.method_a_audit(inp, "pkg:npm/web-kit@3.0.1") == []


def test_every_task_states_expected_findings_that_name_nodes_of_the_synthetic_inputs():
    doc = json.loads(TASKS.read_text(encoding="utf-8"))
    known = {x for s, _, t in compare.facts(compare.load_inputs(ROOT, doc)) for x in (s, t)}
    for t in doc["tasks"]:
        exp = t["expected"]
        assert exp["paths"] and exp["policy_links"] and isinstance(t["graph_expected_to_help"], bool)
        ids = [x for p in exp["paths"] for x in p] + [link.get("node", link.get("decision")) for link in exp["policy_links"]]
        assert set(ids) <= known
    assert any(not t["graph_expected_to_help"] for t in doc["tasks"])


def test_the_command_writes_the_json_and_the_table(tmp_path, capsys):
    assert cli.main(["compare", "--out", str(tmp_path / "r.json"), "--table", str(tmp_path / "r.md")]) == 0
    printed = capsys.readouterr().out
    assert printed == (tmp_path / "r.md").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["total"]["C"]["paths"] == [13, 13]
