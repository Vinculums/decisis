from __future__ import annotations

import json
from pathlib import Path

import pytest

from vinc_relate import checkout as co
from vinc_relate import cli, impact
from vinc_relate.queries import load as query

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "impact" / "vinc.json"


def graph():
    return co.load(FIXTURE.read_text(encoding="utf-8"))


def one(report, i=0):
    return report["impact"][i]["governing"]


@pytest.mark.parametrize("ref,repo,want", [
    ("api/graph_algo.py", None, "api/graph_algo.py"),
    ("store/embedded_backend.py:_vector_query_guard", None, "store/embedded_backend.py"),
    ("Demo:store/embedded_backend.py", None, "store/embedded_backend.py"),
    ("Demo:store/embedded_backend.py", "Demo", "store/embedded_backend.py"),
    ("Other:store/cache.py", "Demo", None),
    ("Demo:api/", None, "api"),
    ("./server.py:main", None, "server.py"),
    ("Makefile:build", None, "Makefile"),
])
def test_a_code_ref_drops_its_repository_prefix_and_symbol_suffix(ref, repo, want):
    assert impact.code_path(ref, repo) == want


def test_a_direct_code_ref_hit_lists_the_concept_then_what_governs_it(tmp_path):
    gov = one(impact.run(graph(), ["api/graph_algo.py"], root=tmp_path))
    assert [(g["hops"], g["kind"], g["id"]) for g in gov] == [
        (0, "concept", "concept:api-layer"),
        (0, "concept", "concept:graph-algorithms"),
        (1, "decision", "decision:bound-graph-algorithm-cost"),
        (1, "record", "record:graph-algo-timeout"),
    ]
    by = {g["id"]: g for g in gov}
    assert by["concept:graph-algorithms"]["code_ref"] == [{"ref": "api/graph_algo.py", "match": "exact"}]
    assert by["concept:api-layer"]["code_ref"] == [{"ref": "Demo:api/", "match": "encloses"}]
    assert by["decision:bound-graph-algorithm-cost"]["path"] == [
        {"source": "decision:bound-graph-algorithm-cost", "type": "ABOUT", "target": "concept:graph-algorithms",
         "evidence": "the bound applies to this endpoint"}]
    assert by["decision:bound-graph-algorithm-cost"]["via"] == "concept:graph-algorithms"


def test_a_decision_two_hops_away_comes_with_its_edge_path_and_evidence(tmp_path):
    gov = one(impact.run(graph(), ["store/embedded_backend.py:_vector_query_guard"], root=tmp_path))
    d = next(g for g in gov if g["id"] == "decision:refuse-unbounded-vector-scans")
    assert d["hops"] == 2 and d["kind"] == "decision"
    assert d["nodes"] == ["concept:vector-query-guard", "concept:query-budget", "decision:refuse-unbounded-vector-scans"]
    assert d["path"] == [
        {"source": "concept:query-budget", "type": "RELATED_TO", "target": "concept:vector-query-guard", "evidence": "the guard enforces the budget"},
        {"source": "decision:refuse-unbounded-vector-scans", "type": "ABOUT", "target": "concept:query-budget", "evidence": "the decision sets the budget"},
    ]


def test_ordering_is_by_hops_then_decision_record_concept():
    rows = [{"anchor": "c", "id": i, "kind": k, "hops": h, "ids": ["c"] if h == 0 else ["c", i], "rels": [] if h == 0 else ["ABOUT"],
             "evidence": [] if h == 0 else [""]} for i, k, h in
            [("concept:z", "concept", 1), ("record:a", "record", 1), ("decision:b", "decision", 1), ("c", "concept", 0), ("decision:far", "decision", 2)]]
    g = co.Subgraph([{"id": r["id"], "kind": r["kind"], "props": {}} for r in rows], [], {})
    assert [i["id"] for i in impact.collect(rows, g, "x")] == ["c", "decision:b", "record:a", "concept:z", "decision:far"]


def test_the_hop_bound_holds(tmp_path):
    ids = [g["id"] for g in one(impact.run(graph(), ["store/embedded_backend.py"], hops=1, root=tmp_path))]
    assert "decision:refuse-unbounded-vector-scans" not in ids
    ids = [g["id"] for g in one(impact.run(graph(), ["store/embedded_backend.py"], hops=3, root=tmp_path))]
    assert "decision:refuse-unbounded-vector-scans" in ids and "record:vector-scan-review" in ids


def test_a_path_nothing_names_returns_no_governing_node(tmp_path):
    report = impact.run(graph(), ["docs/index.md"], root=tmp_path)
    assert one(report) == []
    assert "nothing in the snapshot names this path" in impact.render(report)


def test_a_directory_prefix_matches_the_files_under_it_and_not_a_sibling_with_the_same_stem(tmp_path):
    report = impact.run(graph(), ["store/", "api"], repo="Demo", root=tmp_path)
    store = {g["id"]: g for g in one(report, 0)}
    assert {i for i, g in store.items() if g["hops"] == 0} == {"concept:embedded-store", "concept:vector-query-guard"}
    assert store["concept:embedded-store"]["code_ref"] == [{"ref": "Demo:store/embedded_backend.py", "match": "under"}]
    assert "decision:refuse-unbounded-vector-scans" in store
    api = {g["id"] for g in one(report, 1)}
    assert "concept:graph-algorithms" in api and "concept:api-gateway" not in api and "decision:gateway-rate-limits" not in api


def test_the_task_file_is_gone_after_the_run(tmp_path):
    impact.run(graph(), ["api/graph_algo.py"], root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_the_query_lives_in_a_cypher_file():
    assert "code_paths" in query("governing_nodes", hops=2) and "*0..2" in query("governing_nodes", hops=2)


def test_the_cli_prints_json_and_a_short_human_form(capsys):
    assert cli.main(["impact", str(FIXTURE), "api/graph_algo.py", "docs/index.md"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [r["path"] for r in out["impact"]] == ["api/graph_algo.py", "docs/index.md"]
    assert out["loaded"] == {"nodes": 12, "edges": 8}
    assert cli.main(["impact", str(FIXTURE), "api/graph_algo.py", "--format", "text"]) == 0
    text = capsys.readouterr().out
    assert text.startswith("api/graph_algo.py: 4 node(s) within 3 hop(s)")
    assert "decision:bound-graph-algorithm-cost -ABOUT-> concept:graph-algorithms" in text


def test_an_unusable_path_or_hop_bound_is_refused():
    with pytest.raises(ValueError):
        impact.run(graph(), ["/"])
    with pytest.raises(ValueError):
        impact.run(graph(), ["api"], hops=99)
