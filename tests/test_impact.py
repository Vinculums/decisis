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
    ("reports/export.py", None, "reports/export.py"),
    ("storage/page_store.py:check_page_size", None, "storage/page_store.py"),
    ("Demo:storage/page_store.py", None, "storage/page_store.py"),
    ("Demo:storage/page_store.py", "Demo", "storage/page_store.py"),
    ("Other:storage/cache.py", "Demo", None),
    ("Demo:reports/", None, "reports"),
    ("./server.py:main", None, "server.py"),
    ("Makefile:build", None, "Makefile"),
])
def test_a_code_ref_drops_its_repository_prefix_and_symbol_suffix(ref, repo, want):
    assert impact.code_path(ref, repo) == want


def test_a_direct_code_ref_hit_lists_the_concept_then_what_governs_it(tmp_path):
    gov = one(impact.run(graph(), ["reports/export.py"], root=tmp_path))
    assert [(g["hops"], g["kind"], g["id"]) for g in gov] == [
        (0, "concept", "concept:demo-report-export"),
        (0, "concept", "concept:demo-report-service"),
        (1, "decision", "decision:demo-report-exports-finish-in-time"),
        (1, "record", "record:demo-report-export-timed-out"),
    ]
    by = {g["id"]: g for g in gov}
    assert by["concept:demo-report-export"]["code_ref"] == [{"ref": "reports/export.py", "match": "exact"}]
    assert by["concept:demo-report-service"]["code_ref"] == [{"ref": "Demo:reports/", "match": "encloses"}]
    assert by["decision:demo-report-exports-finish-in-time"]["path"] == [
        {"source": "decision:demo-report-exports-finish-in-time", "type": "ABOUT", "target": "concept:demo-report-export",
         "evidence": "the limit applies to this endpoint"}]
    assert by["decision:demo-report-exports-finish-in-time"]["via"] == "concept:demo-report-export"


def test_a_decision_two_hops_away_comes_with_its_edge_path_and_evidence(tmp_path):
    gov = one(impact.run(graph(), ["storage/page_store.py:check_page_size"], root=tmp_path))
    d = next(g for g in gov if g["id"] == "decision:demo-oversized-pages-are-refused")
    assert d["hops"] == 2 and d["kind"] == "decision"
    assert d["nodes"] == ["concept:demo-page-size-check", "concept:demo-page-budget", "decision:demo-oversized-pages-are-refused"]
    assert d["path"] == [
        {"source": "concept:demo-page-budget", "type": "RELATED_TO", "target": "concept:demo-page-size-check", "evidence": "the check enforces the budget"},
        {"source": "decision:demo-oversized-pages-are-refused", "type": "ABOUT", "target": "concept:demo-page-budget", "evidence": "the decision sets the budget"},
    ]


def test_ordering_is_by_hops_then_decision_record_concept():
    rows = [{"anchor": "c", "id": i, "kind": k, "hops": h, "ids": ["c"] if h == 0 else ["c", i], "rels": [] if h == 0 else ["ABOUT"],
             "evidence": [] if h == 0 else [""]} for i, k, h in
            [("concept:z", "concept", 1), ("record:a", "record", 1), ("decision:b", "decision", 1), ("c", "concept", 0), ("decision:far", "decision", 2)]]
    g = co.Subgraph([{"id": r["id"], "kind": r["kind"], "props": {}} for r in rows], [], {})
    assert [i["id"] for i in impact.collect(rows, g, "x")] == ["c", "decision:b", "record:a", "concept:z", "decision:far"]


def test_the_hop_bound_holds(tmp_path):
    ids = [g["id"] for g in one(impact.run(graph(), ["storage/page_store.py"], hops=1, root=tmp_path))]
    assert "decision:demo-oversized-pages-are-refused" not in ids
    ids = [g["id"] for g in one(impact.run(graph(), ["storage/page_store.py"], hops=3, root=tmp_path))]
    assert "decision:demo-oversized-pages-are-refused" in ids and "record:demo-page-size-check-review" in ids


def test_a_path_nothing_names_returns_no_governing_node(tmp_path):
    report = impact.run(graph(), ["docs/index.md"], root=tmp_path)
    assert one(report) == []
    assert "nothing in the snapshot names this path" in impact.render(report)


def test_a_directory_prefix_matches_the_files_under_it_and_not_a_sibling_with_the_same_stem(tmp_path):
    report = impact.run(graph(), ["storage/", "reports"], repo="Demo", root=tmp_path)
    store = {g["id"]: g for g in one(report, 0)}
    assert {i for i, g in store.items() if g["hops"] == 0} == {"concept:demo-page-store", "concept:demo-page-size-check"}
    assert store["concept:demo-page-store"]["code_ref"] == [{"ref": "Demo:storage/page_store.py", "match": "under"}]
    assert "decision:demo-oversized-pages-are-refused" in store
    api = {g["id"] for g in one(report, 1)}
    assert "concept:demo-report-export" in api and "concept:demo-report-archive" not in api and "decision:demo-archive-reads-are-rate-limited" not in api


def test_the_task_file_is_gone_after_the_run(tmp_path):
    impact.run(graph(), ["reports/export.py"], root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_the_query_lives_in_a_cypher_file():
    assert "code_paths" in query("governing_nodes", hops=2) and "*0..2" in query("governing_nodes", hops=2)


def test_the_cli_prints_json_and_a_short_human_form(capsys):
    assert cli.main(["impact", str(FIXTURE), "reports/export.py", "docs/index.md"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [r["path"] for r in out["impact"]] == ["reports/export.py", "docs/index.md"]
    assert out["loaded"] == {"nodes": 12, "edges": 8}
    assert cli.main(["impact", str(FIXTURE), "reports/export.py", "--format", "text"]) == 0
    text = capsys.readouterr().out
    assert text.startswith("reports/export.py: 4 node(s) within 3 hop(s)")
    assert "decision:demo-report-exports-finish-in-time -ABOUT-> concept:demo-report-export" in text


def test_an_unusable_path_or_hop_bound_is_refused():
    with pytest.raises(ValueError):
        impact.run(graph(), ["/"])
    with pytest.raises(ValueError):
        impact.run(graph(), ["reports"], hops=99)


def test_a_decision_anchors_by_its_subject_path_and_also_touches_with_any_repo_case(tmp_path):
    snap = json.loads(FIXTURE.read_text(encoding="utf-8"))
    snap["nodes"] += [
        {"id": "decision:demo-runs-stop-and-report", "kind": "decision", "title": "Runs stop and report", "domain": "engineering/runs",
         "props": {"subject_path": "demo:runs/protocol.py", "also_touches": ["Demo:runs/state.py"]}},
        {"id": "record:demo-old-waits-closed", "kind": "record", "title": "Old waits closed", "domain": "engineering/runs",
         "props": {}},
    ]
    snap["edges"].append({"source": "record:demo-old-waits-closed", "target": "decision:demo-runs-stop-and-report", "type": "RELATED_TO",
                          "evidence": "the close follows the decision"})
    snap["meta"].update(nodes=len(snap["nodes"]), edges=len(snap["edges"]))
    g = co.load(json.dumps(snap))
    report = impact.run(g, ["runs/protocol.py", "runs/state.py"], repo="Demo", root=tmp_path)
    first = [(x["hops"], x["kind"], x["id"]) for x in one(report, 0)]
    assert first == [(0, "decision", "decision:demo-runs-stop-and-report"), (1, "record", "record:demo-old-waits-closed")]
    assert one(report, 0)[0]["code_ref"] == [{"ref": "demo:runs/protocol.py", "match": "exact"}]
    assert [x["id"] for x in one(report, 1)][:1] == ["decision:demo-runs-stop-and-report"]
