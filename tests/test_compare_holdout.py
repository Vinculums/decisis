from __future__ import annotations

import json
from pathlib import Path

from decisis import compare

ROOT = Path(__file__).resolve().parents[1]
HOLDOUT = ROOT / "bench" / "holdout"
TASKS = HOLDOUT / "tasks.json"
PROPS = {"decision": {"source_file", "status", "date", "statement", "code_ref", "content_hash"},
         "concept": {"source_file", "code_ref", "content_hash"}}


def doc() -> dict:
    return json.loads(TASKS.read_text(encoding="utf-8"))


def test_the_held_out_set_has_twenty_tasks_on_five_repositories_with_both_kinds():
    d = doc()
    assert len(d["tasks"]) >= 20 and len(d["repos"]) >= 5
    assert {t["kind"] for t in d["tasks"]} == {"impact", "audit"}
    assert {t["repo"] for t in d["tasks"]} == set(d["repos"])
    assert all(isinstance(t["graph_expected_to_help"], bool) for t in d["tasks"])


def test_a_snapshot_keeps_only_ids_paths_titles_and_short_statements():
    for repo in doc()["repos"]:
        snap = json.loads((HOLDOUT / repo / "snapshot.json").read_text(encoding="utf-8"))
        for n in snap["nodes"]:
            assert set(n) == {"id", "kind", "title", "props"}
            assert set(n["props"]) <= PROPS[n["kind"]], n["id"]
            assert len(n["props"].get("statement", "")) <= 204, n["id"]


def test_every_mapped_path_is_in_the_snapshot_under_its_adr():
    for repo in doc()["repos"]:
        mapping = json.loads((HOLDOUT / repo / "mapping.json").read_text(encoding="utf-8"))
        snap = json.loads((HOLDOUT / repo / "snapshot.json").read_text(encoding="utf-8"))
        refs = {n["props"]["source_file"]: n["props"].get("code_ref", []) for n in snap["nodes"] if n["kind"] == "decision"}
        assert snap["meta"]["commit"] == mapping["commit"]
        for adr, rows in mapping["decisions"].items():
            for row in rows:
                assert row["path"] in row["sentence"]
                path = row["path"][2:] if row["path"].startswith("./") else row["path"]
                assert f"{repo}:{path.rstrip('/')}" in refs[adr]


def test_every_expected_id_names_a_node_of_the_stored_inputs():
    d = doc()
    for t in d["tasks"]:
        repo = HOLDOUT / t["repo"]
        exp = t["expected"]
        if t["kind"] == "impact":
            nodes = {n["id"] for n in json.loads((repo / "snapshot.json").read_text(encoding="utf-8"))["nodes"]}
            assert {x for p in exp["paths"] for x in p} | {link["node"] for link in exp["policy_links"]} <= nodes, t["id"]
            continue
        lock = json.loads((repo / "package-lock.json").read_text(encoding="utf-8"))["packages"]
        cache = json.loads((repo / "osv-cache.json").read_text(encoding="utf-8"))
        pkgs = {f"pkg:npm/{m.get('name') or p.rsplit('node_modules/', 1)[-1]}@{m['version']}" for p, m in lock.items() if p and m.get("version")}
        for path in exp["paths"]:
            assert path[0] == f"repo:{t['repo']}" and set(path[1:-1]) <= pkgs and path[-1][4:] in cache["vulns"], t["id"]
        assert {f["advisory"][4:] for f in exp["findings"]} == set(cache["queries"][t["subject"]]), t["id"]


def test_each_repository_loads_on_its_own_and_one_without_a_lockfile_has_no_audit_inputs():
    sets = compare.input_sets(ROOT, doc())
    assert set(sets) == set(doc()["repos"])
    assert sets["cf-cli"]["lock"] is None and sets["cf-cli"]["vinc"].nodes == []
    assert sets["supabase-multitenant"]["lock"] is not None
    assert all(inp["repo"] == name for name, inp in sets.items())


def test_the_committed_held_out_results_are_what_the_command_gives():
    result = compare.run(ROOT, TASKS)
    committed = json.loads((HOLDOUT / "results.json").read_text(encoding="utf-8"))
    assert compare.without_latency(committed) == compare.without_latency(result)
    assert (HOLDOUT / "results.md").read_text(encoding="utf-8").splitlines()[2:5] == compare.render(committed).splitlines()[2:5]
    c, b = result["total"]["C"], result["total"]["B"]
    assert c["paths"] == [35, 44] and c["policy_links"] == [19, 28] and c["covered"] == [30, 68]
    assert b["paths"] == [7, 44] and b["unsupported"] == [5, 26]
    assert result["c_vs_b"]["worse"] == [] and len(result["c_vs_b"]["same"]) == 9
