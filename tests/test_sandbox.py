from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
import relate

from decisis import checkout as co
from decisis.queries import load as query
from decisis import cli
from decisis.sandbox import LoadMismatch, Sandbox, sandbox

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vinc_subgraph.json"


def graph():
    return co.load(FIXTURE.read_text(encoding="utf-8"))


def test_the_task_file_lives_in_its_own_private_directory_and_is_gone_after(tmp_path):
    with sandbox(tmp_path) as box:
        box.load(graph())
        assert box.path.exists() and box.dir.stat().st_mode & 0o777 == 0o700
        kept = box.dir
    assert not kept.exists()


def test_load_counts_what_landed_and_a_multi_hop_path_comes_back(tmp_path):
    with sandbox(tmp_path) as box:
        assert box.load(graph()) == {"nodes": 5, "edges": 4}
        q = query("paths_between", hops=4, limit=5)
        rows = box.query(q, {"source": "record:tls-advisory-example", "target": "concept:service-api"})
    assert rows[0]["ids"] == ["record:tls-advisory-example", "concept:tls-stack", "concept:http-client-lib", "concept:service-api"]
    assert rows[0]["rels"] == ["RELATED_TO", "PREREQUISITE_OF", "PREREQUISITE_OF"]


def test_reasoning_reads_cannot_write(tmp_path):
    with sandbox(tmp_path) as box:
        box.load(graph())
        with pytest.raises(relate.OperationalError, match="WriteOnReadOnly"):
            box.query("CREATE (:X {id: 'x'})")


def test_an_open_writer_locks_out_both_a_second_writer_and_a_reader(tmp_path):
    box = Sandbox(tmp_path)
    try:
        writer = relate.connect(str(box.path))
        try:
            with pytest.raises(relate.OperationalError, match="storage locked"):
                relate.connect(str(box.path))
            with pytest.raises(relate.OperationalError, match="storage locked"):
                relate.connect(str(box.path), read_only=True)
        finally:
            writer.close()
    finally:
        box.destroy()


def test_a_sandbox_is_loaded_once(tmp_path):
    with sandbox(tmp_path) as box:
        box.load(graph())
        with pytest.raises(RuntimeError):
            box.load(graph())


def test_a_label_that_could_inject_cypher_is_refused(tmp_path):
    bad = co.Subgraph([{"id": "x", "kind": "1bad", "props": {}}], [], {})
    with sandbox(tmp_path) as box, pytest.raises(ValueError):
        box.load(bad)


def test_an_edge_with_a_missing_endpoint_fails_the_load_by_name(tmp_path):
    g = graph()
    broken = co.Subgraph(g.nodes, g.edges + [{"source": g.nodes[0]["id"], "target": "concept:not-there", "type": "RELATED_TO"}], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match=r"loaded 5 nodes and 4 edges, but the snapshot has 5 nodes and 5 edges.*concept:not-there"):
            box.load(broken)


def test_a_repeated_node_id_fails_the_load_by_name(tmp_path):
    g = graph()
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="repeated node ids: " + g.nodes[0]["id"]):
            box.load(co.Subgraph(g.nodes + [g.nodes[0]], g.edges, {}))


def test_a_node_id_repeated_under_two_kinds_still_fails_the_load(tmp_path):
    g = graph()
    twin = {**g.nodes[0], "kind": "Other"}
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="repeated node ids: " + g.nodes[0]["id"]):
            box.load(co.Subgraph(g.nodes + [twin], g.edges, {}))


def node(i: str, kind: str = "Thing", **props) -> dict:
    return {"id": i, "kind": kind, "title": i, "props": props}


def edge(s: str, t: str, kind: str = "REL") -> dict:
    return {"source": s, "target": t, "type": kind, "evidence": ""}


def test_an_edge_is_not_credited_to_a_node_whose_props_carry_its_id(tmp_path):
    g = co.Subgraph([node("decision:a", "decision", id="decision:b", status="accepted"), node("decision:b", "decision", status="accepted"),
                     node("concept:c", "concept")], [edge("decision:a", "concept:c", "about")], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="loaded 3 nodes and 0 edges, but the snapshot has 3 nodes and 1 edges"):
            box.load(g)


def test_a_props_id_that_overrides_the_node_id_fails_the_load(tmp_path):
    g = co.Subgraph([node("a", id="z"), node("b")], [edge("a", "b")], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="loaded 2 nodes and 0 edges, but the snapshot has 2 nodes and 1 edges"):
            box.load(g)


def test_a_props_id_that_collides_with_another_node_fails_the_load(tmp_path):
    g = co.Subgraph([node("a", id="b"), node("b"), node("c")], [edge("c", "b")], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="loaded 3 nodes and 2 edges, but the snapshot has 3 nodes and 1 edges"):
            box.load(g)


def chain(n: int) -> co.Subgraph:
    nodes = [{"id": "repo:Big", "kind": "Repository", "props": {}}]
    nodes += [{"id": f"pkg:npm/p{i}@1.0.0", "kind": "Package", "props": {"name": f"p{i}"}} for i in range(n)]
    edges = [{"source": "repo:Big", "target": f"pkg:npm/p{i}@1.0.0", "type": "DEPENDS_ON"} for i in range(0, n, 10)]
    edges += [{"source": f"pkg:npm/p{i}@1.0.0", "target": f"pkg:npm/p{i + 1}@1.0.0", "type": "DEPENDS_ON"} for i in range(n - 1)]
    return co.Subgraph(nodes, edges, {})


def test_a_lockfile_sized_graph_loads_in_seconds(tmp_path):
    big = chain(3000)
    start = time.perf_counter()
    with sandbox(tmp_path) as box:
        assert box.load(big) == {"nodes": len(big.nodes), "edges": len(big.edges)}
        rows = box.query("MATCH (:Repository {id: 'repo:Big'})-[:DEPENDS_ON]->(p:Package {id: 'pkg:npm/p10@1.0.0'})-[:DEPENDS_ON]->(q) RETURN q.id AS id")
    assert rows == [{"id": "pkg:npm/p11@1.0.0"}]
    assert time.perf_counter() - start < 10


def test_nodes_without_edges_load(tmp_path):
    with sandbox(tmp_path) as box:
        assert box.load(co.Subgraph(graph().nodes, [], {})) == {"nodes": 5, "edges": 0}


def test_paths_bounds_hops_and_limit_with_an_argparse_error(capsys):
    fixture = str(FIXTURE)
    for flag, value in [("--hops", "1000"), ("--hops", "0"), ("--limit", "0"), ("--limit", "100000"), ("--hops", "x")]:
        with pytest.raises(SystemExit) as e:
            cli.main(["paths", fixture, "record:tls-advisory-example", "concept:service-api", flag, value])
        err = capsys.readouterr().err
        assert e.value.code == 2 and f"argument {flag}" in err and "Traceback" not in err
    assert cli.main(["paths", fixture, "record:tls-advisory-example", "concept:service-api", "--hops", "6", "--limit", "100"]) == 0
    assert json.loads(capsys.readouterr().out)["paths"]


def test_the_cli_reports_a_count_mismatch_without_a_traceback(tmp_path, capsys):
    snap = json.loads(FIXTURE.read_text(encoding="utf-8"))
    snap["edges"].append({"source": "concept:service-api", "target": "concept:not-there", "type": "RELATED_TO"})
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(snap), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.main(["paths", str(bad), "record:tls-advisory-example", "concept:service-api"])
    err = capsys.readouterr().err
    assert e.value.code == 2 and "edges with a missing endpoint: concept:service-api -RELATED_TO-> concept:not-there" in err
