from __future__ import annotations

import time

import pytest
import relate

from decisis import audit
from decisis import sandbox as sb


def diamond(width: int, rounds: int) -> sb.Subgraph:
    nodes = [{"id": "repo:R", "kind": "Repository", "title": "R", "props": {}},
             {"id": "m0", "kind": "Package", "title": "m0", "props": {"dev": False}}]
    edges = [("repo:R", "m0", "DEPENDS_ON")]
    for d in range(1, rounds + 1):
        nodes.append({"id": f"m{d}", "kind": "Package", "title": f"m{d}", "props": {"dev": False}})
        for b in range(width):
            nodes.append({"id": f"b{d}_{b}", "kind": "Package", "title": f"b{d}_{b}", "props": {"dev": b == 0}})
            edges += [(f"m{d - 1}", f"b{d}_{b}", "DEPENDS_ON"), (f"b{d}_{b}", f"m{d}", "DEPENDS_ON")]
    nodes.append({"id": "adv:X", "kind": "Advisory", "title": "X", "props": {}})
    edges.append((f"m{rounds}", "adv:X", "AFFECTED_BY"))
    return sb.Subgraph(nodes, [{"source": s, "target": t, "type": k} for s, t, k in edges])


def dev_of(graph: sb.Subgraph):
    flags = {n["id"]: bool((n.get("props") or {}).get("dev")) for n in graph.nodes if n["kind"] == "Package"}
    return lambda nid: flags.get(nid, False)


def shipped_ok(path: list[str], is_dev) -> bool:
    return not any(is_dev(n) for n in path[1:])


@pytest.mark.parametrize("width,rounds", [(2, 3), (3, 4), (4, 5)])
def test_shipped_paths_match_the_python_search(tmp_path, width, rounds):
    graph = diamond(width, rounds)
    depth = 2 * rounds + 1
    is_dev = dev_of(graph)
    with sb.sandbox(tmp_path) as box:
        box.load(graph)
        with audit.shipped_steps(box, graph):
            rows = audit.advisory_paths(box, "R", depth)
            paths = audit.query_package_paths(box, "repo:R", {f"m{rounds}"}, depth)
    shipped = [r["path"] for r in rows if shipped_ok(r["path"][:-1], is_dev)]
    assert shipped and all(len(p) == depth + 2 for p in shipped)
    want = audit.package_paths(graph, "repo:R", {f"m{rounds}"}, depth, is_dev)[f"m{rounds}"]
    assert set(map(len, paths[f"m{rounds}"])) == set(map(len, want))
    assert any(shipped_ok(p, is_dev) for p in paths[f"m{rounds}"])


def test_shipped_paths_stay_fast_on_a_wide_diamond(tmp_path):
    graph = diamond(8, 6)
    with sb.sandbox(tmp_path) as box:
        box.load(graph)
        with audit.shipped_steps(box, graph):
            started = time.perf_counter()
            rows = audit.advisory_paths(box, "R", 13)
            audit.query_package_paths(box, "repo:R", {"m6"}, 13)
            spent = time.perf_counter() - started
    assert len(rows) == 2 and spent < 3


def test_shipped_steps_leave_no_edges_in_the_saved_graph(tmp_path):
    kept = tmp_path / "kept.rl"
    graph = diamond(2, 2)
    with sb.sandbox(tmp_path, keep_graph=kept) as box:
        box.load(graph)
        with audit.shipped_steps(box, graph):
            assert box.query(f"MATCH ()-[s:{audit.SHIPPED_STEP}]->() RETURN count(s) AS c")[0]["c"] > 0
    con = relate.connect(str(kept), read_only=True)
    try:
        assert con.execute("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"] == len(graph.edges)
    finally:
        con.close()


def test_a_snapshot_that_uses_the_shipped_step_type_is_refused(tmp_path):
    graph = diamond(2, 1)
    graph.edges.append({"source": "m0", "target": "m1", "type": audit.SHIPPED_STEP})
    with sb.sandbox(tmp_path) as box:
        box.load(graph)
        with pytest.raises(ValueError, match=audit.SHIPPED_STEP):
            with audit.shipped_steps(box, graph):
                pass
