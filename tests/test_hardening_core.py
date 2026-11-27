from __future__ import annotations

import json
from pathlib import Path

import pytest

from decisis import checkout as co
from decisis import cli, cypher
from decisis import commit as wb
from decisis.sandbox import LoadMismatch, NotReadOnly, Subgraph, sandbox

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vinc_subgraph.json"


def test_props_cannot_overwrite_reserved_title_or_domain_and_input_props_stay_intact(tmp_path):
    props = {"title": "forged-title", "domain": "forged-domain", "status": "accepted"}
    g = Subgraph([{"id": "decision:a", "kind": "decision", "title": "Real title", "domain": "real/domain", "props": props}], [], {})
    with sandbox(tmp_path) as box:
        assert box.load(g) == {"nodes": 1, "edges": 0}
        rows = box.query("MATCH (n:Decision {id: 'decision:a'}) RETURN n.id AS id, n.title AS title, n.domain AS domain, n.status AS status")
    assert rows == [{"id": "decision:a", "title": "Real title", "domain": "real/domain", "status": "accepted"}]
    assert props == {"title": "forged-title", "domain": "forged-domain", "status": "accepted"}


def test_props_overriding_id_fails_load_even_with_zero_edges(tmp_path):
    g = Subgraph([{"id": "decision:a", "kind": "decision", "title": "A", "props": {"id": "decision:b"}}], [], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="node props overrode id: decision:a"):
            box.load(g)


def test_duplicate_node_ids_fail_load_with_zero_edges(tmp_path):
    same_kind = Subgraph([{"id": "concept:dup", "kind": "concept", "props": {}}, {"id": "concept:dup", "kind": "concept", "props": {}}], [], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="repeated node ids: concept:dup"):
            box.load(same_kind)
    diff_kind = Subgraph([{"id": "concept:dup", "kind": "concept", "props": {}}, {"id": "concept:dup", "kind": "decision", "props": {}}], [], {})
    with sandbox(tmp_path) as box:
        with pytest.raises(LoadMismatch, match="repeated node ids: concept:dup"):
            box.load(diff_kind)


@pytest.mark.parametrize("raw", [
    "{not json",
    "null",
    "[]",
    "123",
    '"text"',
    "true",
    json.dumps({"meta": None, "nodes": [], "edges": []}),
    json.dumps({"meta": [], "nodes": [], "edges": []}),
    json.dumps({"meta": "bad", "nodes": [], "edges": []}),
    json.dumps({"edges": []}),
    json.dumps({"nodes": []}),
    json.dumps({"nodes": {}, "edges": []}),
    json.dumps({"nodes": [], "edges": {}}),
    json.dumps({"meta": {"nodes": True}, "nodes": [{"id": "a", "kind": "concept"}], "edges": []}),
    json.dumps({"meta": {"edges": False}, "nodes": [], "edges": []}),
    json.dumps({"nodes": ["not-a-dict"], "edges": []}),
    json.dumps({"nodes": [{"kind": "concept"}], "edges": []}),
    json.dumps({"nodes": [{"id": 1, "kind": "concept"}], "edges": []}),
    json.dumps({"nodes": [{"id": "a"}], "edges": []}),
    json.dumps({"nodes": [{"id": "a", "kind": 1}], "edges": []}),
    json.dumps({"nodes": [{"id": "a", "kind": "concept", "props": []}], "edges": []}),
    json.dumps({"nodes": [{"id": "a", "kind": "concept", "props": "bad"}], "edges": []}),
    json.dumps({"nodes": [], "edges": ["not-a-dict"]}),
    json.dumps({"nodes": [], "edges": [{"target": "b", "type": "REL"}]}),
    json.dumps({"nodes": [], "edges": [{"source": 1, "target": "b", "type": "REL"}]}),
    json.dumps({"nodes": [], "edges": [{"source": "a", "type": "REL"}]}),
    json.dumps({"nodes": [], "edges": [{"source": "a", "target": 2, "type": "REL"}]}),
    json.dumps({"nodes": [], "edges": [{"source": "a", "target": "b"}]}),
    json.dumps({"nodes": [], "edges": [{"source": "a", "target": "b", "type": 3}]}),
])
def test_checkout_load_rejects_malformed_snapshots_with_value_error(raw):
    with pytest.raises(ValueError):
        co.load(raw)


def test_checkout_load_accepts_minimal_valid_snapshot_with_null_props():
    g = co.load(json.dumps({"nodes": [{"id": "concept:a", "kind": "concept", "props": None}], "edges": []}))
    assert g.meta == {} and len(g.nodes) == 1 and g.edges == []


def test_cli_exits_1_without_traceback_for_missing_or_non_utf8_files(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.json"
    with pytest.raises(SystemExit) as e:
        cli.main(["query", str(missing), "RETURN 1 AS x"])
    err = capsys.readouterr().err
    assert e.value.code == 1 and "decisis: error:" in err and "Traceback" not in err

    bad_utf8 = tmp_path / "bad.json"
    bad_utf8.write_bytes(b"\xff\xfe\xfd")
    with pytest.raises(SystemExit) as e:
        cli.main(["query", str(bad_utf8), "RETURN 1 AS x"])
    err = capsys.readouterr().err
    assert e.value.code == 1 and "decisis: error:" in err and "Traceback" not in err

    with pytest.raises(SystemExit) as e:
        cli.main(["commit", str(missing), "--approve", "0" * 16])
    err = capsys.readouterr().err
    assert e.value.code == 1 and "decisis: error:" in err and "Traceback" not in err


@pytest.mark.parametrize("bad_report", [
    None,
    [],
    "text",
    123,
    {"meta": "bad", "findings": []},
    {"findings": None},
    {"findings": {}},
    {"findings": "bad"},
    {"findings": ["not-a-dict"]},
    {"findings": [1]},
])
def test_commit_propose_rejects_invalid_report_schema(bad_report):
    with pytest.raises(ValueError):
        wb.propose(bad_report, "Demo", "space-1")


@pytest.mark.parametrize("bad_plan", [
    None,
    [],
    "text",
    123,
    {"nodes": [], "edges": [], "digest": "a"},
    {"space": 123, "nodes": [], "edges": [], "digest": "a"},
    {"space": "s", "edges": [], "digest": "a"},
    {"space": "s", "nodes": {}, "edges": [], "digest": "a"},
    {"space": "s", "nodes": [], "digest": "a"},
    {"space": "s", "nodes": [], "edges": "bad", "digest": "a"},
    {"space": "s", "nodes": [], "edges": []},
    {"space": "s", "nodes": [], "edges": [], "digest": 123},
])
def test_commit_check_approval_rejects_invalid_plan_schema(bad_plan):
    with pytest.raises(ValueError):
        wb.check_approval(bad_plan, "a")


def test_cli_commit_rejects_malformed_plan_without_traceback(tmp_path, capsys):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.main(["commit", str(plan), "--approve", "0" * 16])
    err = capsys.readouterr().err
    assert e.value.code == 2 and "Traceback" not in err


def test_cypher_check_enforces_max_cypher_bytes(capsys):
    prefix = "RETURN '"
    suffix = "' AS s"
    exact = prefix + ("a" * (cypher.MAX_CYPHER - len(prefix) - len(suffix))) + suffix
    assert len(exact.encode("utf-8")) == cypher.MAX_CYPHER
    cypher.check(exact)

    too_long = exact + " "
    assert len(too_long.encode("utf-8")) == cypher.MAX_CYPHER + 1
    with pytest.raises(NotReadOnly, match=f"longer than {cypher.MAX_CYPHER} bytes"):
        cypher.check(too_long)

    multibyte = "RETURN '" + ("é" * (cypher.MAX_CYPHER // 2 + 1)) + "' AS s"
    assert len(multibyte) < cypher.MAX_CYPHER and len(multibyte.encode("utf-8")) > cypher.MAX_CYPHER
    with pytest.raises(NotReadOnly, match=f"longer than {cypher.MAX_CYPHER} bytes"):
        cypher.check(multibyte)

    with pytest.raises(SystemExit) as e:
        cli.main(["query", str(FIXTURE), too_long])
    err = capsys.readouterr().err
    assert e.value.code == 2 and f"longer than {cypher.MAX_CYPHER} bytes" in err and "Traceback" not in err
