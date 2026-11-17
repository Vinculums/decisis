from __future__ import annotations

from pathlib import Path

import pytest
import relate

from vinc_relate import checkout as co
from vinc_relate.cli import PATH_QUERY
from vinc_relate.sandbox import Sandbox, sandbox

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
        q = PATH_QUERY.replace("$hops", "4").replace("$limit", "5")
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
