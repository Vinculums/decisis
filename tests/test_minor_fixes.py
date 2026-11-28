from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from decisis import cli, compare, search
from decisis import sandbox as sb

ROOT = Path(__file__).resolve().parents[1]


def node(nid: str, kind: str, title: str, **props) -> dict:
    return {"id": nid, "kind": kind, "title": title, "props": props}


def ids(report: dict) -> list[str]:
    return sorted(m["id"] for m in report["matches"])


WORDS = sb.Subgraph([node("decision:a", "decision", "storage storage"), node("decision:b", "decision", "storage pages"),
                     node("decision:e", "decision", "pages only"), node("record:c", "RECORD", "storage"),
                     node("concept:k", "Concept", "데이터베이스를 바꾼다"), node("decision:r", "decision", "결제 시스템은 🚀 빠르다")], [])


def test_search_plus_requires_a_word():
    report = search.run(WORDS, "+storage +pages")
    assert ids(report) == ["decision:b"]
    assert report["query"] == "+storage +pages"


def test_search_minus_excludes_a_word():
    assert ids(search.run(WORDS, "storage -pages")) == ["decision:a", "record:c"]
    assert ids(search.run(WORDS, "+storage pages")) == ["decision:a", "decision:b", "record:c"]


def test_search_refuses_a_query_of_only_excluded_words():
    with pytest.raises(ValueError, match="excluded"):
        search.run(WORDS, "-pages")


def test_search_keeps_hyphenated_words():
    graph = sb.Subgraph([node("decision:d", "decision", "dead-code sweep")], [])
    assert ids(search.run(graph, "dead-code")) == ["decision:d"]


def test_search_indexes_kinds_written_in_upper_case():
    assert ids(search.run(WORDS, "storage", kinds=["record"])) == ["record:c"]
    assert ids(search.run(WORDS, "데이터베이스", kinds=["concept"])) == ["concept:k"]


def test_search_finds_a_korean_word_written_with_a_particle():
    assert ids(search.run(WORDS, "데이터베이스")) == ["concept:k"]
    assert ids(search.run(WORDS, "결제")) == ["decision:r"]


def test_search_refuses_a_query_with_no_words():
    with pytest.raises(ValueError, match="no letters or digits"):
        search.run(WORDS, "🚀")
    assert ids(search.run(WORDS, "시스템은")) == ["decision:r"]


def test_mcp_schema_errors_do_not_echo_the_whole_input():
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    long = "x" * 20000
    with pytest.raises(serve.Refused) as exc:
        serve.validated("query", {"cypher": long})
    text = str(exc.value)
    assert text.startswith("query: cypher:") and len(text) < 400 and "20000 characters" in text
    with pytest.raises(serve.Refused) as exc:
        serve.validated("search", {"query": "a", "kinds": ["nope"]})
    assert "kinds/0" in str(exc.value) and "nope" in str(exc.value)


def test_the_readme_does_not_tell_pip_users_to_run_relate_serve():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "relate serve" not in text


def test_version_flag_prints_the_installed_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("decisis ") and out.split()[1][0].isdigit()


def test_load_mismatch_with_equal_counts_names_the_problem_first(tmp_path):
    graph = sb.Subgraph([node("x:a", "decision", "A"), node("x:a", "concept", "B")], [])
    with sb.sandbox(tmp_path) as box:
        with pytest.raises(sb.LoadMismatch) as exc:
            box.load(graph)
    text = str(exc.value)
    assert text.startswith("the snapshot cannot be loaded: repeated node ids: x:a (decision, concept)")
    assert "but the snapshot has" not in text


def test_compare_finds_holdout_inputs_next_to_the_tasks_file(tmp_path, monkeypatch):
    copy = tmp_path / "checkout"
    shutil.copytree(ROOT / "bench", copy / "bench")
    elsewhere = tmp_path / "site-packages" / "decisis"
    elsewhere.mkdir(parents=True)
    tasks = copy / "bench" / "holdout" / "tasks.json"
    assert compare.root_for(tasks, json.loads(tasks.read_text(encoding="utf-8")), elsewhere) == copy


def test_compare_says_where_the_inputs_are_missing(tmp_path):
    tasks = tmp_path / "tasks.json"
    doc = json.loads((ROOT / "bench" / "holdout" / "tasks.json").read_text(encoding="utf-8"))
    tasks.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError, match="checkout"):
        compare.root_for(tasks, doc, tmp_path)


@pytest.mark.parametrize("bad", [None, True, 1.5, ["a"], {"a": 1}, ""])
def test_sandbox_load_refuses_ids_that_are_not_text_or_whole_numbers(tmp_path, bad):
    with sb.sandbox(tmp_path) as box:
        with pytest.raises(ValueError, match="node id"):
            box.load(sb.Subgraph([{"id": bad, "kind": "decision", "title": "", "props": {}}], []))
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("decisis-")]


def test_sandbox_load_still_takes_text_and_whole_number_ids(tmp_path):
    with sb.sandbox(tmp_path) as box:
        assert box.load(sb.Subgraph([node("d:a", "decision", "A"), {"id": 7, "kind": "decision", "title": "", "props": {}}], [])) == {"nodes": 2, "edges": 0}
