from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from test_audit import advisories, lock
from test_check import judge_import
from decisis import audit, check, cli, impact, imports
from decisis import checkout as co
from decisis.sandbox import LoadMismatch, Subgraph

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def test_aliased_from_importlib_import_module_resolves_literal_and_marks_dynamic_unresolved(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/db.py": "",
        "pkg/ui.py": (
            "from importlib import import_module as im\n"
            "im('pkg.db')\n"
            "im(dynamic_var)\n"
            "im('.db')\n"
        ),
    }
    rule = {"from": ["pkg/**"], "to": ["pkg/db.py"]}
    got = judge_import(tmp_path, files, "pkg/ui.py", rule)
    assert got == [
        (1, "from importlib import import_module", "external", None, "not_violated"),
        (2, "pkg.db", "repository", "pkg/db.py", "violated"),
        (3, "im() with a computed name", "unresolved", None, "unresolved"),
        (4, ".db", "unresolved", None, "unresolved"),
    ]


def test_aliased_importlib_module_resolves_literal_and_marks_dynamic_unresolved(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/db.py": "",
        "pkg/ui.py": (
            "import importlib as il\n"
            "il.import_module('pkg.db')\n"
            "il.import_module(target)\n"
        ),
    }
    rule = {"from": ["pkg/**"], "to": ["pkg/db.py"]}
    got = judge_import(tmp_path, files, "pkg/ui.py", rule)
    assert got == [
        (1, "import importlib", "external", None, "not_violated"),
        (2, "pkg.db", "repository", "pkg/db.py", "violated"),
        (3, "import_module() with a computed name", "unresolved", None, "unresolved"),
    ]


def test_aliased_builtins_dunder_import_resolves_literal_and_marks_dynamic_unresolved(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/db.py": "",
        "pkg/ui.py": (
            "from builtins import __import__ as bi\n"
            "import builtins as b\n"
            "bi('pkg.db')\n"
            "bi(dynamic_name)\n"
            "b.__import__('pkg.db')\n"
        ),
    }
    rule = {"from": ["pkg/**"], "to": ["pkg/db.py"]}
    got = judge_import(tmp_path, files, "pkg/ui.py", rule)
    assert got == [
        (1, "from builtins import __import__", "external", None, "not_violated"),
        (2, "import builtins", "external", None, "not_violated"),
        (3, "pkg.db", "repository", "pkg/db.py", "violated"),
        (4, "bi() with a computed name", "unresolved", None, "unresolved"),
        (5, "pkg.db", "repository", "pkg/db.py", "violated"),
    ]


def test_reassigned_dynamic_import_alias_is_detected(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/db.py": "",
        "pkg/ui.py": (
            "import importlib as il\n"
            "loader = il.import_module\n"
            "loader('pkg.db')\n"
            "loader(dyn)\n"
        ),
    }
    rule = {"from": ["pkg/**"], "to": ["pkg/db.py"]}
    got = judge_import(tmp_path, files, "pkg/ui.py", rule)
    assert got == [
        (1, "import importlib", "external", None, "not_violated"),
        (3, "pkg.db", "repository", "pkg/db.py", "violated"),
        (4, "loader() with a computed name", "unresolved", None, "unresolved"),
    ]


@pytest.mark.parametrize("bad", ["\x00", "src/a.py\x00", "\x00src/a.py", "src/\x00/a.py"])
def test_check_normal_rejects_nul_byte(bad):
    with pytest.raises(ValueError, match="inside the repository"):
        check.normal(bad)


def test_check_run_and_cli_reject_changed_path_with_nul_byte(tmp_path, capsys):
    snap_path = FIX / "check" / "vinc.json"
    g = co.load(snap_path.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="inside the repository"):
        check.run(g, ["src/payments/charge.py\x00"], FIX / "check" / "repo")
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", str(snap_path), "--repo-dir", str(FIX / "check" / "repo"), "--changed", "src/a.py\x00"])
    assert exc.value.code == 2 and "inside the repository" in capsys.readouterr().err


def test_governance_links_supports_list_and_case_insensitive_repo_with_at_most_one_edge():
    nodes = [
        {"id": "concept:one", "kind": "concept", "props": {"code_ref": "demo:src/a.py"}},
        {"id": "concept:two", "kind": "concept", "props": {"code_ref": ["Other:lib/", "DEMO:src/b.py", "demo:src/c.py", 123]}},
        {"id": "concept:exact", "kind": "concept", "props": {"code_ref": ["dEmO"]}},
        {"id": "concept:miss", "kind": "concept", "props": {"code_ref": ["DemoExtra:src/", "other:src/"]}},
        {"id": "concept:empty", "kind": "concept", "props": {}},
    ]
    links = audit.governance_links(nodes, "Demo")
    assert links == [
        {"source": "repo:Demo", "target": "concept:one", "type": "DESCRIBED_BY", "evidence": "concept:one has code_ref demo:src/a.py"},
        {"source": "repo:Demo", "target": "concept:two", "type": "DESCRIBED_BY", "evidence": "concept:two has code_ref DEMO:src/b.py"},
        {"source": "repo:Demo", "target": "concept:exact", "type": "DESCRIBED_BY", "evidence": "concept:exact has code_ref dEmO"},
    ]


def test_audit_run_links_decisions_through_list_code_ref_and_different_repo_case():
    snap = json.loads((FIX / "audit" / "vinc.json").read_text(encoding="utf-8"))
    for n in snap["nodes"]:
        if n["id"] == "concept:demo-app":
            n["props"]["code_ref"] = ["Other:unrelated/", "demo:src/app", "DEMO:src/other"]
    rep = audit.run(co.load(json.dumps(snap)), lock(), "Demo", advisories=advisories())
    assert rep["meta"]["governance_links"] == 1
    assert rep["violations"] > 0
    assert {d["decision"] for d in rep["governing"]} == {
        "decision:no-high-advisories-in-shipped-dependencies",
        "decision:dependencies-are-pinned-by-a-lockfile",
    }


def test_audit_compose_rejects_snapshot_with_existing_repo_node():
    snap = json.loads((FIX / "audit" / "vinc.json").read_text(encoding="utf-8"))
    snap["nodes"].append({"id": "repo:Demo", "kind": "Repository", "title": "Existing", "props": {}})
    g = Subgraph(snap["nodes"], snap["edges"], snap.get("meta") or {})
    with pytest.raises(ValueError, match=r"the snapshot already has a node with id repo:Demo"):
        audit.compose(g, lock(), "Demo", advisories=advisories())
    with pytest.raises(ValueError, match=r"the snapshot already has a node with id repo:Demo"):
        audit.run(g, lock(), "Demo", advisories=advisories())


@pytest.mark.parametrize("edge,missing", [
    ({"source": "decision:ghost", "target": "concept:a", "type": "ABOUT", "evidence": ""}, "decision:ghost"),
    ({"source": "decision:d", "target": "concept:ghost", "type": "ABOUT", "evidence": ""}, "concept:ghost"),
    ({"source": "decision:d", "target": "decision:ghost", "type": "SUPERSEDES", "evidence": ""}, "decision:ghost"),
])
def test_impact_governance_edges_and_run_reject_dangling_edges(edge, missing, tmp_path):
    g = Subgraph(
        [
            {"id": "concept:a", "kind": "concept", "title": "A", "props": {"code_ref": "a.py"}},
            {"id": "decision:d", "kind": "decision", "title": "D", "props": {}},
        ],
        [edge],
        {},
    )
    with pytest.raises(LoadMismatch, match=missing):
        impact.governance_edges(g)
    with pytest.raises(LoadMismatch, match=missing):
        impact.run(g, ["a.py"], root=tmp_path)


def test_impact_cli_reports_dangling_edge_with_exit_2(tmp_path, capsys):
    snap = json.loads((FIX / "impact" / "vinc.json").read_text(encoding="utf-8"))
    snap["edges"].append({"source": "decision:demo-report-exports-finish-in-time", "target": "concept:missing", "type": "ABOUT", "evidence": ""})
    snap["meta"]["edges"] = len(snap["edges"])
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(snap), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.main(["impact", str(bad), "reports/export.py"])
    err = capsys.readouterr().err
    assert exc.value.code == 2 and "concept:missing" in err and "Traceback" not in err


@pytest.mark.parametrize("value,want", [
    ("2026-11-27T00:30:00+09:00", datetime.date(2026, 11, 26)),
    ("2026-11-27T00:30:00+0900", datetime.date(2026, 11, 26)),
    ("2026-11-27T00:30:00+09", datetime.date(2026, 11, 26)),
    ("2026-11-26T23:30:00-02:00", datetime.date(2026, 11, 27)),
    ("2026-11-27T00:30:00Z", datetime.date(2026, 11, 27)),
    ("2026-11-27T25:99:99Z", None),
    ("2026-11-27T24:00:00Z", None),
    ("2026-11-27T10:60:00Z", None),
    ("2026-11-27T10:00:60Z", None),
    ("2026-11-27T10:00:00+25:00", None),
    ("2026-11-27T10:00:00+00:60", None),
    ("2026-02-30T10:00:00Z", None),
    ("2026T10:00", None),
    ("2026-11T10:00", None),
    ("0001-01-01T00:00:00+05:00", None),
])
def test_until_of_validates_clock_time_and_converts_offset_to_utc_date(value, want):
    assert impact.until_of(value) == want


def test_impact_run_closes_decision_using_utc_date_and_ignores_invalid_clock_time(tmp_path):
    g = Subgraph(
        [
            {"id": "concept:a", "kind": "concept", "title": "A", "props": {"code_ref": "a.py"}},
            {"id": "decision:tz", "kind": "decision", "title": "TZ", "props": {"valid_until": "2026-11-27T00:30:00+09:00"}},
            {"id": "decision:bad", "kind": "decision", "title": "Bad", "props": {"valid_until": "2026-11-27T25:99:99Z"}},
        ],
        [
            {"source": "decision:tz", "target": "concept:a", "type": "ABOUT", "evidence": ""},
            {"source": "decision:bad", "target": "concept:a", "type": "ABOUT", "evidence": ""},
        ],
        {},
    )
    rep = impact.run(g, ["a.py"], day=datetime.date(2026, 11, 26), root=tmp_path)["impact"][0]
    assert [i["id"] for i in rep["closed"]] == ["decision:tz"]
    assert [i["id"] for i in rep["governing"]] == ["concept:a", "decision:bad"]
