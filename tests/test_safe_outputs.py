from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import audit, checkout as co, cli, search, vault
from decisis import sandbox as sb

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
IMPACT_SNAPSHOT = FIX / "impact" / "vinc.json"
AUDIT_SNAPSHOT = FIX / "audit" / "vinc.json"
AUDIT_LOCK = FIX / "audit" / "demo-lockfile.json"
AUDIT_CACHE = FIX / "audit" / "osv-cache.json"
CHECK_SNAPSHOT = FIX / "check" / "vinc.json"
CHECK_REPO = FIX / "check" / "repo"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def keep_args(name: str, snapshot: Path) -> list[str]:
    if name == "paths":
        return ["paths", str(snapshot), "concept:demo-report-export", "decision:demo-report-exports-finish-in-time"]
    if name == "impact":
        return ["impact", str(snapshot), "reports/export.py"]
    if name == "check":
        return ["check", str(snapshot), "--repo-dir", str(CHECK_REPO), "--changed", "src/payments/charge.py", "--reviewers", "@alice"]
    return ["audit", str(snapshot), str(AUDIT_LOCK), "--repo", "Demo", "--osv-cache", str(AUDIT_CACHE)]


SNAPSHOT_OF = {"paths": IMPACT_SNAPSHOT, "impact": IMPACT_SNAPSHOT, "check": CHECK_SNAPSHOT, "audit": AUDIT_SNAPSHOT}


def fails(argv: list[str], capsys) -> str:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2
    return capsys.readouterr().err


@pytest.mark.parametrize("name", ["paths", "impact", "check", "audit"])
def test_keep_graph_refuses_an_existing_file_unless_forced(name, tmp_path, capsys, no_network):
    kept = tmp_path / "kept.rl"
    kept.write_bytes(b"precious")
    err = fails([*keep_args(name, SNAPSHOT_OF[name]), "--keep-graph", str(kept)], capsys)
    assert "already exists" in err and "--force" in err
    assert kept.read_bytes() == b"precious"
    assert cli.main([*keep_args(name, SNAPSHOT_OF[name]), "--keep-graph", str(kept), "--force"]) == 0
    capsys.readouterr()
    assert kept.read_bytes()[:8] == b"MDBCLB01"


@pytest.mark.parametrize("name", ["paths", "impact", "check", "audit"])
def test_keep_graph_never_overwrites_the_input_snapshot(name, tmp_path, capsys, no_network):
    snapshot = tmp_path / "snapshot.rl"
    snapshot.write_bytes(SNAPSHOT_OF[name].read_bytes())
    before = digest(snapshot)
    err = fails([*keep_args(name, snapshot), "--keep-graph", str(snapshot), "--force"], capsys)
    assert "input" in err
    assert digest(snapshot) == before


def test_keep_graph_never_overwrites_the_lockfile(tmp_path, capsys, no_network):
    lock = tmp_path / "lock.rl"
    lock.write_bytes(AUDIT_LOCK.read_bytes())
    err = fails(["audit", str(AUDIT_SNAPSHOT), str(lock), "--repo", "Demo", "--osv-cache", str(AUDIT_CACHE),
                 "--keep-graph", str(lock), "--force"], capsys)
    assert "input" in err and lock.read_bytes() == AUDIT_LOCK.read_bytes()


def test_keep_graph_refuses_a_name_without_rl(tmp_path, capsys, no_network):
    kept = tmp_path / "graph.json"
    err = fails([*keep_args("impact", IMPACT_SNAPSHOT), "--keep-graph", str(kept)], capsys)
    assert ".rl" in err and not kept.exists()


def test_sandbox_save_refuses_an_existing_file(tmp_path):
    kept = tmp_path / "x.rl"
    kept.write_bytes(b"keep")
    graph = co.load(IMPACT_SNAPSHOT.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="already exists"):
        with sb.sandbox(tmp_path, keep_graph=kept) as box:
            box.load(graph)
    assert kept.read_bytes() == b"keep"
    with sb.sandbox(tmp_path, keep_graph=kept, force=True) as box:
        box.load(graph)
    assert kept.read_bytes()[:8] == b"MDBCLB01"


def test_export_vault_force_refuses_a_directory_without_the_marker(tmp_path, capsys, no_network):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "important.py").write_text("print(1)\n", encoding="utf-8")
    err = fails(["export-vault", str(IMPACT_SNAPSHOT), "--out", str(project), "--force"], capsys)
    assert vault.MARKER in err
    assert (project / "src" / "important.py").read_text(encoding="utf-8") == "print(1)\n"


def test_export_vault_refuses_the_current_directory(tmp_path, capsys, monkeypatch, no_network):
    here = tmp_path / "cwd"
    (here / "keep").mkdir(parents=True)
    (here / "keep" / "f.txt").write_text("x", encoding="utf-8")
    (here / vault.MARKER).write_text("{}", encoding="utf-8")
    monkeypatch.chdir(here)
    err = fails(["export-vault", str(IMPACT_SNAPSHOT), "--out", ".", "--force"], capsys)
    assert "current directory" in err
    assert (here / "keep" / "f.txt").is_file()


def test_export_vault_refuses_home_root_and_input_parents(tmp_path, capsys, monkeypatch, no_network):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert "home directory" in fails(["export-vault", str(IMPACT_SNAPSHOT), "--out", str(home), "--force"], capsys)
    assert "root" in fails(["export-vault", str(IMPACT_SNAPSHOT), "--out", "/", "--force"], capsys)
    data = tmp_path / "data"
    data.mkdir()
    snap = data / "snap.json"
    snap.write_bytes(IMPACT_SNAPSHOT.read_bytes())
    (data / vault.MARKER).write_text("{}", encoding="utf-8")
    assert "input" in fails(["export-vault", str(snap), "--out", str(data), "--force"], capsys)
    assert "input" in fails(["export-vault", str(snap), "--out", str(tmp_path), "--force"], capsys)
    assert snap.is_file()


def test_export_vault_force_replaces_a_decisis_vault(tmp_path, capsys, no_network):
    out = tmp_path / "v"
    assert cli.main(["export-vault", str(IMPACT_SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    assert (out / vault.MARKER).is_file()
    assert cli.main(["export-vault", str(AUDIT_SNAPSHOT), "--out", str(out), "--force"]) == 0
    capsys.readouterr()
    assert (out / vault.MARKER).is_file()
    assert cli.main(["query", str(out), "MATCH (d:Decision) RETURN d.id AS id ORDER BY id"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["rows"]]
    assert ids == sorted(n["id"] for n in json.loads(AUDIT_SNAPSHOT.read_text(encoding="utf-8"))["nodes"] if n["kind"] == "decision")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["v"]


def test_audit_export_vault_refuses_a_full_directory_before_the_audit(tmp_path, capsys, monkeypatch, no_network):
    full = tmp_path / "full"
    full.mkdir()
    (full / "notes.txt").write_text("mine", encoding="utf-8")
    monkeypatch.setattr(audit, "compose", lambda *a, **k: pytest.fail("the audit ran before the vault target was checked"))
    err = fails([*keep_args("audit", AUDIT_SNAPSHOT), "--export-vault", str(full)], capsys)
    assert "not empty" in err and (full / "notes.txt").read_text(encoding="utf-8") == "mine"


def write_snapshot(path: Path, nodes: list[dict], edges: list[dict]) -> Path:
    path.write_text(json.dumps({"meta": {}, "nodes": nodes, "edges": edges}), encoding="utf-8")
    return path


def node(nid: str, kind: str, title: str, **props) -> dict:
    return {"id": nid, "kind": kind, "title": title, "props": props}


def test_export_vault_with_a_repeated_id_writes_nothing(tmp_path, capsys, no_network):
    snap = write_snapshot(tmp_path / "dup.json", [node("decision:a", "decision", "A"), node("decision:a", "decision", "dup")], [])
    out = tmp_path / "v"
    err = fails(["export-vault", str(snap), "--out", str(out)], capsys)
    assert "decision:a" in err and "repeated" in err
    assert not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dup.json"]


def test_export_vault_with_a_repeated_id_keeps_the_old_vault(tmp_path, capsys, no_network):
    out = tmp_path / "v"
    assert cli.main(["export-vault", str(IMPACT_SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    before = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.md"))
    snap = write_snapshot(tmp_path / "dup.json", [node("decision:a", "decision", "A"), node("decision:a", "decision", "dup")], [])
    fails(["export-vault", str(snap), "--out", str(out), "--force"], capsys)
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*.md")) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dup.json", "v"]


def test_export_vault_refuses_a_dangling_edge_like_the_sandbox(tmp_path, capsys, no_network):
    snap = write_snapshot(tmp_path / "dangling.json", [node("decision:a", "decision", "A"), node("concept:b", "concept", "B")],
                          [{"source": "decision:a", "target": "concept:b", "type": "ABOUT"},
                           {"source": "decision:a", "target": "concept:missing", "type": "ABOUT"}])
    with pytest.raises(sb.LoadMismatch, match="concept:missing"):
        vault.export(co.load(snap.read_text(encoding="utf-8")), tmp_path / "v")
    assert not (tmp_path / "v").exists()
    assert "concept:missing" in fails(["export-vault", str(snap), "--out", str(tmp_path / "v")], capsys)


def test_export_vault_refuses_one_id_under_two_kinds(tmp_path, capsys, no_network):
    snap = write_snapshot(tmp_path / "cross.json", [node("x:a", "decision", "A"), node("x:a", "concept", "B")], [])
    with pytest.raises(sb.LoadMismatch, match="x:a"):
        vault.export(co.load(snap.read_text(encoding="utf-8")), tmp_path / "v")
    assert not (tmp_path / "v").exists()


def test_export_vault_reports_the_edges_it_wrote(tmp_path, capsys, no_network):
    out = tmp_path / "v"
    assert cli.main(["export-vault", str(IMPACT_SNAPSHOT), "--out", str(out)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert cli.main(["query", str(out), "MATCH ()-[r]->() RETURN count(r) AS c"]) == 0
    assert json.loads(capsys.readouterr().out)["rows"][0]["c"] == result["edges"]
    assert cli.main(["query", str(out), "MATCH (n) RETURN count(n) AS c"]) == 0
    assert json.loads(capsys.readouterr().out)["rows"][0]["c"] == result["nodes"]


def test_vault_keeps_name_body_and_matches_the_saved_graph(tmp_path, capsys, no_network):
    kept, out = tmp_path / "a.rl", tmp_path / "v"
    assert cli.main([*keep_args("audit", AUDIT_SNAPSHOT), "--keep-graph", str(kept), "--export-vault", str(out)]) == 0
    capsys.readouterr()
    for q in ("MATCH (p:Package) WHERE p.name = 'lodash' RETURN p.id AS id ORDER BY id",
              "MATCH (p:Package) RETURN p.id AS id, p.name AS name, p.version AS version ORDER BY id",
              "MATCH (n) RETURN n.id AS id, n.title AS title, n.body AS body ORDER BY id"):
        assert cli.main(["query", str(kept), q]) == 0
        saved = json.loads(capsys.readouterr().out)["rows"]
        assert cli.main(["query", str(out), q]) == 0
        assert json.loads(capsys.readouterr().out)["rows"] == saved
    assert len(saved) > 5


def test_vault_keeps_props_called_name_body_and_id(tmp_path, capsys, no_network):
    snap = write_snapshot(tmp_path / "s.json", [node("concept:a", "concept", "A", name="Alpha", body="raw body", id="concept:a"),
                                                node("concept:b", "concept", "B", name="Alpha")], [])
    out = tmp_path / "v"
    assert cli.main(["export-vault", str(snap), "--out", str(out)]) == 0
    capsys.readouterr()
    assert cli.main(["query", str(out), "MATCH (c:Concept) RETURN c.id AS id, c.name AS name, c.body AS body ORDER BY id"]) == 0
    assert json.loads(capsys.readouterr().out)["rows"] == [{"id": "concept:a", "name": "Alpha", "body": "raw body"},
                                                           {"id": "concept:b", "name": "Alpha", "body": None}]
    note = (out / "Concept" / "a.md").read_text(encoding="utf-8")
    assert "# A" in note


def test_vault_refuses_a_prop_id_that_differs_from_the_node_id(tmp_path, capsys, no_network):
    snap = write_snapshot(tmp_path / "s.json", [node("concept:a", "concept", "A", id="concept:other")], [])
    assert "concept:a" in fails(["export-vault", str(snap), "--out", str(tmp_path / "v")], capsys)
    assert not (tmp_path / "v").exists()


def test_vault_refuses_props_that_use_its_own_keys(tmp_path, capsys, no_network):
    snap = write_snapshot(tmp_path / "s.json", [node("concept:a", "concept", "A", **{vault.FILE_KEY: "x"})], [])
    assert vault.FILE_KEY in fails(["export-vault", str(snap), "--out", str(tmp_path / "v")], capsys)


def kind_cap_graph() -> sb.Subgraph:
    nodes = [node(f"concept:c{i:03d}", "concept", "storage storage storage", body="storage") for i in range(150)]
    nodes.append(node("decision:lonely", "decision", "a long title that mentions storage once among many other words"))
    return sb.Subgraph(nodes, [])


def test_search_kind_filter_finds_a_match_outranked_by_other_kinds():
    report = search.run(kind_cap_graph(), "storage", kinds=["decision"])
    assert [m["id"] for m in report["matches"]] == ["decision:lonely"]
    assert "cut" not in report


def test_search_says_when_matches_were_cut():
    report = search.run(kind_cap_graph(), "storage", limit=20, kinds=["concept"])
    assert report["match_count"] == 20 and "cut" in report
    assert "cut" not in search.run(kind_cap_graph(), "storage", limit=100, kinds=["decision", "record"])
    assert "more" in search.render(report)


def test_search_cli_kind_filter(tmp_path, capsys):
    snap = tmp_path / "kindcap.json"
    g = kind_cap_graph()
    snap.write_text(json.dumps({"meta": {}, "nodes": g.nodes, "edges": []}), encoding="utf-8")
    assert cli.main(["search", str(snap), "storage", "--kind", "decision", "--format", "text"]) == 0
    assert "decision:lonely" in capsys.readouterr().out


def test_mcp_search_kinds_find_a_match_outranked_by_other_kinds(tmp_path):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    snap = tmp_path / "kindcap.json"
    g = kind_cap_graph()
    snap.write_text(json.dumps({"meta": {}, "nodes": g.nodes, "edges": []}), encoding="utf-8")
    tools = serve.load_tools(snap, tmp_path, None)
    found = tools.call("search", {"query": "storage", "kinds": ["decision"], "detail": "full"})
    assert [m["id"] for m in found["matches"]] == ["decision:lonely"]
    cut = tools.call("search", {"query": "storage", "kinds": ["concept"], "limit": 5})
    assert "cut" in cut


def test_query_on_a_saved_graph_or_vault_keeps_the_size_caps(tmp_path, capsys, no_network):
    kept, out = tmp_path / "a.rl", tmp_path / "v"
    assert cli.main(["impact", str(IMPACT_SNAPSHOT), "reports/export.py", "--keep-graph", str(kept)]) == 0
    assert cli.main(["export-vault", str(IMPACT_SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    for store in (kept, out):
        for flag in ("--max-nodes", "--max-edges"):
            with pytest.raises(SystemExit) as exc:
                cli.main(["query", str(store), "MATCH (n) RETURN count(n) AS c", flag, "1"])
            assert exc.value.code == 1 and "over the cap" in capsys.readouterr().err
        assert cli.main(["query", str(store), "MATCH (n) RETURN count(n) AS c"]) == 0
        capsys.readouterr()
