from __future__ import annotations

import json
from pathlib import Path

import pytest
import relate

from test_audit import no_network
from decisis import audit, checkout as co, cli, cycles, cypher, search, vault
from decisis import sandbox as sb

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
IMPACT_SNAPSHOT = FIX / "impact" / "vinc.json"
AUDIT_SNAPSHOT = FIX / "audit" / "vinc.json"
AUDIT_LOCK = FIX / "audit" / "demo-lockfile.json"
AUDIT_CACHE = FIX / "audit" / "osv-cache.json"
CHECK_SNAPSHOT = FIX / "check" / "vinc.json"
CHECK_REPO = FIX / "check" / "repo"


def test_cypher25_cycles_and_chains_match_python_finder(tmp_path):
    nodes = [
        {"id": "decision:a", "kind": "decision", "title": "A", "props": {"source_file": "docs/adr/0001-a.md"}},
        {"id": "decision:b", "kind": "decision", "title": "B", "props": {"source_file": "docs/adr/0002-b.md"}},
        {"id": "decision:c", "kind": "decision", "title": "C", "props": {"source_file": "docs/adr/0003-c.md"}},
        {"id": "decision:self", "kind": "decision", "title": "Self", "props": {"source_file": "docs/adr/0004-self.md"}},
        {"id": "decision:old", "kind": "decision", "title": "Old", "props": {"source_file": "docs/adr/0005-old.md"}},
        {"id": "decision:mid", "kind": "decision", "title": "Mid", "props": {"source_file": "docs/adr/0006-mid.md"}},
        {"id": "decision:new", "kind": "decision", "title": "New", "props": {"source_file": "docs/adr/0007-new.md"}},
    ]
    edges = [
        {"source": "decision:a", "target": "decision:b", "type": "SUPERSEDES"},
        {"source": "decision:b", "target": "decision:c", "type": "SUPERSEDES"},
        {"source": "decision:c", "target": "decision:a", "type": "SUPERSEDES"},
        {"source": "decision:self", "target": "decision:self", "type": "SUPERSEDES"},
        {"source": "decision:new", "target": "decision:mid", "type": "SUPERSEDES"},
        {"source": "decision:mid", "target": "decision:old", "type": "SUPERSEDES"},
    ]
    graph = sb.Subgraph(nodes, edges, {})
    with sb.sandbox(tmp_path) as box:
        box.load(graph)
        found = cycles.find_in(box, nodes)
        chains = cycles.chains_in(box)
    assert found == cycles.find(nodes, edges)
    assert [c.members for c in found] == [("decision:a", "decision:b", "decision:c"), ("decision:self",)]
    assert any(r["newer"] == "decision:new" and r["old"] == "decision:old" and r["hops"] == 2 for r in chains)


def test_sandbox_applies_unique_constraints_and_graph_type(tmp_path):
    kept = tmp_path / "schema.rl"
    graph = co.load(IMPACT_SNAPSHOT.read_text(encoding="utf-8"))
    with sb.sandbox(tmp_path, keep_graph=kept) as box:
        box.load(graph)
    assert kept.is_file()
    con = relate.connect(str(kept))
    try:
        constraints = [dict(r) for r in con.execute("SHOW CONSTRAINTS").fetchall()]
        labels = {c["labelsOrTypes"][0] for c in constraints if c["type"] == "NODE_PROPERTY_UNIQUENESS"}
        assert {"Concept", "Decision", "Record"} <= labels
        gtype = con.execute("SHOW CURRENT GRAPH TYPE").single()["specification"]
        assert "Decision" in gtype and "STRING NOT NULL" in gtype
        with pytest.raises(relate.IntegrityError):
            con.execute("CREATE (:Decision {id: 'decision:demo-oversized-pages-are-refused'})")
        with pytest.raises(relate.IntegrityError):
            con.execute("CREATE (:Decision {id: 12345})")
    finally:
        con.close()


def test_keep_graph_saves_rl_and_query_reads_it_read_only(tmp_path, capsys, no_network):
    saved = tmp_path / "saved" / "audit.rl"
    code = cli.main(["audit", str(AUDIT_SNAPSHOT), str(AUDIT_LOCK), "--repo", "Demo",
                     "--osv-cache", str(AUDIT_CACHE), "--keep-graph", str(saved)])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["saved_graph"] == str(saved) and saved.is_file()

    assert cli.main(["query", str(saved), "MATCH (d:Decision) RETURN count(d) AS c"]) == 0
    queried = json.loads(capsys.readouterr().out)
    assert queried["store"] == str(saved) and queried["rows"][0]["c"] >= 1

    with pytest.raises(SystemExit) as exc:
        cli.main(["query", str(saved), "MATCH (n) DETACH DELETE n"])
    assert exc.value.code == 2 and "writes to the graph" in capsys.readouterr().err


def test_keep_graph_works_for_paths_impact_and_check(tmp_path, capsys, no_network):
    p_rl = tmp_path / "paths.rl"
    i_rl = tmp_path / "impact.rl"
    c_rl = tmp_path / "check.rl"
    assert cli.main(["paths", str(IMPACT_SNAPSHOT), "concept:demo-report-export",
                     "decision:demo-report-exports-finish-in-time", "--keep-graph", str(p_rl)]) == 0
    assert json.loads(capsys.readouterr().out)["saved_graph"] == str(p_rl) and p_rl.is_file()

    assert cli.main(["impact", str(IMPACT_SNAPSHOT), "reports/export.py", "--keep-graph", str(i_rl)]) == 0
    assert json.loads(capsys.readouterr().out)["saved_graph"] == str(i_rl) and i_rl.is_file()

    assert cli.main(["check", str(CHECK_SNAPSHOT), "--repo-dir", str(CHECK_REPO),
                     "--changed", "src/payments/charge.py", "--reviewers", "@alice", "--keep-graph", str(c_rl)]) == 0
    assert json.loads(capsys.readouterr().out)["saved_graph"] == str(c_rl) and c_rl.is_file()


def test_export_vault_writes_obsidian_markdown_and_is_queryable(tmp_path, capsys, no_network):
    out_dir = tmp_path / "audit-vault"
    code = cli.main(["export-vault", str(AUDIT_SNAPSHOT), "--lockfile", str(AUDIT_LOCK),
                     "--repo", "Demo", "--osv-cache", str(AUDIT_CACHE), "--out", str(out_dir)])
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["codec"] == "markdown" and result["markdown_files"] > 5
    assert (out_dir / "index.md").is_file()
    assert list((out_dir / "Decision").glob("*.md"))
    assert list((out_dir / "Package").glob("*.md"))
    assert list((out_dir / "Advisory").glob("*.md"))
    decision_notes = [p.read_text(encoding="utf-8") for p in (out_dir / "Decision").glob("*.md") if p.name != "index.md"]
    assert any("[[" in text for text in decision_notes)

    assert cli.main(["query", str(out_dir),
                     "MATCH (r:Repository)-[:DEPENDS_ON]->(p:Package) RETURN count(p) AS c"]) == 0
    queried = json.loads(capsys.readouterr().out)
    assert queried["store"] == str(out_dir) and queried["rows"][0]["c"] >= 1

    with pytest.raises(SystemExit) as exc:
        cli.main(["export-vault", str(AUDIT_SNAPSHOT), "--out", str(out_dir)])
    assert exc.value.code == 2 and "already exists" in capsys.readouterr().err

    assert cli.main(["export-vault", str(AUDIT_SNAPSHOT), "--out", str(out_dir), "--force"]) == 0
    assert json.loads(capsys.readouterr().out)["codec"] == "markdown"


def test_audit_export_vault_flag(tmp_path, capsys, no_network):
    out_dir = tmp_path / "from-audit-vault"
    assert cli.main(["audit", str(AUDIT_SNAPSHOT), str(AUDIT_LOCK), "--repo", "Demo",
                     "--osv-cache", str(AUDIT_CACHE), "--export-vault", str(out_dir)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["vault"]["out"] == str(out_dir) and (out_dir / "index.md").is_file()


def test_query_profile_returns_plan_timings_and_notifications(capsys):
    assert cli.main(["query", str(IMPACT_SNAPSHOT), "MATCH (d:Decision) RETURN d.id AS id ORDER BY id", "--profile"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["row_count"] == 3
    prof = out["profile"]
    assert prof["elapsed_ms"] >= 0 and prof["parse_ms"] >= 0 and prof["plan_ms"] >= 0 and prof["execute_ms"] >= 0
    assert prof["plan"]["profiled"] is True and prof["plan"]["schema"] == "relate.plan/v1"
    assert isinstance(prof["notifications"], list)


def test_offline_fulltext_search_cli_and_module(capsys):
    assert cli.main(["search", str(IMPACT_SNAPSHOT), "oversized OR page", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["match_count"] >= 1
    assert any("page" in m["id"] or "page" in m["title"].lower() for m in out["matches"])
    assert all(m["score"] > 0 for m in out["matches"])

    assert cli.main(["search", str(IMPACT_SNAPSHOT), "oversized", "--kind", "decision", "--format", "text"]) == 0
    text = capsys.readouterr().out
    assert "decision:demo-oversized-pages-are-refused" in text

    cypher.check("CALL db.index.fulltext.queryNodes('decisis_text', 'page') YIELD node, score RETURN node.id, score")


def test_mcp_search_and_query_profile():
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    from decisis import serve
    tools = serve.load_tools(IMPACT_SNAPSHOT, ROOT, None)
    found = tools.call("search", {"query": "oversized", "kinds": ["decision"], "detail": "full"})
    assert found["match_count"] >= 1
    assert all(m["kind"] == "decision" for m in found["matches"])
    profiled = tools.call("query", {"cypher": "MATCH (d:Decision) RETURN d.id AS id", "profile": True, "detail": "full"})
    assert profiled["profile"]["plan"]["profiled"] is True
