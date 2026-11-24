from __future__ import annotations

import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from test_audit import no_network
from decisis import cli, render

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = Path(__file__).resolve().parent / "golden"
FIX = ROOT / "fixtures"
COMMANDS = {
    "impact": ["impact", str(FIX / "impact" / "vinc.json"), "reports/export.py", "storage/"],
    "paths": ["paths", str(FIX / "vinc_subgraph.json"), "record:tls-advisory-example", "concept:service-api"],
    "audit": ["audit", str(FIX / "audit" / "vinc.json"), str(FIX / "audit" / "demo-lockfile.json"), "--repo", "Demo",
              "--osv-cache", str(FIX / "audit" / "osv-cache.json")],
}
SUFFIX = {"mermaid": "md", "html": "html"}
HOSTILE = 'a "quoted" <script>alert(1)</script> ] [x]\nnext line `tick` #1 & | --> end'


def run(capsys, args: list[str]) -> str:
    capsys.readouterr()
    assert cli.main(args) == 0
    return capsys.readouterr().out


def hostile_reports() -> dict[str, dict]:
    nid = 'concept:x"]-->y<script>'
    step = {"source": "decision:" + HOSTILE, "type": "ABOUT", "target": nid, "evidence": HOSTILE}
    return {
        "impact": {"loaded": {"nodes": 2, "edges": 1}, "hops": 1, "repo": None, "impact": [{"path": "src/" + HOSTILE, "matched_as": "src/x", "governing": [
            {"id": nid, "kind": "concept", "title": HOSTILE, "hops": 0, "via": nid, "nodes": [nid], "path": [], "code_ref": [{"ref": HOSTILE, "match": "exact"}]},
            {"id": "decision:" + HOSTILE, "kind": "decision", "title": HOSTILE, "hops": 1, "via": nid, "nodes": [nid, "decision:" + HOSTILE], "path": [step]}]}]},
        "paths": {"loaded": {"nodes": 2, "edges": 1}, "source": nid, "target": "decision:" + HOSTILE,
                  "nodes": {nid: {"kind": "concept", "title": HOSTILE, "source": "javascript:alert(1)"}},
                  "paths": [{"ids": [nid, "decision:" + HOSTILE], "rels": ["ABOUT"], "steps": [step]}]},
        "audit": {"meta": {"repo": HOSTILE, "space": HOSTILE}, "loaded": {"nodes": 1, "edges": 1}, "summary": {"affected": 1},
                  "governing": [{"decision": "decision:" + HOSTILE, "title": HOSTILE, "via": nid}], "violations": 1,
                  "findings": [{"package": "pkg:npm/" + HOSTILE, "advisory": "adv:" + HOSTILE, "severity": "HIGH", "status": "affected", "dev_only": False,
                                "path": ["repo:" + HOSTILE, "pkg:npm/" + HOSTILE, "adv:" + HOSTILE], "source_url": "javascript:alert(1)",
                                "fetched_at": HOSTILE, "content_hash": HOSTILE, "advisory_summary": HOSTILE,
                                "policies": [{"decision": "decision:" + HOSTILE, "verdict": "violated", "why": HOSTILE}]}]},
        "check": {"loaded": {"nodes": 2, "edges": 1}, "hops": 1, "repo": None, "base": HOSTILE, "changed": ["src/" + HOSTILE],
                  "reviewers": [HOSTILE], "governing": [{"decision": "decision:" + HOSTILE, "title": HOSTILE, "files": ["src/" + HOSTILE]}],
                  "superseded": [{"decision": "decision:old" + HOSTILE, "title": HOSTILE, "files": ["src/" + HOSTILE], "superseded_by": [HOSTILE]}],
                  "rules": [], "rule_problems": [{"decision": "decision:" + HOSTILE, "rule": HOSTILE, "problem": HOSTILE}],
                  "imports": [{"file": "src/" + HOSTILE, "line": 1, "import": HOSTILE, "resolution": "repository", "target": "db/" + HOSTILE}],
                  "violations": [{"file": "src/" + HOSTILE, "line": 1, "decision": "decision:" + HOSTILE, "rule": "imports_forbidden",
                                  "verdict": "violated", "why": HOSTILE, "import": HOSTILE, "target": "db/" + HOSTILE},
                                 {"file": "src/" + HOSTILE, "line": None, "decision": "decision:" + HOSTILE, "rule": "review_required",
                                  "verdict": "violated", "why": HOSTILE}],
                  "unresolved": [], "summary": {"violated": 2, "unresolved": 0, "not_violated": 0},
                  "impact": [{"path": "src/" + HOSTILE, "matched_as": "src/x", "governing": [
                      {"id": nid, "kind": "concept", "title": HOSTILE, "hops": 0, "via": nid, "nodes": [nid], "path": [],
                       "code_ref": [{"ref": HOSTILE, "match": "exact"}]}]}]},
    }


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def tags(page: str) -> list[tuple[str, dict]]:
    parser = Tags()
    parser.feed(page)
    return parser.tags


@pytest.mark.parametrize("kind", sorted(COMMANDS))
@pytest.mark.parametrize("fmt", sorted(SUFFIX))
def test_the_fixtures_render_to_the_committed_golden_output(kind, fmt, capsys, no_network):
    out = run(capsys, COMMANDS[kind] + ["--format", fmt])
    golden = GOLDEN / f"{kind}.{SUFFIX[fmt]}"
    if os.environ.get("DECISIS_GOLDEN") == "write":
        golden.write_text(out, encoding="utf-8")
    assert out == golden.read_text(encoding="utf-8")


@pytest.mark.parametrize("kind", sorted(COMMANDS))
def test_json_stays_the_default_format(kind, capsys, no_network):
    assert run(capsys, COMMANDS[kind]) == run(capsys, COMMANDS[kind] + ["--format", "json"])
    assert isinstance(json.loads(run(capsys, COMMANDS[kind])), dict)


def test_audit_out_still_writes_the_json_report_while_the_view_goes_to_stdout(tmp_path, capsys, no_network):
    out = run(capsys, COMMANDS["audit"] + ["--format", "html", "--out", str(tmp_path / "report.json")])
    assert out.startswith("<!doctype html>")
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["violations"] == 3


def test_mermaid_is_one_fenced_block_with_generated_ids_and_quoted_labels(capsys, no_network):
    out = run(capsys, COMMANDS["audit"] + ["--format", "mermaid"])
    assert out.startswith("```mermaid\nflowchart LR\n") and out.endswith("\n```\n") and out.count("```") == 2
    for line in out.splitlines()[2:-1]:
        assert re.fullmatch(r'  (n\d+\["[^"]*"\]|n\d+ -->\|"[^"]*"\| n\d+|classDef \w+ [^"]+|class [n\d,]+ \w+|linkStyle [\d,]+ [^"]+)', line), line


def test_violated_paths_are_styled_apart(capsys, no_network):
    out = run(capsys, COMMANDS["audit"] + ["--format", "mermaid"])
    edges = [line for line in out.splitlines() if "-->" in line]
    hot = {int(i) for i in re.search(r"linkStyle ([\d,]+) ", out).group(1).split(",")}
    assert hot and len(hot) < len(edges)
    assert all('"violates"' not in edges[i] for i in range(len(edges)) if i not in hot)
    assert "classDef violated" in out
    page = run(capsys, COMMANDS["audit"] + ["--format", "html"])
    assert page.count('class="item violated"') == 3


@pytest.mark.parametrize("kind", sorted(render.KINDS))
def test_hostile_titles_are_escaped_in_mermaid(kind):
    out = render.mermaid(kind, hostile_reports()[kind])
    body = out.splitlines()[1:-1]
    assert len(body) == out.count("\n") - 2
    for line in body:
        quoted = re.findall(r'"([^"]*)"', line)
        assert line.count('"') == 2 * len(quoted)
        for text in quoted:
            assert not set(text.replace("<br/>", "")) & set("<>[]`|")
    assert "<script>" not in out and "alert(1)</script>" not in out
    assert "#34;quoted#34;" in out and "#60;script#62;" in out and "#93;" in out


@pytest.mark.parametrize("kind", sorted(render.KINDS))
def test_hostile_titles_are_escaped_in_html(kind):
    page = render.html(kind, hostile_reports()[kind])
    assert "<script" not in page.lower()
    assert "&lt;script&gt;" in page and "&quot;quoted&quot;" in page
    assert [t for t, _ in tags(page) if t not in {"html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "dl", "dt", "dd", "code", "section",
                                                  "p", "ul", "ol", "li", "div", "span", "table", "tr", "th", "td", "details", "summary", "pre", "a"}] == []
    assert not [t for t, _ in tags(page) if t == "a"]


@pytest.mark.parametrize("kind", sorted(COMMANDS))
def test_the_html_is_one_offline_file_with_no_url_but_source_links(kind, capsys, no_network):
    page = run(capsys, COMMANDS[kind] + ["--format", "html"])
    found = tags(page)
    assert not [t for t, _ in found if t in {"script", "link", "img", "iframe", "object", "embed", "svg", "video", "audio", "source", "base", "form"}]
    assert not re.search(r"url\(|@import|@font-face", page)
    sources = {a["href"] for t, a in found if t == "a" and a.get("class") == "source"}
    assert all(t != "a" or a.get("class") == "source" for t, a in found)
    assert set(re.findall(r"https?://[^\s\"<>]+", page)) <= sources
    assert ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'") in [(a.get("http-equiv"), a.get("content")) for t, a in found if t == "meta"]


def test_the_audit_html_links_every_finding_to_its_source(capsys, no_network):
    page = run(capsys, COMMANDS["audit"] + ["--format", "html"])
    report = json.loads(run(capsys, COMMANDS["audit"]))
    hrefs = [a["href"] for t, a in tags(page) if t == "a"]
    assert hrefs == [f["source_url"] for f in report["findings"]]
    assert all(f["content_hash"] in page and f["fetched_at"] in page for f in report["findings"])


def test_the_paths_html_shows_the_evidence_on_each_step(capsys, no_network):
    page = run(capsys, COMMANDS["paths"] + ["--format", "html"])
    for ev in ("advisory names the stack", "the client links it", "the API calls out through it"):
        assert f'<div class="evidence">{ev}</div>' in page


def test_an_unknown_kind_is_refused():
    with pytest.raises(ValueError, match="no renderer for 'verdict'"):
        render.mermaid("verdict", {})
