from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

import pytest

from test_audit import no_network

pytest.importorskip("mcp")
pytest.importorskip("jsonschema")

import anyio
from mcp import Client, ClientSession, StdioServerParameters, types

from test_check import CHANGED, git_repo
from decisis import check, cli, codeowners, impact
from decisis import sandbox as sb
from decisis import serve

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
AUDIT = FIX / "audit"
IMPACT_SNAPSHOT = FIX / "impact" / "vinc.json"
AUDIT_SNAPSHOT = AUDIT / "vinc.json"
CACHE = AUDIT / "osv-cache.json"
CHECK = FIX / "check"
CHECK_SNAPSHOT = CHECK / "vinc.json"
CHECK_REPO = CHECK / "repo"


def tools(snapshot=AUDIT_SNAPSHOT, root=AUDIT, cache=CACHE, allow_network=False):
    return serve.load_tools(snapshot, root, cache, allow_network)


def over_mcp(t: serve.Tools, *calls):
    async def drive():
        async with Client(serve.build(t)) as client:
            assert isinstance(client.session, ClientSession)
            listed = await client.list_tools()
            results = [await client.call_tool(name, args) for name, args in calls]
            return listed, results
    return anyio.run(drive)


def text_of(result) -> str:
    return "".join(c.text for c in result.content if c.type == "text")


@pytest.fixture
def boxes(monkeypatch, tmp_path):
    root = tmp_path / "boxes"
    root.mkdir()
    made = []
    real = sb.Sandbox.__init__

    def init(self, r=None, limits=None):
        real(self, r, limits)
        made.append(self.dir)
    monkeypatch.setattr(sb, "default_root", lambda: root)
    monkeypatch.setattr(sb.Sandbox, "__init__", init)
    return root, made


def test_the_server_lists_only_the_six_read_only_tools_with_the_cli_bounds():
    listed, _ = over_mcp(tools())
    by = {t.name: t for t in listed.tools}
    assert sorted(by) == ["audit", "check", "impact", "paths", "query", "search"]
    assert all(t.annotations.read_only_hint and not t.annotations.destructive_hint for t in listed.tools)
    assert not by["audit"].annotations.open_world_hint
    hops = by["impact"].input_schema["properties"]["hops"]
    assert (hops["minimum"], hops["maximum"]) == (0, impact.MAX_HOPS)
    p = by["paths"].input_schema["properties"]
    assert (p["hops"]["minimum"], p["hops"]["maximum"], p["limit"]["maximum"]) == (1, impact.MAX_HOPS, cli.MAX_LIMIT)
    assert all(t.input_schema["additionalProperties"] is False for t in listed.tools)
    c = by["check"].input_schema["properties"]
    assert sorted(c) == ["base", "changed", "detail", "reviewers", "today", "warn_days"] and c["changed"]["maxItems"] == check.MAX_CHANGED
    assert not by["check"].annotations.open_world_hint and by["check"].annotations.idempotent_hint


def test_one_call_per_tool_gives_what_the_cli_gives(boxes, no_network, capsys):
    root, made = boxes
    _, (im, pa, au) = over_mcp(
        tools(IMPACT_SNAPSHOT, ROOT),
        ("impact", {"code_paths": ["reports/export.py"], "detail": "full"}),
        ("paths", {"source": "concept:demo-report-export", "target": "decision:demo-report-exports-finish-in-time", "hops": 2}),
        ("audit", {"lockfile": "fixtures/audit/demo-lockfile.json", "repo": "Demo"}),
    )
    assert not (im.is_error or pa.is_error or au.is_error)
    assert len(set(made)) == 3 and list(root.iterdir()) == []
    assert [g["id"] for g in im.structured_content["impact"][0]["governing"]][:1] == ["concept:demo-report-export"]
    assert json.loads(text_of(im)) == im.structured_content
    assert pa.structured_content["paths"][0]["ids"] == ["concept:demo-report-export", "decision:demo-report-exports-finish-in-time"]
    assert au.structured_content["loaded"]["nodes"] > 0
    assert cli.main(["impact", str(IMPACT_SNAPSHOT), "reports/export.py"]) == 0
    assert json.loads(capsys.readouterr().out) == im.structured_content


def test_the_query_tool_carries_the_snapshot_schema_and_the_caps():
    t = tools(IMPACT_SNAPSHOT, ROOT)
    listed, _ = over_mcp(t)
    q = {x.name: x for x in listed.tools}["query"]
    assert q.description.endswith(serve.cypher.describe(t.graph))
    assert "  :ABOUT (3): Decision -> Concept (3)" in q.description and "500 rows and 1048576 bytes" in q.description
    assert q.annotations.read_only_hint and q.annotations.idempotent_hint and not q.annotations.open_world_hint
    props = q.input_schema["properties"]
    assert q.input_schema["required"] == ["cypher"] and props["detail"]["enum"] == ["summary", "full"]
    assert all(x.input_schema["properties"]["detail"]["default"] == "summary" for x in listed.tools)


def test_query_over_mcp_answers_refuses_writes_and_cleans_up(boxes):
    root, made = boxes
    governed = ("MATCH p = (g)-[*1..3]->(c) WHERE c.code_ref CONTAINS $path AND (g:Decision OR g:Record) "
                "RETURN DISTINCT g.id AS id ORDER BY id")
    _, (ok, full, write, sub, bad_param, syntax) = over_mcp(
        tools(IMPACT_SNAPSHOT, ROOT),
        ("query", {"cypher": governed, "params": {"path": "storage/page_store.py"}}),
        ("query", {"cypher": "UNWIND range(1, 600) AS x RETURN x", "detail": "full"}),
        ("query", {"cypher": "MATCH (n) DETACH DELETE n"}),
        ("query", {"cypher": "MATCH (n) CALL { WITH n SET n.x = 1 } RETURN n.id"}),
        ("query", {"cypher": "RETURN 1 AS x", "params": {"bad-name": 1}}),
        ("query", {"cypher": "MATCH (n RETURN n"}),
    )
    assert [r.is_error for r in (ok, full, write, sub, bad_param, syntax)] == [False, False, True, True, True, True]
    got = ok.structured_content
    assert got["detail"] == "summary" and got["row_count"] == 2
    assert [r["id"] for r in got["rows"]] == ["decision:demo-oversized-pages-are-refused", "record:demo-page-size-check-review"]
    assert len(full.structured_content["rows"]) == 500 and full.structured_content["cut"].startswith("500 of 600 rows")
    assert "query: refused before running" in text_of(write) and "DETACH writes to the graph" in text_of(write)
    assert "refused before running" in text_of(sub) and "params" in text_of(bad_param)
    assert "parse error" in text_of(syntax)
    assert len(made) == 3 and list(root.iterdir()) == []


def sent(result) -> int:
    return len(result.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))


def test_what_the_server_sends_stays_under_the_byte_cap(boxes):
    wide = "UNWIND range(1, 500) AS i RETURN i, [x IN range(1, 1000) | 0] AS xs"
    _, (full, short, small) = over_mcp(tools(IMPACT_SNAPSHOT, ROOT), ("query", {"cypher": wide, "detail": "full"}),
                                       ("query", {"cypher": wide}), ("query", {"cypher": "UNWIND range(1, 3) AS i RETURN i", "detail": "full"}))
    assert not (full.is_error or short.is_error)
    got = full.structured_content
    assert sent(full) <= serve.MAX_SENT and json.loads(text_of(full)) == got
    assert 0 < len(got["rows"]) < 348 and [r["i"] for r in got["rows"]] == list(range(1, len(got["rows"]) + 1))
    assert got["row_count"] == 500 and "the response was shortened to stay under 1048576 bytes: rows" in got["cut"]
    assert re.match(r"\d+ of 500 rows are shown: results stop at 500 rows", got["cut"])
    assert sent(short) <= serve.MAX_SENT and len(short.structured_content["rows"]) == 10
    assert "cut" not in small.structured_content


def test_a_query_over_mcp_past_the_time_limit_is_an_error_result(boxes, monkeypatch, tmp_path):
    root, made = boxes
    monkeypatch.setenv("DECISIS_QUERY_TIMEOUT", "1")
    _, (slow, fast) = over_mcp(tools(dense_snapshot(tmp_path / "dense.json"), ROOT),
                               ("query", {"cypher": "MATCH p = (a)-[*1..6]-(b) RETURN count(p) AS c"}),
                               ("query", {"cypher": "MATCH (n) RETURN count(n) AS c"}))
    assert slow.is_error and "ran longer than 1 s" in text_of(slow)
    assert not fast.is_error and fast.structured_content["rows"] == [{"c": 14}]
    assert list(root.iterdir()) == []


def test_the_audit_summary_is_short_and_full_is_the_cli_report(no_network, capsys):
    _, (short, full) = over_mcp(tools(), ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo"}),
                                ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo", "detail": "full"}))
    assert cli.main(["audit", str(AUDIT_SNAPSHOT), str(AUDIT / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(CACHE)]) == 0
    assert full.structured_content == json.loads(capsys.readouterr().out)
    s, f = short.structured_content, full.structured_content
    assert len(json.dumps(s)) * 2 < len(json.dumps(f))
    assert (s["summary"], s["violations"], s["findings_count"], s["governing_count"]) == (f["summary"], f["violations"], len(f["findings"]),
                                                                                           len(f["governing"]))
    assert [x["package"] for x in s["findings"]] == [x["package"] for x in f["findings"]][:10]
    assert {x["package"] for x in s["findings"] if x["violated"]} == {x["package"] for x in f["findings"]
                                                                      if any(p["verdict"] == "violated" for p in x["policies"])}
    assert "detail \"full\"" in s["note"] and "policies" not in s["findings"][0]


def test_impact_and_paths_default_to_a_summary_and_give_the_cli_report_in_full(capsys):
    t = tools(IMPACT_SNAPSHOT, ROOT)
    args = {"source": "concept:demo-report-export", "target": "decision:demo-report-exports-finish-in-time"}
    _, (im, im_full, pa, pa_full) = over_mcp(t, ("impact", {"code_paths": ["storage/page_store.py"]}),
                                             ("impact", {"code_paths": ["storage/page_store.py"], "detail": "full"}),
                                             ("paths", args), ("paths", {**args, "detail": "full"}))
    entry = im.structured_content["impact"][0]
    assert entry["governing_count"] == 4 and [g["id"] for g in entry["governing"]] == [g["id"] for g in
                                                                                      im_full.structured_content["impact"][0]["governing"]]
    assert "path" not in entry["governing"][0] and "detail" not in im_full.structured_content
    assert cli.main(["impact", str(IMPACT_SNAPSHOT), "storage/page_store.py"]) == 0
    assert json.loads(capsys.readouterr().out) == im_full.structured_content
    assert pa.structured_content["path_count"] == len(pa_full.structured_content["paths"])
    assert pa.structured_content["paths"] == pa_full.structured_content["paths"]


def test_the_audit_over_mcp_matches_the_cli_audit(no_network, capsys):
    _, (au,) = over_mcp(tools(), ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo"}))
    assert cli.main(["audit", str(AUDIT_SNAPSHOT), str(AUDIT / "demo-lockfile.json"), "--repo", "Demo", "--osv-cache", str(CACHE)]) == 0
    shown = json.loads(capsys.readouterr().out)
    got = au.structured_content
    assert (got["summary"], got["violations"]) == (shown["summary"], shown["violations"]) and got["violations"] > 0


def test_a_write_shaped_request_is_refused_and_nothing_is_written(boxes, no_network, tmp_path):
    root, made = boxes
    _, results = over_mcp(
        tools(root=tmp_path),
        ("commit", {"plan": "plan.json", "approve": "d761d1c8a44d62e2"}),
        ("propose", {"report": "report.json", "repo": "Demo", "space": "s", "out": "plan.json"}),
        ("impact", {"code_paths": ["a.py"], "out": "report.json"}),
    )
    assert all(r.is_error for r in results)
    assert "'commit' is not a decisis tool; this server is read only" in text_of(results[0])
    assert "'propose' is not a decisis tool" in text_of(results[1])
    assert "Additional properties are not allowed" in text_of(results[2])
    assert made == [] and list(tmp_path.iterdir()) == [root]


@pytest.mark.parametrize("name,args,said", [
    ("impact", {"code_paths": ["../secrets.py"]}, "leaves the snapshot's repository"),
    ("impact", {"code_paths": ["reports/../../etc"]}, "leaves the snapshot's repository"),
    ("impact", {"code_paths": ["/etc/passwd"]}, "is not a path inside the snapshot's repository"),
    ("impact", {"code_paths": ["Other:reports/export.py"], "repo": "Demo"}, "names another repository"),
    ("impact", {"code_paths": ["reports"], "hops": impact.MAX_HOPS + 1}, "hops"),
    ("impact", {"code_paths": []}, "code_paths"),
    ("impact", {"code_paths": "reports"}, "code_paths"),
    ("impact", {}, "'code_paths' is a required property"),
    ("paths", {"source": "a", "target": "b", "hops": 0}, "hops"),
    ("paths", {"source": "a", "target": "b", "limit": cli.MAX_LIMIT + 1}, "limit"),
    ("paths", {"source": "a" * (serve.MAX_TEXT + 1), "target": "b"}, "source"),
    ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo", "depth": serve.MAX_DEPTH + 1}, "depth"),
])
def test_bad_input_is_an_error_result_not_a_crash(name, args, said, boxes):
    root, made = boxes
    _, (bad, good) = over_mcp(tools(), (name, args), ("paths", {"source": "concept:demo-app", "target": "concept:demo-app"}))
    assert bad.is_error and said in text_of(bad)
    assert not good.is_error and list(root.iterdir()) == []


def test_the_audit_reads_only_under_the_root_and_refuses_an_escaping_symlink(tmp_path, no_network):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text((AUDIT / "demo-lockfile.json").read_text(encoding="utf-8"), encoding="utf-8")
    (root / "package-lock.json").symlink_to(outside)
    (root / "inside.json").write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "lock.json").symlink_to(root / "inside.json")
    calls = [("audit", {"lockfile": f, "repo": "Demo"}) for f in
             ["package-lock.json", str(outside), "../outside.json", "missing.json", "nested", "nested/lock.json", str(root / "inside.json"),
              str(tmp_path / "nothing-here.json")]]
    _, results = over_mcp(tools(root=root), *calls)
    said = [text_of(r) for r in results]
    assert [r.is_error for r in results] == [True, True, True, True, True, False, False, True]
    assert "outside the server's root" in said[0] and "outside the server's root" in said[1] and "outside the server's root" in said[2]
    assert "does not exist" in said[3] and "is not a file" in said[4]
    assert "outside the server's root" in said[7]


def test_the_audit_uses_the_network_only_when_allowed(monkeypatch, no_network):
    asked = []
    real = serve.external.fetch_advisories

    def fetch(pkgs, opener=None, **kw):
        if opener is None:
            asked.append(len(pkgs))
            return [], []
        return real(pkgs, opener=opener, **kw)
    monkeypatch.setattr(serve.external, "fetch_advisories", fetch)
    _, (closed,) = over_mcp(tools(cache=None), ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo"}))
    assert closed.is_error and "--allow-network" in text_of(closed) and asked == []
    listed, (opened,) = over_mcp(tools(cache=None, allow_network=True), ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo"}))
    assert not opened.is_error and asked and {t.name: t for t in listed.tools}["audit"].annotations.open_world_hint
    asked.clear()
    _, (cached,) = over_mcp(tools(allow_network=True), ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo"}))
    assert not cached.is_error and asked == []


def test_a_cache_miss_is_an_error_result(tmp_path, no_network):
    cache = json.loads(CACHE.read_text(encoding="utf-8"))
    del cache["queries"]["pkg:npm/minimist@1.2.8"]
    partial = tmp_path / "partial.json"
    partial.write_text(json.dumps(cache), encoding="utf-8")
    _, (r,) = over_mcp(tools(cache=partial), ("audit", {"lockfile": "demo-lockfile.json", "repo": "Demo"}))
    assert r.is_error and "pkg:npm/minimist@1.2.8 is not in the OSV cache" in text_of(r)


def test_the_cli_serves_over_stdio(no_network):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    params = StdioServerParameters(command=sys.executable, args=["-m", "decisis.cli", "serve", "--mcp", "--snapshot", str(IMPACT_SNAPSHOT)],
                                   env=env, cwd=str(ROOT))

    async def drive():
        with anyio.fail_after(60):
            async with Client(params) as client:
                names = sorted(t.name for t in (await client.list_tools()).tools)
                result = await client.call_tool("impact", {"code_paths": ["reports/export.py"], "hops": 1})
                return names, result
    names, result = anyio.run(drive)
    assert names == ["audit", "check", "impact", "paths", "query", "search"]
    assert not result.is_error and result.structured_content["hops"] == 1


def test_the_base_install_needs_relate_db_and_pyyaml_and_does_not_import_mcp():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == ["relate-db==1.0.2", "PyYAML>=6.0.1"]
    assert any(re.match(r"mcp>=2\.\d+,<3$", d) for d in project["optional-dependencies"]["mcp"])
    code = "import sys, decisis.cli; print(sorted(m for m in ('mcp', 'jsonschema') if m in sys.modules))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    assert out.stdout.strip() == "[]"


def test_serve_without_the_extra_says_how_to_install_it(monkeypatch, capsys):
    monkeypatch.delitem(sys.modules, "decisis.serve")
    monkeypatch.delattr(sys.modules["decisis"], "serve")
    monkeypatch.setitem(sys.modules, "mcp", None)
    with pytest.raises(SystemExit) as e:
        cli.main(["serve", "--mcp", "--snapshot", str(IMPACT_SNAPSHOT)])
    assert e.value.code == 2 and "pip install 'decisis[mcp]'" in capsys.readouterr().err


@pytest.mark.parametrize("doc", ["docs/mcp.md", "skills/decisis/SKILL.md"])
def test_the_docs_show_the_claude_code_configuration(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    assert "pip install \"decisis[mcp]\"" in text
    assert "claude mcp add decisis -- decisis serve --mcp --snapshot " in text
    block = next(b for b in re.findall(r"```json\n(.*?)```", text, re.S) if "mcpServers" in b)
    server = json.loads(block)["mcpServers"]["decisis"]
    assert server["command"] == "decisis" and server["args"][:2] == ["serve", "--mcp"] and "--snapshot" in server["args"]


def dense_snapshot(path: Path, n: int = 14) -> Path:
    ids = [f"concept:n{i}" for i in range(n)]
    nodes = [{"id": i, "kind": "concept", "title": i, "props": {}} for i in ids]
    edges = [{"source": a, "target": b, "type": "RELATED_TO", "evidence": "x"} for a in ids for b in ids if a != b]
    path.write_text(json.dumps({"meta": {}, "nodes": nodes, "edges": edges}), encoding="utf-8")
    return path


SERVE_UNDER = "import sys; from pathlib import Path; from decisis import cli, sandbox; sandbox.TMPFS = Path(sys.argv[1]); sys.exit(cli.main(sys.argv[2:]))"


def scratch_dirs(root: Path | None = None) -> set[Path]:
    return set((root or sb.default_root()).glob("decisis-serve-*"))


def slow_call(snapshot: Path, root: Path | None = None):
    before = scratch_dirs(root)
    start = [sys.executable, "-c", SERVE_UNDER, str(root)] if root else [sys.executable, "-m", "decisis.cli"]
    p = subprocess.Popen([*start, "serve", "--mcp", "--snapshot", str(snapshot)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=str(ROOT), env={**os.environ, "PYTHONPATH": str(ROOT / "src")})

    def send(message):
        p.stdin.write((json.dumps(message) + "\n").encode())
        p.stdin.flush()
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}})
    p.stdout.readline()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "paths", "arguments": {"source": "concept:n0", "target": "concept:n1", "hops": impact.MAX_HOPS, "limit": cli.MAX_LIMIT}}})
    deadline = time.monotonic() + 30
    while not any((d / "task.rl").exists() for s in scratch_dirs(root) - before for d in s.iterdir()):
        assert time.monotonic() < deadline and p.poll() is None
        time.sleep(0.05)
    return p, scratch_dirs(root) - before


@pytest.mark.parametrize("stop,code", [(lambda p: p.send_signal(signal.SIGTERM), 128 + signal.SIGTERM),
                                       (lambda p: p.send_signal(signal.SIGINT), 128 + signal.SIGINT),
                                       (lambda p: p.stdin.close(), 0)], ids=["sigterm", "sigint", "eof"])
def test_a_server_stopped_during_a_slow_call_leaves_no_sandbox(stop, code, tmp_path):
    p, mine = slow_call(dense_snapshot(tmp_path / "dense.json"))
    try:
        assert mine and p.poll() is None
        stop(p)
        assert p.wait(timeout=15) == code
        assert not any(d.exists() for d in mine)
    finally:
        p.kill()
        p.wait()


@pytest.mark.parametrize("inventory", ["go/go.mod", "cyclonedx.json", "uv.lock", "poetry/poetry.lock", "requirements/requirements.txt"])
def test_audit_reads_every_inventory_format_and_go_sum_only_from_under_the_root(inventory, no_network):
    t = tools(AUDIT_SNAPSHOT, FIX / "inventory", FIX / "inventory" / "osv-cache.json")
    report = t.call("audit", {"lockfile": inventory, "repo": "Demo"})
    assert report["summary"]["affected"] >= 1
    assert all(f["package"].startswith("pkg:") for f in report["findings"])


def test_audit_follows_requirements_includes_through_the_server_root_check(tmp_path, no_network):
    reqs = FIX / "inventory" / "requirements"
    (tmp_path / "requirements.txt").write_text((reqs / "requirements.txt").read_text(encoding="utf-8") + "-r ../outside.txt\n",
                                               encoding="utf-8")
    (tmp_path / "base.txt").write_text((reqs / "base.txt").read_text(encoding="utf-8"), encoding="utf-8")
    t = tools(AUDIT_SNAPSHOT, tmp_path, FIX / "inventory" / "osv-cache.json")
    report = t.call("audit", {"lockfile": "requirements.txt", "repo": "Demo"})
    assert report["meta"]["packages"] == 7
    assert report["inventory_notes"][0].startswith("requirements.txt line 13 includes ../outside.txt, which was not followed")


def test_audit_follows_an_include_above_the_inventory_while_it_stays_under_the_root(tmp_path, no_network):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "requirements.txt").write_text("\ufeff-r ../base.txt\n-r d/requirements.txt\n-r ../../secret.txt\n"
                                                   "certifi==2023.7.22\n", encoding="utf-8")
    (root / "base.txt").write_text("\ufeffidna==3.6\n", encoding="utf-8")
    (root / "sub" / "d").symlink_to(".")
    (tmp_path / "secret.txt").write_text("click==8.1.7\n", encoding="utf-8")
    t = tools(AUDIT_SNAPSHOT, root, FIX / "inventory" / "osv-cache.json")
    report = t.call("audit", {"lockfile": "sub/requirements.txt", "repo": "Demo"})
    assert report["meta"]["packages"] == 2
    assert report["inventory_notes"][0].startswith("requirements.txt line 3 includes ../../secret.txt, which was not followed")


def test_audit_does_not_read_a_go_sum_outside_the_root(tmp_path, no_network):
    (tmp_path / "go.mod").write_text((FIX / "inventory" / "go" / "go.mod").read_text(encoding="utf-8"), encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.sum"
    outside.write_text((FIX / "inventory" / "go" / "go.sum").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "go.sum").symlink_to(outside)
    t = tools(AUDIT_SNAPSHOT, tmp_path, FIX / "inventory" / "osv-cache.json")
    with pytest.raises(Exception, match="go.sum"):
        t.call("audit", {"lockfile": "go.mod", "repo": "Demo"})


def age(path: Path) -> None:
    old = time.time() - sb.GRACE_SECONDS - 60
    os.utime(path, (old, old))


@pytest.mark.skipif(not sb.can_sweep(), reason="this platform cannot check the owner of a task directory")
def test_gc_removes_the_directory_of_a_server_killed_with_sigkill_and_keeps_a_live_one(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    snapshot = dense_snapshot(tmp_path / "dense.json")
    killed, (gone,) = slow_call(snapshot, root)
    live, (kept,) = slow_call(snapshot, root)
    try:
        assert re.fullmatch(r"decisis-serve-[0-9a-f]{32}", gone.name) and gone.stat().st_mode & 0o777 == 0o700
        owner = json.loads((gone / sb.OWNER).read_text(encoding="utf-8"))
        assert owner["pid"] == killed.pid and owner["host"] == sb.socket.gethostname()
        assert owner["start"] == sb._start_time(killed.pid) and (gone / sb.OWNER).stat().st_mode & 0o777 == 0o600
        killed.kill()
        assert killed.wait(timeout=15) == -signal.SIGKILL
        assert gone.is_dir() and any(d.name != sb.OWNER for d in gone.iterdir())
        age(gone)
        age(kept)
        capsys.readouterr()
        assert cli.main(["gc", "--root", str(root)]) == 0
        assert f"removed {gone}" in capsys.readouterr().out
        assert not gone.exists() and kept.is_dir() and live.poll() is None
        assert scratch_dirs(root) == {kept}
    finally:
        for p in (killed, live):
            p.kill()
            p.wait()
            p.stdin.close()
            p.stdout.close()


@pytest.mark.skipif(not sb.can_sweep(), reason="this platform cannot check the owner of a task directory")
def test_a_new_server_sweeps_the_directory_a_killed_server_left(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    snapshot = dense_snapshot(tmp_path / "dense.json")
    killed, (gone,) = slow_call(snapshot, root)
    killed.kill()
    killed.wait()
    killed.stdin.close()
    killed.stdout.close()
    age(gone)
    p, (mine,) = slow_call(snapshot, root)
    try:
        assert not gone.exists() and scratch_dirs(root) == {mine}
    finally:
        p.kill()
        p.wait()
        p.stdin.close()
        p.stdout.close()


def cli_check(capsys, *args: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = cli.main(["check", str(CHECK_SNAPSHOT), *args])
    return code, json.loads(capsys.readouterr().out)


def test_check_over_mcp_gives_what_the_cli_gives_for_changed_files(boxes, no_network, capsys):
    root, made = boxes
    args = {"changed": CHANGED, "reviewers": ["@alice"]}
    _, (short, full) = over_mcp(tools(CHECK_SNAPSHOT, CHECK_REPO, None), ("check", args), ("check", {**args, "detail": "full"}))
    code, shown = cli_check(capsys, "--repo-dir", str(CHECK_REPO), "--changed", *CHANGED, "--reviewers", "@alice")
    assert code == 1 and not (short.is_error or full.is_error)
    assert full.structured_content == shown and json.loads(text_of(full)) == shown
    s = short.structured_content
    assert s["detail"] == "summary" and "detail \"full\"" in s["note"] and s["summary"] == shown["summary"]
    assert s["violations_count"] == len(shown["violations"]) == 3 and s["unresolved_count"] == len(shown["unresolved"])
    key = ("file", "line", "decision", "rule", "why")
    assert [{k: v[k] for k in key} for v in s["violations"]] == [{k: v[k] for k in key} for v in shown["violations"]]
    assert s["governing"] == [{"decision": g["decision"], "title": g["title"]} for g in shown["governing"]]
    assert s["changed"] == shown["changed"] and s["imports_count"] == len(shown["imports"])
    assert "impact" not in s and "imports" not in s and len(json.dumps(s)) < len(json.dumps(shown))
    assert made and list(root.iterdir()) == []


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_check_over_mcp_with_base_runs_git_through_the_hardened_helper_and_matches_the_cli(tmp_path, monkeypatch, no_network, capsys):
    repo = git_repo(tmp_path)
    marker = tmp_path / "ran"
    hook = tmp_path / "monitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", str(hook)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "core.pager", f"touch {marker}"], check=True)
    calls = []
    real = codeowners.git

    def spy(root, *args, timeout):
        calls.append((root, args, timeout))
        return real(root, *args, timeout=timeout)
    monkeypatch.setattr(codeowners, "git", spy)
    args = {"base": "main~1", "reviewers": ["@shop/payments"]}
    _, (short, full) = over_mcp(tools(CHECK_SNAPSHOT, repo, None), ("check", args), ("check", {**args, "detail": "full"}))
    diff = ("diff", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--relative", "main~1...HEAD", "--")
    assert calls == [(repo.resolve(), diff, check.GIT_SECONDS)] * 2
    code, shown = cli_check(capsys, "--repo-dir", str(repo), "--base", "main~1", "--reviewers", "@shop/payments")
    assert code == 1 and full.structured_content == shown
    assert shown["base"] == "main~1" and shown["changed"] == ["src/payments/charge.py", "src/shop/ui/late.py"]
    assert short.structured_content["base"] == "main~1" and short.structured_content["violations_count"] == 1
    assert not marker.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_a_base_git_cannot_read_is_an_error_result(tmp_path, no_network):
    repo = git_repo(tmp_path)
    _, (bad, plain) = over_mcp(tools(CHECK_SNAPSHOT, repo, None), ("check", {"base": "no-such-ref"}),
                               ("check", {"base": "main~1"}))
    assert bad.is_error and "check: git diff no-such-ref...HEAD failed" in text_of(bad)
    assert not plain.is_error


@pytest.mark.parametrize("args,said", [
    ({"changed": ["../outside.py"]}, "leaves the server's root"),
    ({"changed": ["src/../../outside.py"]}, "leaves the server's root"),
    ({"changed": ["src/payments/charge.py", "/etc/passwd"]}, "is not a path inside the server's root"),
    ({"changed": ["~/notes.txt"]}, "is not a path inside the server's root"),
    ({"changed": ["src\\payments\\charge.py"]}, "is not a path inside the server's root"),
    ({"changed": ["src/x\x00.py"]}, "is not a path inside the server's root"),
    ({"changed": ["escape/secret.py"]}, "is outside the server's root"),
    ({"base": "-p"}, "base must name a commit"),
    ({"base": "--output=/tmp/x"}, "base must name a commit"),
    ({"base": "main --output=/tmp/x"}, "base must name a commit"),
    ({"base": "main\tHEAD"}, "base must name a commit"),
    ({"base": "main\n"}, "base must name a commit"),
    ({"base": "main\x00"}, "base must name a commit"),
    ({"base": "main\x1b[31m"}, "base must name a commit"),
    ({"base": "main​"}, "base must name a commit"),
    ({"base": "main　"}, "base must name a commit"),
    ({"base": ""}, "base"),
    ({}, "exactly one of them"),
    ({"changed": ["src/payments/charge.py"], "base": "main"}, "exactly one of them"),
    ({"changed": []}, "changed"),
    ({"base": "main", "reviewers": "@alice"}, "reviewers"),
    ({"base": "main", "repo_dir": "/"}, "Additional properties are not allowed"),
])
def test_check_refuses_a_path_outside_the_root_and_a_base_that_could_pass_for_an_option_before_git_runs(args, said, tmp_path, monkeypatch,
                                                                                                       boxes):
    root, made = boxes
    repo = tmp_path / "repo"
    shutil.copytree(CHECK_REPO, repo)
    (repo / "escape").symlink_to(tmp_path)
    calls = []
    monkeypatch.setattr(codeowners, "git", lambda *a, **k: calls.append(a))
    _, (bad,) = over_mcp(tools(CHECK_SNAPSHOT, repo, None), ("check", args))
    assert bad.is_error and said in text_of(bad)
    assert calls == [] and made == []


COUNT = ("query", {"cypher": "MATCH (n) RETURN count(n) AS c"})


def nodes_in(snapshot: Path) -> int:
    return len(serve.co.load(snapshot.read_text(encoding="utf-8")).nodes)


def rewrite(path: Path, data: bytes | None = None, ns: int | None = None) -> None:
    before = path.stat().st_mtime_ns
    if data is not None:
        path.write_bytes(data)
    when = before + 2_000_000_000 if ns is None else ns
    os.utime(path, ns=(when, when))


def held(tmp_path: Path, source: Path = IMPACT_SNAPSHOT) -> Path:
    path = tmp_path / "snapshot.json"
    path.write_bytes(source.read_bytes())
    return path


def reloading(t: serve.Tools, *steps, mode="legacy"):
    heard = []

    async def handler(message):
        if isinstance(message, types.ToolListChangedNotification):
            heard.append(message)

    async def drive():
        out = []
        async with Client(serve.build(t), mode=mode, message_handler=handler) as client:
            for step in steps:
                if callable(step):
                    step()
                    continue
                name, args = step
                got = await client.list_tools(cache_mode="bypass") if name == "list" else await client.call_tool(name, args)
                await anyio.wait_all_tasks_blocked()
                out.append((got, len(heard)))
            return out, client.server_capabilities
    return anyio.run(drive)


def query_description(listed) -> str:
    return {t.name: t for t in listed.tools}["query"].description


def test_a_changed_snapshot_is_reloaded_before_the_call_and_the_tool_list_is_announced(tmp_path, boxes):
    path = held(tmp_path)
    t = tools(path, ROOT, None)
    (before, _), (first, h1), (again, h2), (second, h3), (after, _) = reloading(
        t, ("list", None), COUNT, COUNT, lambda: rewrite(path, CHECK_SNAPSHOT.read_bytes()), COUNT, ("list", None))[0]
    assert first.structured_content["rows"] == again.structured_content["rows"] == [{"c": nodes_in(IMPACT_SNAPSHOT)}]
    assert second.structured_content["rows"] == [{"c": nodes_in(CHECK_SNAPSHOT)}] and nodes_in(CHECK_SNAPSHOT) != nodes_in(IMPACT_SNAPSHOT)
    assert (h1, h2, h3) == (0, 0, 1)
    assert "reload_failed" not in second.structured_content
    assert query_description(before).endswith(serve.cypher.describe(t.graph))
    assert query_description(after).endswith(serve.cypher.describe(serve.co.load(CHECK_SNAPSHOT.read_text(encoding="utf-8"))))
    assert query_description(after) != query_description(before)


def test_the_server_says_it_can_announce_a_changed_tool_list(tmp_path):
    _, capabilities = reloading(tools(held(tmp_path), ROOT, None))
    assert capabilities.tools.list_changed is True


def test_a_reload_reaches_a_client_listening_on_the_2026_wire(tmp_path):
    path = held(tmp_path)
    t = tools(path, ROOT, None)

    async def drive():
        async with Client(serve.build(t)) as client:
            assert client.protocol_version == "2026-07-28"
            async with client.listen(tools_list_changed=True) as events:
                await client.call_tool(*COUNT)
                rewrite(path, CHECK_SNAPSHOT.read_bytes())
                result = await client.call_tool(*COUNT)
                with anyio.fail_after(10):
                    event = await events.__anext__()
                return result, event
    result, event = anyio.run(drive)
    assert result.structured_content["rows"] == [{"c": nodes_in(CHECK_SNAPSHOT)}]
    assert type(event).__name__ == "ToolsListChanged"


@pytest.mark.parametrize("breakage,why", [
    (lambda p: rewrite(p, b'{"nodes": [}'), "JSONDecodeError"),
    (lambda p: rewrite(p, b'{"meta": {}}'), "ValueError: snapshot must have a list of nodes"),
    (lambda p: p.unlink(), "FileNotFoundError"),
], ids=["not-json", "not-a-snapshot", "deleted"])
def test_a_snapshot_that_fails_to_reload_leaves_the_previous_one_and_the_reply_says_why(breakage, why, tmp_path, boxes):
    path = held(tmp_path)
    t = tools(path, ROOT, None)
    steps = reloading(t, COUNT, lambda: breakage(path), COUNT, ("query", {"cypher": "MATCH (n) DELETE n"}), ("list", None),
                      lambda: path.write_bytes(CHECK_SNAPSHOT.read_bytes()), lambda: rewrite(path), COUNT)[0]
    (ok, _), (kept, h1), (refused, _), (listed, _), (fixed, h2) = steps
    old = [{"c": nodes_in(IMPACT_SNAPSHOT)}]
    assert ok.structured_content["rows"] == old and not kept.is_error and kept.structured_content["rows"] == old
    note = kept.structured_content["reload_failed"]
    assert note.startswith(f"the snapshot reload failed: {path} changed on disk but could not be loaded") and why in note
    assert note.endswith("this reply comes from the snapshot loaded before") and json.loads(text_of(kept)) == kept.structured_content
    assert refused.is_error and "refused before running" in text_of(refused) and "the snapshot reload failed" in text_of(refused)
    assert query_description(listed).endswith(serve.cypher.describe(t.graph))
    assert fixed.structured_content["rows"] == [{"c": nodes_in(CHECK_SNAPSHOT)}] and "reload_failed" not in fixed.structured_content
    assert (h1, h2) == (0, 1)


def test_the_snapshot_is_reloaded_when_its_mtime_or_its_size_changes_and_only_then(tmp_path, monkeypatch):
    path = held(tmp_path)
    live = serve.Live(tools(path, ROOT, None))
    loads = []
    real = serve.co.load
    monkeypatch.setattr(serve.co, "load", lambda text: loads.append(len(text)) or real(text))
    assert live.current()[1:] == (False, None) and live.current()[1:] == (False, None) and loads == []
    rewrite(path)
    first, reloaded, failed = live.current()
    assert (reloaded, failed, len(loads)) == (True, None, 1) and first.stamp == serve.stamp_of(path)
    assert live.current()[1] is False and len(loads) == 1
    same_time = path.stat().st_mtime_ns
    rewrite(path, CHECK_SNAPSHOT.read_bytes(), ns=same_time)
    assert path.stat().st_mtime_ns == same_time and path.stat().st_size != first.stamp[1]
    second, reloaded, _ = live.current()
    assert reloaded and len(loads) == 2 and len(second.graph.nodes) == nodes_in(CHECK_SNAPSHOT)
    assert second.schema == serve.cypher.describe(second.graph) != first.schema


def test_a_server_built_from_tools_without_a_snapshot_file_never_reloads(tmp_path):
    t = tools(held(tmp_path), ROOT, None)
    fixed = serve.Tools(t.graph, t.root)
    live = serve.Live(fixed)
    assert live.current() == (fixed, False, None)


def test_the_cli_server_reloads_a_changed_snapshot_over_stdio(tmp_path, no_network):
    path = held(tmp_path)
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    params = StdioServerParameters(command=sys.executable, args=["-m", "decisis.cli", "serve", "--mcp", "--snapshot", str(path)],
                                   env=env, cwd=str(ROOT))
    heard = []

    async def handler(message):
        if isinstance(message, types.ToolListChangedNotification):
            heard.append(message)

    async def drive():
        with anyio.fail_after(60):
            async with Client(params, mode="legacy", message_handler=handler) as client:
                first = await client.call_tool(*COUNT)
                rewrite(path, CHECK_SNAPSHOT.read_bytes())
                second = await client.call_tool(*COUNT)
                await anyio.wait_all_tasks_blocked()
                return first, second, client.server_capabilities
    first, second, capabilities = anyio.run(drive)
    assert first.structured_content["rows"] == [{"c": nodes_in(IMPACT_SNAPSHOT)}]
    assert second.structured_content["rows"] == [{"c": nodes_in(CHECK_SNAPSHOT)}]
    assert capabilities.tools.list_changed is True and len(heard) == 1


def test_a_reload_in_a_call_the_client_cancels_is_announced_by_the_next_call(tmp_path, monkeypatch):
    path = held(tmp_path)
    t = tools(path, ROOT, None)
    gate, real, heard = threading.Event(), serve.co.load, []

    async def handler(message):
        if isinstance(message, types.ToolListChangedNotification):
            heard.append(message)

    def slow_load(text):
        gate.wait(10)
        return real(text)

    async def drive():
        async with Client(serve.build(t), mode="legacy", message_handler=handler) as client:
            first = await client.call_tool(*COUNT)
            monkeypatch.setattr(serve.co, "load", slow_load)
            rewrite(path, CHECK_SNAPSHOT.read_bytes())
            with anyio.move_on_after(0.5):
                await client.call_tool(*COUNT)
            gate.set()
            with anyio.fail_after(10):
                while serve.cypher.describe(serve.co.load(CHECK_SNAPSHOT.read_text(encoding="utf-8"))) not in query_description(
                        await client.list_tools(cache_mode="bypass")):
                    await anyio.sleep(0.05)
            await anyio.wait_all_tasks_blocked()
            unannounced = len(heard)
            monkeypatch.setattr(serve.co, "load", real)
            later = await client.call_tool(*COUNT)
            again = await client.call_tool(*COUNT)
            await anyio.wait_all_tasks_blocked()
            return first, later, again, unannounced
    first, later, again, unannounced = anyio.run(drive)
    assert first.structured_content["rows"] == [{"c": nodes_in(IMPACT_SNAPSHOT)}]
    assert later.structured_content["rows"] == again.structured_content["rows"] == [{"c": nodes_in(CHECK_SNAPSHOT)}]
    assert unannounced == 0 and len(heard) == 1
