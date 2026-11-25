"""examples/bookshop commits what each command prints, and these tests run the commands again and compare.

The tests copy the example to a temporary directory and run the commands there, as its README shows them, so
nothing is written into the repository. To rewrite the committed outputs after a change that moves them, run
`DECISIS_GOLDEN=write python -m pytest tests/test_examples.py` and read the diff. The test that drives the
MCP server needs the mcp extra and is skipped without it; it imports mcp inside the test, not at module level.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from test_mcp_clients import serves_the_snapshot

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "bookshop"
README = (EXAMPLE / "README.md").read_text(encoding="utf-8")
WRITE = os.environ.get("DECISIS_GOLDEN") == "write"
DAY = "2026-11-25"
CHANGED = "src/bookshop/ui/catalog.py src/bookshop/payments/charge.py"
AUDIT = f"--repo Bookshop --osv-cache osv-cache.json --today {DAY}"

# (the command as the README shows it, its exit code, the file that holds what it prints, whether the README shows the output)
STEPS = [
    ("decisis init --repo-dir app --repo Bookshop --out snapshot.json", 0, "outputs/init.json", True),
    (f"decisis check snapshot.json --repo-dir app --changed {CHANGED} --reviewers @bob --format text", 1, "outputs/check.txt", True),
    (f"decisis audit snapshot.json app/package-lock.json {AUDIT}", 0, "outputs/audit-lockfile.json", False),
    (f"decisis audit snapshot.json app/package-lock.json {AUDIT} --format mermaid", 0, "outputs/audit-lockfile.md", False),
    (f"decisis audit snapshot.json app/.github/workflows/ci.yml {AUDIT} --format mermaid", 0, "outputs/audit-workflow.md", False),
]
# What an agent asks over MCP, in the order outputs/mcp-session.json records it.
CALLS = [
    ("impact", {"code_paths": ["src/bookshop/payments/charge.py"]}),
    ("check", {"changed": CHANGED.split(), "reviewers": ["@bob"], "today": DAY}),
    ("audit", {"lockfile": "package-lock.json", "repo": "Bookshop", "today": DAY}),
    ("query", {"cypher": "MATCH (r:Record)-[e:ABOUT]->(d:Decision) RETURN r.id AS record, d.id AS decision, e.evidence AS evidence"}),
]


def quiet_env() -> dict:
    return {**os.environ, "PYTHONPATH": str(ROOT / "src"), "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "NO_PROXY": ""}


def committed(name: str, text: str | None = None) -> str:
    path = EXAMPLE / name
    if WRITE and text is not None:
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    work = tmp_path_factory.mktemp("example") / "bookshop"
    shutil.copytree(EXAMPLE, work, ignore=shutil.ignore_patterns("outputs", "snapshot.json"))
    done = {}
    for command, _, _, _ in STEPS:
        words = shlex.split(command)
        assert words[0] == "decisis"
        done[command] = subprocess.run([sys.executable, "-m", "decisis.cli", *words[1:]], cwd=work, capture_output=True, text=True,
                                       encoding="utf-8", env=quiet_env(), timeout=120)
    return work, done


@pytest.mark.parametrize("command,code,name,shown", STEPS)
def test_each_command_exits_as_the_readme_says_and_prints_what_is_committed(command, code, name, shown, ran):
    _, done = ran
    result = done[command]
    assert result.returncode == code and result.stderr == ""
    assert result.stdout == committed(name, result.stdout)
    if shown:
        assert f"$ {command}\n{result.stdout.rstrip()}\n" in README
    else:
        assert f"$ {command}\n" in README and name in README


def test_the_committed_snapshot_is_the_one_init_writes(ran):
    work, _ = ran
    written = (work / "snapshot.json").read_text(encoding="utf-8")
    assert written == committed("snapshot.json", written)
    assert json.loads(written)["meta"]["problems"] == []


def test_the_example_has_what_the_issue_asks_for():
    app = EXAMPLE / "app"
    adrs = sorted((app / "docs" / "adr").glob("*.md"))
    assert len(adrs) >= 3 and all("\nrule:" in a.read_text(encoding="utf-8") for a in adrs)
    assert (app / "package-lock.json").is_file() and list((app / ".github" / "workflows").glob("*.yml"))
    assert (EXAMPLE / "osv-cache.json").is_file()


def test_the_mcp_config_in_the_example_starts_the_server_on_the_committed_snapshot():
    server = json.loads((EXAMPLE / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["decisis"]
    serves_the_snapshot(server["command"], server["args"], where="examples/bookshop/.mcp.json")
    assert server["args"][server["args"].index("--snapshot") + 1] == "snapshot.json"
    assert server["args"][server["args"].index("--root") + 1] == "app"
    assert (EXAMPLE / "osv-cache.json").is_file() and (EXAMPLE / "snapshot.json").is_file()


def test_the_readme_shows_each_mcp_call_and_the_committed_session_holds_what_the_server_returns(ran):
    pytest.importorskip("mcp")
    pytest.importorskip("jsonschema")
    import anyio
    from mcp import Client, StdioServerParameters
    work, _ = ran
    server = json.loads((EXAMPLE / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["decisis"]
    params = StdioServerParameters(command=sys.executable, args=["-m", "decisis.cli", *server["args"]], env=quiet_env(), cwd=str(work))

    async def drive():
        with anyio.fail_after(120):
            async with Client(params) as client:
                tools = sorted(t.name for t in (await client.list_tools()).tools)
                calls = []
                for name, arguments in CALLS:
                    reply = await client.call_tool(name, arguments)
                    assert not reply.is_error
                    calls.append({"tool": name, "arguments": arguments, "result": reply.structured_content})
                return {"server": server, "tools": tools, "calls": calls}
    session = json.dumps(anyio.run(drive), indent=1, ensure_ascii=False) + "\n"
    assert session == committed("outputs/mcp-session.json", session)
    for name, arguments in CALLS:
        assert json.dumps({"tool": name, "arguments": arguments}) in README
