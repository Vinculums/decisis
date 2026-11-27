from __future__ import annotations

import datetime
import json
import re
import shlex
import tomllib
from pathlib import Path

import pytest

from decisis import cli

ROOT = Path(__file__).resolve().parents[1]
MCP_DOC = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")

TOOLS = {
    "Claude Code": [".mcp.json", "~/.claude.json"],
    "Cursor": [".cursor/mcp.json", "~/.cursor/mcp.json"],
    "Windsurf": ["~/.config/devin/mcp_config.json", ".devin/mcp_config.json"],
    "VS Code": [".mcp.json", "~/.copilot/mcp-config.json", ".vscode/mcp.json"],
    "OpenAI Codex CLI": ["~/.codex/config.toml", ".codex/config.toml"],
}
TOP_LEVEL_KEYS = ("mcpServers", "servers")
FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)


def sections() -> dict[str, str]:
    start = MCP_DOC.index("\n## Set up your tool")
    body = MCP_DOC[start + 1:MCP_DOC.index("\n## ", start + 1)]
    parts = re.split(r"^### ", body, flags=re.M)[1:]
    return {part.split("\n", 1)[0]: part for part in parts}


def section_of(tool: str) -> tuple[str, str]:
    [(title, text)] = [(t, s) for t, s in sections().items() if t.startswith(tool)]
    return title, text


def serves_the_snapshot(command: str, args: list[str], *, where: str) -> None:
    assert command == "decisis", where
    assert args[:2] == ["serve", "--mcp"], where
    for flag in ("--snapshot", "--osv-cache"):
        assert flag in args, f"{where}: {flag} is missing"
        value = args[args.index(flag) + 1]
        assert value and not value.startswith("--"), f"{where}: {flag} has no value"


def server_entries(text: str) -> list[tuple[str, str, dict]]:
    found = []
    for lang, block in FENCE.findall(text):
        if lang == "json":
            data = json.loads(block)
            key = next(k for k in TOP_LEVEL_KEYS if k in data)
            found.append((lang, key, data[key]["decisis"]))
        elif lang == "toml":
            found.append((lang, "mcp_servers", tomllib.loads(block)["mcp_servers"]["decisis"]))
    return found


def add_commands(text: str, tool: str) -> list[list[str]]:
    lines = [line.strip() for _, block in FENCE.findall(text) for line in block.splitlines()]
    return [shlex.split(line) for line in lines if line.startswith(f"{tool} mcp add ")]


def test_the_doc_has_a_section_for_each_tool_the_issue_names():
    titles = list(sections())
    assert [t for t in titles if any(t.startswith(tool) for tool in TOOLS)] == titles
    assert len(titles) == len(TOOLS)


@pytest.mark.parametrize("tool", TOOLS)
def test_each_snippet_runs_decisis_serve_mcp_with_a_snapshot_and_an_osv_cache(tool):
    title, text = section_of(tool)
    entries = server_entries(text)
    assert entries, f"{title} has no config snippet"
    for lang, key, entry in entries:
        serves_the_snapshot(entry["command"], entry["args"], where=f"{title} ({lang}, {key})")


@pytest.mark.parametrize("tool,cli_name", [("Claude Code", "claude"), ("OpenAI Codex CLI", "codex")])
def test_the_add_command_of_a_tool_that_has_one_runs_the_same_server(tool, cli_name):
    _, text = section_of(tool)
    [words] = add_commands(text, cli_name)
    assert words[:4] == [cli_name, "mcp", "add", "decisis"] and words[4] == "--"
    serves_the_snapshot(words[5], words[6:], where=f"{tool} {cli_name} mcp add")


@pytest.mark.parametrize("tool,files", TOOLS.items())
def test_each_section_names_its_config_files_where_relative_paths_are_read_from_and_the_page_it_was_checked_against(tool, files):
    title, text = section_of(tool)
    config = re.search(r"^\*\*Config file:\*\*(.*?)(?=\n\n|\Z)", text, re.S | re.M)
    assert config, f"{title} has no Config file line"
    for path in files:
        assert f"`{path}`" in config.group(1), f"{title} does not name {path}"
    assert re.search(r"^\*\*Relative paths:\*\* \S", text, re.M), f"{title} does not say where relative paths are read from"
    checked = re.search(r"^\*\*Checked:\*\*(.*?)(?=\n\n|\Z)", text, re.S | re.M)
    assert checked, f"{title} has no Checked line"
    assert re.search(r"\]\(https://[^)\s]+\)", checked.group(1)), f"{title} does not link the page it checked"
    day = re.search(r"\bon\s+(\d{4}-\d{2}-\d{2})\.", checked.group(1))
    assert day and datetime.date.fromisoformat(day.group(1)) >= datetime.date(2026, 11, 25)


def test_every_flag_in_a_snippet_is_a_flag_decisis_serve_has(capsys):
    capsys.readouterr()
    with pytest.raises(SystemExit) as stop:
        cli.main(["serve", "--help"])
    assert stop.value.code == 0
    known = set(re.findall(r"--[a-z][a-z-]*", capsys.readouterr().out))
    assert {"--mcp", "--snapshot", "--osv-cache", "--root"} <= known
    used = set()
    for title, text in sections().items():
        for _, _, entry in server_entries(text):
            used |= {a for a in entry["args"] if a.startswith("--")}
        for tool in ("claude", "codex"):
            for words in add_commands(text, tool):
                used |= {w for w in words[words.index("--") + 1:] if w.startswith("--")}
    assert used and used <= known
