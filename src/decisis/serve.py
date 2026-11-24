"""A read-only MCP server over stdio: impact, paths and audit on one snapshot.

Each tool call loads the snapshot into its own sandbox and deletes it before the reply. The sandboxes live
in one private directory that the server removes when stdin closes or on SIGTERM or SIGINT, even while a call runs. No tool writes,
proposes or commits. File reads are limited to the snapshot, the OSV cache given at start, and lockfiles
under the root given at start. Audit asks api.osv.dev only when the server was started with --allow-network.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

import anyio
import jsonschema
from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import audit, external, impact
from . import checkout as co
from .cli import MAX_LIMIT
from .queries import load as query
from .sandbox import Subgraph, default_root, sandbox

MAX_DEPTH = 16
MAX_TEXT = 512
MAX_LOCKFILE_BYTES = 64 * 1024 * 1024
TEXT = {"type": "string", "minLength": 1, "maxLength": MAX_TEXT}

SCHEMAS = {
    "impact": {
        "type": "object",
        "properties": {
            "code_paths": {"type": "array", "items": TEXT, "minItems": 1, "maxItems": MAX_LIMIT,
                           "description": "repository-relative files or directories, for example reports/export.py or storage/"},
            "hops": {"type": "integer", "minimum": 0, "maximum": impact.MAX_HOPS, "default": 3,
                     "description": f"how far from a matching concept to look (0 to {impact.MAX_HOPS})"},
            "repo": {**TEXT, "description": "skip code_refs that name another repository, for example Demo"},
        },
        "required": ["code_paths"],
        "additionalProperties": False,
    },
    "paths": {
        "type": "object",
        "properties": {
            "source": {**TEXT, "description": "a node id in the snapshot"},
            "target": {**TEXT, "description": "a node id in the snapshot"},
            "hops": {"type": "integer", "minimum": 1, "maximum": impact.MAX_HOPS, "default": 4,
                     "description": f"longest path to look for (1 to {impact.MAX_HOPS})"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": 10,
                      "description": f"most paths to return (1 to {MAX_LIMIT})"},
        },
        "required": ["source", "target"],
        "additionalProperties": False,
    },
    "audit": {
        "type": "object",
        "properties": {
            "lockfile": {**TEXT, "description": "an npm lockfile (v2 or v3) under the server's root"},
            "repo": {**TEXT, "description": "repository name as it appears in Vinc code_ref, for example Vinc"},
            "depth": {"type": "integer", "minimum": 1, "maximum": MAX_DEPTH, "default": 8,
                      "description": f"longest dependency path to follow (1 to {MAX_DEPTH})"},
        },
        "required": ["lockfile", "repo"],
        "additionalProperties": False,
    },
}

DESCRIPTIONS = {
    "impact": "List the decisions, records and concepts in the snapshot that govern one or more code paths, "
              "each with its edge path and the evidence on each edge.",
    "paths": "List bounded paths between two node ids in the snapshot.",
    "audit": "Join the snapshot, an npm lockfile and OSV advisories, and report the advisories the repository reaches "
             "and the decisions they break. Reads advisories from the server's OSV cache, or from api.osv.dev only "
             "when the server was started with --allow-network.",
}

INSTRUCTIONS = ("decisis answers read-only questions about one Vinc snapshot in a throwaway Relate graph. "
                "It never writes to Vinc: to record findings, run decisis propose and show the person the write set.")


class Refused(ValueError):
    pass


@dataclass(frozen=True)
class Tools:
    graph: Subgraph
    root: Path
    osv_cache: dict | None = None
    allow_network: bool = False
    scratch: Path | None = None

    def call(self, name: str, arguments: dict | None) -> dict:
        if name not in SCHEMAS:
            raise Refused(f"{name!r} is not a decisis tool; this server is read only and serves {', '.join(SCHEMAS)}")
        args = validated(name, arguments)
        return getattr(self, name)(args)

    def impact(self, args: dict) -> dict:
        repo = args.get("repo")
        for raw in args["code_paths"]:
            inside_repo(raw, repo)
        return impact.run(self.graph, args["code_paths"], args.get("hops", 3), repo, root=self.scratch)

    def paths(self, args: dict) -> dict:
        cypher = query("paths_between", hops=args.get("hops", 4), limit=args.get("limit", 10))
        with sandbox(self.scratch) as box:
            counts = box.load(self.graph)
            rows = box.query(cypher, {"source": args["source"], "target": args["target"]})
        return {"loaded": counts, "paths": rows}

    def audit(self, args: dict) -> dict:
        advisories = self.advisories()
        lock_text = read_under(self.root, args["lockfile"])
        return audit.run(self.graph, lock_text, args["repo"], args.get("depth", 8), advisories=advisories, root=self.scratch)

    def advisories(self):
        if self.osv_cache is not None:
            return external.cached_advisories(self.osv_cache)
        if self.allow_network:
            return external.fetch_advisories
        raise Refused("audit needs advisories: start the server with --osv-cache FILE, or with --allow-network to ask api.osv.dev")


def validated(name: str, arguments: dict | None) -> dict:
    args = {} if arguments is None else arguments
    try:
        jsonschema.validate(args, SCHEMAS[name])
    except jsonschema.ValidationError as e:
        where = "/".join(str(p) for p in e.absolute_path) or "arguments"
        raise Refused(f"{name}: {where}: {e.message}") from None
    return args


def inside_repo(raw: str, repo: str | None) -> str:
    path = impact.code_path(raw, repo)
    if path is None and impact.code_path(raw):
        raise Refused(f"{raw!r} names another repository than {repo}")
    if not path or "\\" in path or "\x00" in path or path.startswith(("/", "~")):
        raise Refused(f"{raw!r} is not a path inside the snapshot's repository")
    if ".." in PurePosixPath(path).parts:
        raise Refused(f"{raw!r} leaves the snapshot's repository")
    return path


def read_under(root: Path, raw: str) -> str:
    candidate = Path(raw) if Path(raw).is_absolute() else root / raw
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        raise Refused(f"{raw!r} cannot be resolved") from None
    if not resolved.is_relative_to(root):
        raise Refused(f"{raw!r} is outside the server's root {root}")
    if not resolved.exists():
        raise Refused(f"{raw!r} does not exist under the server's root")
    if not resolved.is_file():
        raise Refused(f"{raw!r} is not a file")
    if resolved.stat().st_size > MAX_LOCKFILE_BYTES:
        raise Refused(f"{raw!r} is larger than {MAX_LOCKFILE_BYTES} bytes")
    return resolved.read_text(encoding="utf-8")


def tool_list(tools: Tools) -> list[types.Tool]:
    return [types.Tool(name=name, description=DESCRIPTIONS[name], input_schema=schema,
                       annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                                                         open_world_hint=name == "audit" and tools.allow_network))
            for name, schema in SCHEMAS.items()]


def error(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def answer(report: dict) -> types.CallToolResult:
    text = json.dumps(report, ensure_ascii=False, indent=1)
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], structured_content=report)


def outcome(tools: Tools, name: str, arguments: dict | None) -> types.CallToolResult:
    try:
        return answer(tools.call(name, arguments))
    except Refused as e:
        return error(str(e))
    except Exception as e:
        return error(f"{name} failed: {type(e).__name__}: {e}")


def build(tools: Tools) -> Server:
    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tool_list(tools))

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        return await anyio.to_thread.run_sync(outcome, tools, params.name, params.arguments, abandon_on_cancel=True)

    return Server("decisis", instructions=INSTRUCTIONS, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def load_tools(snapshot: Path, root: Path, osv_cache: Path | None = None, allow_network: bool = False) -> Tools:
    graph = co.load(snapshot.read_text(encoding="utf-8"))
    cache = external.read_osv_cache(osv_cache.read_text(encoding="utf-8")) if osv_cache else None
    return Tools(graph, root.resolve(strict=True), cache, allow_network)


async def stdio(server: Server) -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="decisis-serve-", dir=default_root()))


def leave(scratch: Path, code: int) -> None:
    shutil.rmtree(scratch, ignore_errors=True)
    os._exit(code)


def on_signal(scratch: Path):
    def handler(signum, frame):
        leave(scratch, 128 + signum)
    return handler


def main(tools: Tools) -> int:
    scratch = scratch_dir()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal(scratch))
    try:
        anyio.run(stdio, build(replace(tools, scratch=scratch)))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    leave(scratch, 0)
