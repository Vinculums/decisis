"""A read-only MCP server over stdio: impact, paths, audit, check and query on one snapshot.

Before each tool call the server compares the snapshot file's mtime and size with the copy it holds and reloads it
when either changed; a file that fails to load leaves the previous copy in place and the reply says so. After a
reload the query tool's schema is rebuilt and the server sends notifications/tools/list_changed from the first call
that completes, so a reload inside a call the client cancelled is announced by the next one.
Each tool call loads the snapshot into its own sandbox and deletes it before the reply. The sandboxes live
in one private directory that the server removes when stdin closes or on SIGTERM or SIGINT, even while a call runs,
and that records its owner so that decisis gc removes it after a SIGKILL. No tool writes,
proposes or commits; query refuses write clauses before it runs and runs on a read-only connection. File reads
are limited to the snapshot, the OSV cache given at start, and lockfiles and changed files under the root given at start.
Audit asks api.osv.dev only when the server was started with --allow-network. Check runs git diff only through the
hardened helper check --base uses, with a ref that cannot pass for an option.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import threading
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

import anyio
import jsonschema
from mcp import types
from mcp.server import Server
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.stdio import stdio_server
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler, ToolsListChanged

from . import audit, check, compact, cypher, external, impact, inventory
from . import checkout as co
from .cli import MAX_LIMIT
from .queries import load as query
from .sandbox import SERVE_PREFIX, NotReadOnly, Subgraph, default_root, owned_dir, sandbox

MAX_DEPTH = 16
MAX_TEXT = 512
MAX_LOCKFILE_BYTES = 64 * 1024 * 1024
TEXT = {"type": "string", "minLength": 1, "maxLength": MAX_TEXT}
MAX_PARAMS = 32
MAX_REVIEWERS = 256
MAX_SENT = cypher.MAX_BYTES
DETAIL = {"type": "string", "enum": list(compact.DETAILS), "default": "summary",
          "description": f"summary (the default): counts, ids, titles and the first {compact.FIRST} items of each list; "
                         "full: the whole report"}

SCHEMAS = {
    "impact": {
        "type": "object",
        "properties": {
            "code_paths": {"type": "array", "items": TEXT, "minItems": 1, "maxItems": MAX_LIMIT,
                           "description": "repository-relative files or directories, for example reports/export.py or storage/"},
            "hops": {"type": "integer", "minimum": 0, "maximum": impact.MAX_HOPS, "default": 3,
                     "description": f"how far from a matching concept to look (0 to {impact.MAX_HOPS})"},
            "repo": {**TEXT, "description": "skip code_refs that name another repository, for example Demo"},
            "detail": DETAIL,
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
            "detail": DETAIL,
        },
        "required": ["source", "target"],
        "additionalProperties": False,
    },
    "audit": {
        "type": "object",
        "properties": {
            "lockfile": {**TEXT, "description": "a lockfile or SBOM under the server's root (the formats audit reads)"},
            "repo": {**TEXT, "description": "repository name as it appears in Vinc code_ref, for example Vinc"},
            "depth": {"type": "integer", "minimum": 1, "maximum": MAX_DEPTH, "default": 8,
                      "description": f"longest dependency path to follow (1 to {MAX_DEPTH})"},
            "detail": DETAIL,
        },
        "required": ["lockfile", "repo"],
        "additionalProperties": False,
    },
    "check": {
        "type": "object",
        "properties": {
            "changed": {"type": "array", "items": TEXT, "minItems": 1, "maxItems": check.MAX_CHANGED,
                        "description": "the changed files, relative to the server's root; give this or base"},
            "base": {**TEXT, "description": "a git ref; the changed files are git diff --name-only base...HEAD in the server's root; "
                                            "give this or changed"},
            "reviewers": {"type": "array", "items": TEXT, "maxItems": MAX_REVIEWERS, "default": [],
                          "description": "the handles that reviewed the change, for example @alice or @org/team"},
            "detail": DETAIL,
        },
        "additionalProperties": False,
    },
    "query": {
        "type": "object",
        "properties": {
            "cypher": {"type": "string", "minLength": 1, "maxLength": cypher.MAX_CYPHER,
                       "description": "one read-only Cypher statement; refer to values as $name and pass them in params"},
            "params": {"type": "object", "maxProperties": MAX_PARAMS, "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]{0,63}$"},
                       "description": "values for the $name parameters in cypher"},
            "detail": DETAIL,
        },
        "required": ["cypher"],
        "additionalProperties": False,
    },
}

DESCRIPTIONS = {
    "impact": "List the decisions, records and concepts in the snapshot that govern one or more code paths, "
              "each with its edge path and the evidence on each edge.",
    "paths": "List bounded paths between two node ids in the snapshot.",
    "audit": "Join the snapshot, a lockfile or SBOM and OSV advisories, and report the advisories the repository reaches "
             "and the decisions they break. Reads advisories from the server's OSV cache, or from api.osv.dev only "
             "when the server was started with --allow-network.",
    "check": "Judge a change set against the review and import rules of the decisions in the snapshot, as decisis check does. "
             "Give changed (files under the server's root) or base (a git ref, for git diff base...HEAD in the root), and the "
             "reviewers. Returns the governing decisions, the violations with file, line, decision and rule, and what cannot be "
             "judged. The changed files are read under the root and never run.",
    "query": "Run one read-only Cypher statement on a fresh sandbox of the snapshot and return its rows. Use it for a question "
             "the fixed tools do not answer: impact for the decisions on code paths, paths between two ids, audit for a "
             "lockfile. CREATE, MERGE, SET, DELETE, REMOVE, LOAD CSV, admin clauses and procedures other than the db.labels "
             f"family are refused before the query runs. Results stop at {cypher.MAX_ROWS} rows and {cypher.MAX_BYTES} bytes "
             "with a note when cut, and a query that runs past the server's time limit is stopped.",
}

INSTRUCTIONS = ("decisis answers read-only questions about one Vinc snapshot in a throwaway Relate graph. "
                "Ask impact, paths, audit and check first; use query with read-only Cypher for a question they do not answer. "
                "Call check with base or changed to judge a change before it is committed. "
                "Each tool returns a summary unless called with detail \"full\". "
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
    schema: str = ""
    snapshot: Path | None = None
    stamp: tuple[int, int] | None = None

    def __post_init__(self):
        if not self.schema:
            object.__setattr__(self, "schema", cypher.describe(self.graph))

    def call(self, name: str, arguments: dict | None) -> dict:
        if name not in SCHEMAS:
            raise Refused(f"{name!r} is not a decisis tool; this server is read only and serves {', '.join(SCHEMAS)}")
        args = validated(name, arguments)
        return compact.shape(name, getattr(self, name)(args), args.get("detail", "summary"))

    def query(self, args: dict) -> dict:
        try:
            return cypher.run(self.graph, args["cypher"], args.get("params") or {}, root=self.scratch)
        except NotReadOnly as e:
            raise Refused(f"query: {e}") from None

    def impact(self, args: dict) -> dict:
        repo = args.get("repo")
        for raw in args["code_paths"]:
            inside_repo(raw, repo)
        return impact.run(self.graph, args["code_paths"], args.get("hops", 3), repo, root=self.scratch)

    def check(self, args: dict) -> dict:
        given = [k for k in ("changed", "base") if k in args]
        if len(given) != 1:
            raise Refused("check: give changed (files under the server's root) or base (a git ref), exactly one of them")
        if not self.root.is_dir():
            raise Refused(f"check: the server's root {self.root} is not a directory")
        try:
            changed = (check.changed_since(self.root, git_ref(args["base"])) if "base" in args
                       else [inside_root(self.root, raw) for raw in args["changed"]])
            return check.run(self.graph, changed, self.root, args.get("reviewers", []), base=args.get("base"),
                             sandbox_root=self.scratch)
        except Refused:
            raise
        except ValueError as e:
            raise Refused(f"check: {e}") from None

    def paths(self, args: dict) -> dict:
        cypher = query("paths_between", hops=args.get("hops", 4), limit=args.get("limit", 10))
        with sandbox(self.scratch) as box:
            counts = box.load(self.graph)
            rows = box.query(cypher, {"source": args["source"], "target": args["target"]})
        return {"loaded": counts, "paths": rows}

    def audit(self, args: dict) -> dict:
        advisories = self.advisories()
        if inventory.bun.binary(resolve_under(self.root, args["lockfile"])):
            raise Refused(inventory.bun.refusal(PurePosixPath(args["lockfile"]).name))
        lock_text = read_under(self.root, args["lockfile"])
        name = PurePosixPath(args["lockfile"]).name
        siblings = self.siblings(args["lockfile"], lock_text, name)
        return audit.run(self.graph, lock_text, args["repo"], args.get("depth", 8), advisories=advisories, root=self.scratch,
                         filename=name, siblings=siblings)

    def siblings(self, raw: str, text: str, name: str) -> dict[str, str]:
        parent = PurePosixPath(raw).parent
        return inventory.gather(text, name, lambda rel: read_under(self.root, str(parent / rel)),
                                lambda rel: str(resolve_under(self.root, str(parent / rel))))

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


def inside_root(root: Path, raw: str) -> str:
    if not raw.strip() or "\\" in raw or any(unicodedata.category(c).startswith("C") for c in raw) or raw.startswith(("/", "~")):
        raise Refused(f"{raw!r} is not a path inside the server's root")
    if ".." in PurePosixPath(raw).parts:
        raise Refused(f"{raw!r} leaves the server's root")
    resolve_under(root, raw)
    return raw


def git_ref(raw: str) -> str:
    if raw.startswith("-") or any(c.isspace() or unicodedata.category(c).startswith("C") for c in raw):
        raise Refused(f"check: base must name a commit, not {raw!r}: it may not start with - or hold whitespace or a control character")
    return raw


def resolve_under(root: Path, raw: str) -> Path:
    candidate = Path(raw) if Path(raw).is_absolute() else root / raw
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        raise Refused(f"{raw!r} cannot be resolved") from None
    if not resolved.is_relative_to(root):
        raise Refused(f"{raw!r} is outside the server's root {root}")
    return resolved


def read_under(root: Path, raw: str) -> str:
    resolved = resolve_under(root, raw)
    if not resolved.exists():
        raise Refused(f"{raw!r} does not exist under the server's root")
    if not resolved.is_file():
        raise Refused(f"{raw!r} is not a file")
    if resolved.stat().st_size > MAX_LOCKFILE_BYTES:
        raise Refused(f"{raw!r} is larger than {MAX_LOCKFILE_BYTES} bytes")
    return resolved.read_text(encoding="utf-8")


def tool_list(tools: Tools) -> list[types.Tool]:
    return [types.Tool(name=name, description=description(tools, name), input_schema=schema,
                       annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                                                         open_world_hint=name == "audit" and tools.allow_network))
            for name, schema in SCHEMAS.items()]


def description(tools: Tools, name: str) -> str:
    return DESCRIPTIONS[name] + ("\n\n" + tools.schema if name == "query" else "")


def error(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def answer(report: dict) -> types.CallToolResult:
    text = json.dumps(report, ensure_ascii=False, indent=1)
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], structured_content=report)


def sent_size(report: dict) -> int:
    return len(answer(report).model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))


def stamp_of(path: Path) -> tuple[int, int]:
    seen = path.stat()
    return seen.st_mtime_ns, seen.st_size


class Live:
    def __init__(self, tools: Tools):
        self.tools = tools
        self.lock = threading.Lock()
        self.reloads = 0
        self.announced = 0

    def current(self) -> tuple[Tools, bool, str | None]:
        with self.lock:
            held = self.tools
            if held.snapshot is None:
                return held, False, None
            try:
                seen = stamp_of(held.snapshot)
                if seen == held.stamp:
                    return held, False, None
                self.tools = replace(held, graph=co.load(held.snapshot.read_text(encoding="utf-8")), schema="", stamp=seen)
            except Exception as e:
                return held, False, f"{type(e).__name__}: {e}"
            self.reloads += 1
            return self.tools, True, None

    def unannounced(self) -> int:
        with self.lock:
            return self.reloads if self.reloads > self.announced else 0

    def announce(self, reload: int) -> None:
        with self.lock:
            self.announced = max(self.announced, reload)


def reload_note(tools: Tools, why: str) -> str:
    return (f"the snapshot reload failed: {tools.snapshot} changed on disk but could not be loaded ({why}); "
            "this reply comes from the snapshot loaded before")


def respond(tools: Tools, name: str, arguments: dict | None, failed: str | None = None) -> types.CallToolResult:
    note = reload_note(tools, failed) if failed else None
    try:
        report = tools.call(name, arguments)
        return answer(compact.fit({**report, "reload_failed": note} if note else report, sent_size, MAX_SENT))
    except Refused as e:
        message = str(e)
    except Exception as e:
        message = f"{name} failed: {type(e).__name__}: {e}"
    return error(f"{message}\n\n{note}" if note else message)


def outcome(live: Live, name: str, arguments: dict | None) -> types.CallToolResult:
    tools, _, failed = live.current()
    return respond(tools, name, arguments, failed)


class ReloadingServer(Server):
    def create_initialization_options(self, notification_options: NotificationOptions | None = None, *args, **kwargs):
        return super().create_initialization_options(notification_options or NotificationOptions(tools_changed=True), *args, **kwargs)


def build(tools: Tools) -> Server:
    live = Live(tools)
    bus = InMemorySubscriptionBus()

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tool_list(live.tools))

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        result = await anyio.to_thread.run_sync(outcome, live, params.name, params.arguments, abandon_on_cancel=True)
        reload = live.unannounced()
        if reload:
            await ctx.session.send_tool_list_changed()
            await bus.publish(ToolsListChanged())
            live.announce(reload)
        return result

    return ReloadingServer("decisis", instructions=INSTRUCTIONS, on_list_tools=on_list_tools, on_call_tool=on_call_tool,
                           on_subscriptions_listen=ListenHandler(bus))


def load_tools(snapshot: Path, root: Path, osv_cache: Path | None = None, allow_network: bool = False) -> Tools:
    path = snapshot.absolute()
    seen = stamp_of(path)
    graph = co.load(path.read_text(encoding="utf-8"))
    cache = external.read_osv_cache(osv_cache.read_text(encoding="utf-8")) if osv_cache else None
    return Tools(graph, root.resolve(strict=True), cache, allow_network, snapshot=path, stamp=seen)


async def stdio(server: Server) -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def scratch_dir() -> Path:
    return owned_dir(default_root(), SERVE_PREFIX)


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
