# Use decisis from an AI agent

## The skill

[`skills/decisis/SKILL.md`](../skills/decisis/SKILL.md) is a skill for a coding agent such as Claude Code. It
covers when to reach for `audit`, `impact` or `paths`, how to check out only what the task names, how to
read a finding, and the rule that the agent shows the write set and digest to the person and stops. The
agent never approves its own write. To use it, copy the directory to where your agent loads skills (for
Claude Code, `.claude/skills/decisis/`) and put `decisis` on the agent's `PATH`.

decisis itself calls no language model. The agent is the reasoner that chooses seeds, runs the bounded
queries and explains the paths; the tool gives it a graph it cannot write to, findings that carry their
evidence, and a write path that needs a person's digest.

## Serve it over MCP

`decisis serve --mcp` gives an agent the same `impact`, `paths`, `audit`, `check`, `search` and `query` as MCP tools over
stdio, on the snapshot file named when the server starts. It needs the optional `mcp` extra; the base install keeps
`relate-db` and `PyYAML` as its only dependencies:

```
pip install "decisis[mcp]"
```

Every tool starts the same command: `decisis serve --mcp --snapshot <snapshot> --osv-cache <cache>`, and the
sections below say where each one keeps its config file. `--root` is the directory that `audit` reads lockfiles
from and `check` reads changed files from; it defaults to the directory the server starts in.

decisis reads a relative path from the directory the server starts in, and the tools below do not all say which
directory that is, so each section names what its documentation says and what to use instead.

The server has no tool that writes, proposes or commits; `check` only reads files and
runs `git diff`. The tools take the same
bounds as the commands (`hops` 0 to 6 for `impact`, 1 to 6 for `paths`, `limit` 1 to 100; `audit` takes
`depth` 1 to 16), refuse a code path outside the repository, and build and delete a sandbox for each call.
`audit` takes the lockfile path as an argument and reads it only under `--root` (default: the current
directory), after following symlinks. It reads advisories from `--osv-cache`; without a cache it asks
api.osv.dev only when the server was started with `--allow-network`, and otherwise returns an error.

## Set up your tool

Each section gives the config file, a snippet that runs `decisis serve --mcp --snapshot ... --osv-cache ...`,
where relative paths are read from, and the documentation page the format was checked against with the date. A
test parses every snippet below and checks that it runs `decisis serve --mcp` with `--snapshot` and `--osv-cache`
(`tests/test_mcp_clients.py`). These tools change their formats often: if a page says something other than what
is written here, follow the page and open an issue.

### Claude Code

**Config file:** `.mcp.json` at the project root for a server the team shares through version control; the local
and user scopes live in `~/.claude.json`. `claude mcp add --scope project` writes the project entry.

```
claude mcp add decisis -- decisis serve --mcp --snapshot snapshot.json --osv-cache osv-cache.json
```

The same entry in `.mcp.json`:

```json
{
  "mcpServers": {
    "decisis": {
      "command": "decisis",
      "args": ["serve", "--mcp", "--snapshot", "snapshot.json", "--osv-cache", "osv-cache.json"]
    }
  }
}
```

**Relative paths:** the page does not say which directory Claude Code starts a stdio server in. It sets
`CLAUDE_PROJECT_DIR` in the server's environment, which decisis does not read, and `${CLAUDE_PROJECT_DIR:-.}` in
`.mcp.json` falls back to `.` because the variable is not set where Claude Code expands it. If the server cannot
find the files, give absolute paths and add `--root /path/to/project`.

**Checked:** against [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp) on 2026-11-25.

### Cursor

**Config file:** `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for every project you open.

```json
{
  "mcpServers": {
    "decisis": {
      "type": "stdio",
      "command": "decisis",
      "args": ["serve", "--mcp", "--snapshot", "${workspaceFolder}/snapshot.json", "--osv-cache", "${workspaceFolder}/osv-cache.json", "--root", "${workspaceFolder}"]
    }
  }
}
```

**Relative paths:** the page does not say which directory a relative path in `args` is read from. It does document
`${workspaceFolder}`, "the folder that contains `.cursor/mcp.json`", in `command`, `args`, `env`, `url` and
`headers`, so the snippet uses it. In `~/.cursor/mcp.json` there is no project folder: write absolute paths.

**Checked:** against [Model Context Protocol (MCP)](https://cursor.com/docs/mcp) (the older address
`cursor.com/docs/context/mcp` redirects there) on 2026-11-25.

### Windsurf (now Devin Desktop)

Windsurf's desktop app is now Devin Desktop, and `docs.windsurf.com` redirects to `docs.devin.ai`.

**Config file:** the file that Cascade's **Open MCP config file** action opens: `~/.config/devin/mcp_config.json`
on macOS and Linux (`$XDG_CONFIG_HOME/devin/mcp_config.json` when that is set), `%AppData%/devin/mcp_config.json`
on Windows. The Devin Local agent also reads `.devin/mcp_config.json` in the project, shared through version
control, and `.devin/mcp_config.local.json` for a personal override. The editor's MCP discovery reads a separate
file, `~/.codeium/windsurf/mcp_config.json`, when the `windsurf` source of `chat.mcp.discovery.enabled` is on.

```json
{
  "mcpServers": {
    "decisis": {
      "command": "decisis",
      "args": ["serve", "--mcp", "--snapshot", "/path/to/project/snapshot.json", "--osv-cache", "/path/to/project/osv-cache.json", "--root", "/path/to/project"]
    }
  }
}
```

**Relative paths:** none of the pages below says which directory a stdio server starts in, and the stdio fields
they list (`command`, `args`, `env`, `disabled`) have no working directory. Give absolute paths, as above.

**Checked:** against [Windsurf Cascade MCP configuration](https://docs.devin.ai/windsurf/plugins/cascade/mcp) (the
Devin configuration directory, `mcpServers`, `env` and interpolation),
[Devin Local Customizations](https://docs.devin.ai/desktop/devin-local/customizations) (the project, local and user
files; `docs.windsurf.com/windsurf/cascade/mcp` redirects to it) and
[MCP Configuration](https://docs.devin.ai/cli/extensibility/mcp/configuration) (the stdio fields) on 2026-11-25.
The pages name three user-level files: the Devin configuration directory above, `~/.codeium/windsurf/mcp_config.json`,
and `~/.codeium/mcp_config.json` in the [Devin Desktop FAQ](https://docs.devin.ai/desktop/devin-desktop-faq). Open the
file from the Cascade menu to be sure which one your build reads.

### VS Code (GitHub Copilot agent mode)

VS Code's current documentation does not use the term agent mode. It describes the Copilot harness, which reads
its own MCP files, and calls the older editor-managed configuration the Local harness, deprecated and to be
removed in February 2027.

**Config file:** for a new setup, `.mcp.json` at the workspace root to share a server with the team, or
`~/.copilot/mcp-config.json` (`$COPILOT_HOME/mcp-config.json` when that is set) for every workspace. Both use
a top-level `mcpServers` object. The editor-managed `.vscode/mcp.json` and the profile `mcp.json` use `servers`
instead (second snippet); the page says not to use them for a new Copilot configuration.

```json
{
  "mcpServers": {
    "decisis": {
      "type": "stdio",
      "command": "decisis",
      "args": ["serve", "--mcp", "--snapshot", "snapshot.json", "--osv-cache", "osv-cache.json"],
      "tools": ["*"]
    }
  }
}
```

An existing `.vscode/mcp.json`, which the Local harness reads:

```json
{
  "servers": {
    "decisis": {
      "type": "stdio",
      "command": "decisis",
      "args": ["serve", "--mcp", "--snapshot", "${workspaceFolder}/snapshot.json", "--osv-cache", "${workspaceFolder}/osv-cache.json", "--root", "${workspaceFolder}"]
    }
  }
}
```

**Relative paths:** for `.mcp.json` and `mcp-config.json` the page does not say which directory the Copilot
harness starts a stdio server in. It lists `cwd` ("Working directory") as a stdio field, so set `"cwd":
"/path/to/project"` or give absolute paths. For `.vscode/mcp.json`, `cwd` "defaults to the workspace folder when
run in a workspace" and `${workspaceFolder}` is documented, as in the second snippet.

**Checked:** against [MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
(the older address `code.visualstudio.com/docs/copilot/reference/mcp-configuration` redirects there) on 2026-11-25.

### OpenAI Codex CLI

**Config file:** `~/.codex/config.toml`, or `.codex/config.toml` to scope a server to a project (trusted projects
only). The Codex CLI, its IDE extension and the ChatGPT desktop app share this file.

```
codex mcp add decisis -- decisis serve --mcp --snapshot snapshot.json --osv-cache osv-cache.json
```

The same server as a TOML table:

```toml
[mcp_servers.decisis]
command = "decisis"
args = ["serve", "--mcp", "--snapshot", "snapshot.json", "--osv-cache", "osv-cache.json"]
cwd = "/path/to/project"
```

**Relative paths:** `cwd` is "Working directory to start the server from"; the page does not say what the
default is and gives no example of a relative path. Set `cwd` to the project, as above, and the relative paths
are read from it.

**Checked:** against [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) (the older
address `developers.openai.com/codex/mcp` redirects there) on 2026-11-25.

## Try it on a worked example

[`examples/bookshop`](../examples/bookshop/README.md) is a small application with ADRs that carry rules, a
lockfile and a workflow. It runs `init`, `check`, `audit` and these MCP tools on it, with every output committed
and a test that the commands print what is committed.

## Judge a change with `check`

`check` lets an agent judge its own change before it commits, without leaving the MCP session. It judges
the repository under `--root` exactly as `decisis check --repo-dir <root>` does and returns the same
report. Give one of:

- `changed`: the changed files, relative to `--root`, for example `["src/shop/ui/view.py"]`. A path that
  is absolute, starts with `~`, holds `..`, a backslash or a control character, or resolves outside
  `--root` through a symlink is refused, as `impact` refuses one.
- `base`: a git ref. The changed files are `git diff --name-only <base>...HEAD` in `--root`, run through
  the same hardened git helper and 120 second timeout as `check --base`: the repository's hooks, fsmonitor
  and pager are not run, and `GIT_*` variables are dropped. A `base` that starts with `-` or holds
  whitespace or a control character is refused before git runs.

and optionally `reviewers`, the handles that reviewed the change (for example `["@alice", "@org/team"]`).
The summary gives the counts, the governing decisions, and the first 10 violations and unjudged entries
with the file, the line, the decision, the rule and why; `"detail": "full"` gives the report
`decisis check` prints. Read `unresolved` as not judged, never as a pass. When a CODEOWNERS owner set covers a changed file
that no `review_required` rule covers, the reply lists the file and its owners under `codeowners`, as information: decisis does
not enforce CODEOWNERS, and the list changes no verdict. `check` and `audit` also take
`warn_days`, 0 to 3650 (default 14): the reply lists under `expiring_soon`, apart from the waived results,
the waivers that cover a result and expire within that many days of `today`, and 0 turns the list off. It
changes no verdict (see [Waivers](data-model.md#waivers)).

## A changed snapshot is reloaded

Long agent sessions outlive the snapshot the server started with. Before each tool call the server
compares the snapshot file's mtime and size with the copy it holds, and reloads the file when either
changed; the call is then answered from the new snapshot. After a reload the schema in the `query`
tool's description is rebuilt, and the server sends `notifications/tools/list_changed` (on the
2026-07-28 protocol, a `ToolsListChanged` event to clients listening with `subscriptions/listen`), so
the client lists the tools again. The announcement goes out from the first call that completes after the
reload: a reload inside a call the client cancelled is announced by the next call. If the new file fails to load, for example while it is still being
written, the server keeps the previous snapshot, answers from it, and says so: a reply carries
`reload_failed` with the reason, and an error result ends with the same note. The next call tries again.
To replace a snapshot without a failed reload in between, write the new file next to it and rename it
over the old one. The OSV cache and `--root` stay as they were at start.

Each tool takes `detail`: `"summary"`, the default over MCP, gives counts, ids, titles and the first 10
items of each list with a note on how to get the rest; `"full"` gives the whole report, the same JSON the
command prints. The commands always print the whole report.

## When to use `query` and when the fixed tools

Ask the fixed tools first. `impact` answers which decisions and records govern a code path, and follows
only the edges that carry governance, in their governing direction; `paths` lists the routes between two
ids; `audit` joins a lockfile and advisories with the snapshot and judges each decision's rule. Their
answers carry the evidence on each edge, and the same question gets the same report every time.

Use `query` for a question they do not answer: which decisions have no `ABOUT` edge, how many records
each concept has, which nodes name a field, a path that must pass through a given kind. It runs one
read-only Cypher statement on a fresh sandbox of the server's snapshot and returns the rows:

```
decisis query fixtures/impact/vinc.json 'MATCH p = (g)-[*1..3]->(c) WHERE c.code_ref CONTAINS $path AND (g:Decision OR g:Record) RETURN DISTINCT g.id AS id ORDER BY id' --param path=storage/page_store.py
```

The tool's description carries the snapshot's schema, made when the server starts: each label (a node
kind with the first letter in upper case) with its count and property keys, each edge type with its
count and the labels it joins, and two example queries. A query must be one statement that starts with
`MATCH`, `OPTIONAL MATCH`, `WITH`, `UNWIND`, `RETURN` or `CALL`. The text is checked before anything
runs: `CREATE`, `MERGE`, `SET`, `DELETE`, `REMOVE`, `FOREACH`, `LOAD CSV`, `DROP`, `SHOW`, `USE` and the
other admin clauses are refused in any case, after comments and inside subqueries, and only the
`db.labels`, `db.relationshipTypes`, `db.propertyKeys` and `db.schema.*` procedures may be called. Clause
words inside strings, comments and backticked names do not count; a label, type or key named like a clause
goes in backticks. Relate plans every `CALL { }` subquery as read-write, so those are refused too; use
`COLLECT { }`, `COUNT { }`, `EXISTS { }` or `UNION`. Then the query process plans the statement with
`EXPLAIN` on a read-only connection and runs it only when Relate plans it as a read, and the read-only
connection refuses any write on its own. Results stop at 500 rows and 1 MiB with a note that says how many
rows there were, and every MCP reply, as the server sends it, stays under 1 MiB: in full detail the
longest list is shortened and a `cut` note says so. The schema names come from the snapshot: names that
are not plain ASCII identifiers are shown in backticks, and long or unprintable ones are left out.
The node, edge and time limits are the ones in [commands.md](commands.md#limits). Nodes, edges and paths come back as
labels or type and properties; return ids and properties to keep the rows small.
