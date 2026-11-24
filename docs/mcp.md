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

`decisis serve --mcp` gives an agent the same `impact`, `paths`, `audit` and `query` as MCP tools over stdio, on
one snapshot fixed when the server starts. It needs the optional `mcp` extra; the base install keeps
`relate-db` and `PyYAML` as its only dependencies. For Claude Code:

```
pip install "decisis[mcp]"
claude mcp add decisis -- decisis serve --mcp --snapshot snapshot.json --osv-cache osv-cache.json
```

`claude mcp add --scope project ...` writes the same entry to `.mcp.json` in the project, to share it
with the team:

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

Relative paths are read from the directory the server starts in; use absolute paths if you are not sure
which one that is. The server has no tool that writes, proposes or commits. The tools take the same
bounds as the commands (`hops` 0 to 6 for `impact`, 1 to 6 for `paths`, `limit` 1 to 100; `audit` takes
`depth` 1 to 16), refuse a code path outside the repository, and build and delete a sandbox for each call.
`audit` takes the lockfile path as an argument and reads it only under `--root` (default: the current
directory), after following symlinks. It reads advisories from `--osv-cache`; without a cache it asks
api.osv.dev only when the server was started with `--allow-network`, and otherwise returns an error.

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
