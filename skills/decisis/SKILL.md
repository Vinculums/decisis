---
name: decisis
description: Reason over a task's slice of a Vinc knowledge graph joined with external data (a lockfile or SBOM and OSV advisories) in a throwaway Relate graph, then propose findings that a person approves before anything is written back. Use for a dependency or advisory audit, or to find which decisions govern a code path.
---

# Reason in a sandbox with decisis

Vinc keeps the team's knowledge. Relate holds one task's subgraph in a private file under tmpfs,
opened read only while you reason and deleted when the task ends. Only findings a person approves go
back to Vinc.

## When to use it

- "Which advisories does this repository reach, and which of our decisions do they break?" (`audit`)
- "This code path changes; which decisions and records govern it?" (`impact`)
- "Does this change set lack a required reviewer or make an import a decision forbids?" (`check`, exits 1 on a violation)
- "How are these two nodes connected?" (`paths`)
- A question about the snapshot the three above do not answer, such as "which decisions have no `ABOUT`
  edge?" or "how many records does each concept have?" (`query`, read-only Cypher)

Do not use it to edit the graph by hand. It writes only through `commit`, and only with the digest
a person approved.

## Try it first: the demo

Runs offline with no Vinc account: a synthetic space in an in-process fake Vinc, the demo lockfile,
and OSV advisories from `fixtures/audit/osv-cache.json`.

```
decisis demo                      # stops at approval and prints the digest; nothing is written
decisis demo --approve <digest>   # the person's approval; writes to the fake Vinc and reads back
```

`--yes` approves the demo write set without typing the digest; use it only when the person asked for
an unattended demo. The run writes `demo/transcript.json`, `demo/expected_findings.json` and
`demo/sample.rl` (a copy of the sandbox graph for inspection); the sandbox itself is deleted.

## As an MCP server

With the `mcp` extra, the same `impact`, `paths`, `audit`, `check` and `query` are MCP tools over stdio, on the
snapshot file named when the server starts. For Claude Code:

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

The tools are read only: there is no `propose` or `commit` tool, so the write path below stays a
command the person sees. `audit` takes a lockfile path under the server's `--root`; it uses the network
only when the server was started with `--allow-network` and has no `--osv-cache`. A refused input comes
back as an error result that names the argument; fix the argument rather than retrying the same call.

Before you commit a change, call `check` to judge it against the snapshot's review and import rules:
`{"base": "origin/main", "reviewers": ["@alice"]}`, or `{"changed": ["src/shop/ui/view.py"]}` with paths
relative to the server's `--root`. It returns the same report as `decisis check` on that root. A `base` that
starts with `-` or holds whitespace or a control character, and a changed path outside the root, are
refused. Fix each violation, or say why it stands, before you commit; an `unresolved` entry is not a pass.

The server reloads the snapshot file before a call when its mtime or size changed, rebuilds the schema in
the `query` description and sends `notifications/tools/list_changed`; list the tools again when it does.
If the new file fails to load, the reply comes from the previous snapshot and carries `reload_failed` with
the reason: tell the person, and do not treat that answer as coming from the new snapshot.

Each tool returns a summary by default: counts, ids, titles and the first 10 items of each list, with a
note. Call it again with `"detail": "full"` only when you need every item or field, such as a finding's
policies or an edge path's evidence.

### `query` or a fixed tool

Use `impact`, `paths` and `audit` for their questions: they follow only the edges that carry governance,
judge each decision's rule, and return the evidence on each edge. A Cypher query that looks similar can
miss a direction or an edge type they handle. Use `query` when no fixed tool answers the question.

- Read the schema in the `query` tool's description first: labels are node kinds with the first letter
  in upper case (`:Decision`, `:Concept`), edge types are as in the snapshot (`:ABOUT`), and every node has
  `id`, `title` and `domain`.
- Write one read statement that starts with `MATCH`, `OPTIONAL MATCH`, `WITH`, `UNWIND`, `RETURN` or `CALL`.
  Pass values in `params` and refer to them as `$name`. Return ids and properties, not whole nodes.
- Writes (`CREATE`, `MERGE`, `SET`, `DELETE`, `REMOVE`), `LOAD CSV`, admin clauses, procedures other than
  `db.labels`, `db.relationshipTypes`, `db.propertyKeys` and `db.schema.*`, and `CALL { }` subqueries are
  refused before the query runs. Use `COLLECT { }`, `COUNT { }`, `EXISTS { }` or `UNION` instead of a
  subquery, and put a label or key named like a clause in backticks.
- Results stop at 500 rows and 1 MiB with a `cut` note; add `LIMIT` and `SKIP` rather than asking again
  for everything. A query past the time limit is stopped; narrow the pattern or lower the hops.

On the command line the same query is
`decisis query snapshot.json "MATCH (d:Decision) RETURN d.id AS id" --param KEY=VALUE`.

## The procedure on real data

1. Get a snapshot. With Vinc, check out only what the task needs, with a read-only key:
   `VINC_API_KEY=<read-only key> VINC_SPACE=<space id> decisis checkout <seed id> ... --out snapshot.json`
   Pick seeds that the task names (the repository's concept, the decision in question); keep `--depth` at 1 or 2.
   Without Vinc, build one from the repository's ADRs, CODEOWNERS and postmortems:
   `decisis init --repo-dir . --repo <name> --out snapshot.json` (add `--github OWNER/REPO` for merged pull
   requests labelled `decision`). Read what `init` prints it could not read, and say so in your report.
2. Reason in the sandbox:
   `decisis audit snapshot.json package-lock.json --repo <name as in code_ref> --out report.json`
   (add `--osv-cache <file>` to stay offline), `decisis impact snapshot.json <path> --format text`, or
   `decisis check snapshot.json --base origin/main --reviewers <handle>... --format text`.
   `audit` reads npm, pnpm, Yarn and Bun lockfiles, CycloneDX and SPDX JSON, `uv.lock`, `poetry.lock`,
   `requirements*.txt`, `Cargo.lock`, `go.mod` with `go.sum`, Gradle lockfiles, `pom.xml`, GitHub Actions
   workflows and `.terraform.lock.hcl`, and tells the format from the file. Files next to it are read only
   under the repository root (`--root DIR` sets it). `--format mermaid` or `--format html` gives a view for a
   person; keep the JSON for yourself.
   A graph over 50,000 nodes or 250,000 edges, or a query over 60 seconds, stops the command with exit 1;
   raise `--max-nodes`, `--max-edges` or `--query-timeout` only when the person agrees. If a killed run left
   a `decisis-*` directory behind, `decisis gc` removes it.
3. Propose: `decisis propose report.json snapshot.json package-lock.json --repo <name> --space <space id> --out plan.json`
   (with the same `--osv-cache <file>` as the audit, if any). It re-derives each record from the snapshot, the
   lockfile and OSV, holds back any record that fails, and prints the exact write set and an approval digest.
   A non-zero exit means a record was held; report its failed checks and do not edit the report to get past them.
4. Show the person the printed write set and the digest, and stop. Do not approve on their behalf.
5. Only after the person gives the digest:
   `VINC_API_KEY=<full key> decisis commit plan.json --approve <digest>`.
   A non-zero exit means the read-back differed; report the `problems` list and do not retry blindly.

## Reading the findings

- `status`: `affected` (the installed version is inside the advisory's ranges), `not_affected`, or
  `unresolved` (the version could not be compared). Only `affected` findings become records.
- `path`: the dependency route from `repo:<name>` through packages to the advisory.
- `policies`: per governing decision, `violated` or `not_violated` when the decision has a
  machine-checkable `rule`, otherwise `relevant`. A development-only path does not violate a rule
  about shipped dependencies.
- `source_url`, `fetched_at`, `content_hash`: the advisory evidence each record keeps.
- A finding with `kind` `license`, `package`, `allowlist` or `pin` comes from a decision whose rule
  forbids licenses (`license_denied`, `license_allowed`), denies packages (`package_denied`), allows only
  listed packages (`package_allowed`) or requires GitHub actions pinned to a commit (`pinned_to_commit`);
  its `path` ends at the package and each policy names its `rule`. An unknown license, or a `docker://` image
  under `pinned_to_commit`, is `unresolved`, never `violated`.
- `inventory_notes`: gaps in what the inventory covers, such as a `requirements.txt` that lists
  direct dependencies only, or a Gradle lockfile or `pom.xml` whose transitive dependencies are not
  resolved. Pass them on; a clean report over such an inventory is not a clean bill.
- `unresolved_packages`: packages that could not be queried at OSV (no purl, a local or Docker action, a
  Terraform provider) with the reason. Name them in your report.
- `rule_problems`: decisions whose rule cannot be read, with the reason. Report them; they are never
  `violated`.
- `unread_decisions`: ADR files `init` could not read, such as one with a `rule:` or `waivers:` line that
  does not parse. They are not in the snapshot, so none of their rules were judged. Name each file and
  its reason; a clean report with unread decision files is not a clean bill. `check` reports them too.

For `check`, read `violations` (the file, the line for an import, the decision and the rule) and
`unresolved` (imports or files that cannot be judged, such as an import computed at run time). An
`unresolved` entry is not a pass; report it. A superseded decision is listed apart and not judged.

When you report back, quote the path and the decision for each violation, and name the digest the
person needs to approve.
