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

With the `mcp` extra, the same `impact`, `paths` and `audit` are MCP tools over stdio, on one snapshot
fixed when the server starts. For Claude Code:

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

## The procedure on real data

1. Check out only what the task needs, with a read-only key:
   `VINC_API_KEY=<read-only key> VINC_SPACE=<space id> decisis checkout <seed id> ... --out snapshot.json`
   Pick seeds that the task names (the repository's concept, the decision in question); keep `--depth` at 1 or 2.
2. Reason in the sandbox:
   `decisis audit snapshot.json package-lock.json --repo <name as in code_ref> --out report.json`
   (add `--osv-cache <file>` to stay offline), `decisis impact snapshot.json <path> --format text`, or
   `decisis check snapshot.json --base origin/main --reviewers <handle>... --format text`.
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
- A finding with `kind` `license` or `package` comes from a decision whose rule forbids licenses or
  packages (`license_denied`, `license_allowed`, `package_denied`); its `path` ends at the package and
  each policy names its `rule`. An unknown license is `unresolved`, never `violated`.
- `rule_problems`: decisions whose rule cannot be read, with the reason. Report them; they are never
  `violated`.

When you report back, quote the path and the decision for each violation, and name the digest the
person needs to approve.
