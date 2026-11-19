# vinc-relate

Check out task-relevant knowledge from a Vinc graph, reason over it in an ephemeral [Relate](https://github.com/relatedb/relate) graph, and keep only verified findings.

Vinc stays the persistent store. Relate holds one task's subgraph in a private single-file database under tmpfs, is read only while the agent reasons, and is deleted when the task ends.

## Run

```
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/vinc-relate paths fixtures/vinc_subgraph.json record:tls-advisory-example concept:service-api
```

The fixtures are synthetic, so the tests and the demo run without a Vinc account or the network.
`paths` looks for paths of 1 to 6 hops (`--hops`, default 4) and returns at most 100 (`--limit`,
default 10). Every command that loads a snapshot compares the nodes and edges that landed with the
snapshot's own counts and stops with an error that names a repeated id or an edge with a missing endpoint.

With a Vinc account, set a read-only key and a space, then check out real seeds:

```
VINC_API_KEY=<read-only key> VINC_SPACE=<space id> .venv/bin/vinc-relate checkout <node id> ... --out snapshot.json
.venv/bin/vinc-relate paths snapshot.json <from id> <to id>
```

## The demo

```
.venv/bin/vinc-relate demo
.venv/bin/vinc-relate demo --approve <digest>
```

One command runs the whole procedure on synthetic data, offline and without a Vinc key: a synthetic
space served by an in-process fake Vinc, a checkout of only the app's knowledge, a Relate graph that
joins it with the demo lockfile and cached OSV advisories, a multi-hop path from a decision to an
advisory, a Checker that re-derives each proposed record from the sandbox, and the write set with its
approval digest. Without `--approve <digest>` (or `--yes`) it stops there and writes nothing. With it,
the records go to the fake Vinc with `create_only`, are read back, and a new checkout finds their
edges. The records are dated by the OSV cache, so the digest is the same on every run.

The run leaves `demo/transcript.json` (every step with its counts; run-time stamps only under
`timestamps`), `demo/expected_findings.json` and `demo/sample.rl`, a copy of the sandbox graph built
from the fixtures for inspection. The sandbox itself is deleted. `skills/vinc-relate/SKILL.md` tells
a coding agent how to run the same procedure.

## Impact of a code change

```
.venv/bin/vinc-relate impact fixtures/impact/vinc.json reports/export.py storage/ --format text
```

`impact` answers "this code path changes; what governs it". It loads the snapshot into a throwaway
Relate file, opens it read only and deletes it after the run. For each path it lists the nodes whose
`code_ref` names the path, then the decisions and records within `--hops` (default 3) of them, each
with its edge path in the snapshot's edge direction and the evidence on every edge. Results are
ordered by hop count, then decision, record, concept. A `code_ref` matches when it names the same
path, lies under a queried directory (`storage/` matches `storage/page_store.py`, `reports` does not
match `reports_archive/`), or is a directory holding the queried path. A repository prefix
(`Demo:reports/export.py`) and a symbol suffix (`storage/page_store.py:check_page_size`) are
dropped before matching; `--repo Demo` skips refs that name another repository. Output is JSON by
default; `--format text` prints the short form.

## Dependency policy audit

```
.venv/bin/vinc-relate audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --osv-cache fixtures/audit/osv-cache.json
```

The audit loads three things into one throwaway graph: the Vinc snapshot (decisions about the
repository, found through a concept whose `code_ref` names it), the npm lockfile (direct and
transitive `DEPENDS_ON`, nested copies resolved) and OSV advisories (`AFFECTED_BY`, with source URL,
fetch time and content hash). A path query finds each advisory the repository reaches, then the
verifier checks the installed version against the advisory ranges and applies each governing
decision: a decision with a machine-checkable `rule` is `violated` or `not_violated`, one without a
rule is only `relevant`. Development-only paths do not violate a rule scoped to shipped dependencies.
Each finding keeps the advisory's `source_url`, `fetched_at` and `content_hash`.

`--osv-cache <file>` reads the advisories from a file instead of api.osv.dev and refuses the network:
a package or advisory the file does not hold stops the run with an error. The file holds `fetched_at`
(when the advisories were read), `queries` (package id to the advisory ids OSV returned for it) and
`vulns` (advisory id to the OSV record). `fixtures/audit/osv-cache.json` covers the demo lockfile, so the
demo runs offline and gives the same findings every time. Without `--osv-cache`, `audit` asks OSV live.

## Record after approval

```
.venv/bin/vinc-relate audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --osv-cache fixtures/audit/osv-cache.json --out report.json
.venv/bin/vinc-relate propose report.json --repo Demo --space <space id> --out plan.json
VINC_API_KEY=<full key> .venv/bin/vinc-relate commit plan.json --approve <digest>
```

`propose` turns only `affected` findings into records (anything else is held back and listed) and
prints the exact write set with an approval digest over the space, nodes and edges. Each record
carries the advisory's `source`, `advisory_fetched_at` and `advisory_content_hash`. `commit` refuses
unless the digest matches the plan file as it stands now, so an edited plan needs a new approval. It
writes with `create_only` and an operation id derived from the digest, leaves ids that already exist
alone, then reads every new node and its edges back and exits non-zero if anything differs. An edge
must come back with the same type and direction. A record's `relates_to` edge comes back from Vinc as
`ATTACHES_TO` with the role `relates_to`; checkout reads it as `RELATED_TO`, the name Vinc returns for
`relates_to` between concepts, so a later checkout keeps the committed edges.

Run the demo against a synthetic space; write to a real space only after its owner approves the
printed write set.

## Does the graph help?

```
.venv/bin/vinc-relate compare --out bench/results.json --table bench/results.md
```

`compare` runs nine tasks from `bench/tasks.json` three ways, offline and without a model: A answers from the
Vinc snapshot alone (nodes whose `code_ref` matches the subject, then one hop); B adds the lockfile and the
advisories as flat records joined by package name, with the same version range check and policy rule as C;
C loads all three into a Relate graph and queries it. The tasks and their expected findings were committed
before the first run. A path or a policy link counts when it equals an expected one; any other claim is
unsupported; a claim is covered when its evidence is a connected chain of edges that exist in the inputs.

| Method | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |
|---|---|---|---|---|---|---|
| A | 5/13 | 5/17 | 0/5 | 0/10 | 10/10 | 0.4 |
| B | 9/13 | 15/17 | 5/5 | 1/30 | 27/30 | 0.6 |
| C | 13/13 | 17/17 | 5/5 | 2/37 | 37/37 | 80.2 |

The graph helped on two tasks: a vulnerable package reached only through a shared transitive dependency
(B finds no chain and claims a wrong one through test-kit, which has its own nested copy), and a decision two
hops from the code it governs. It made no difference on a direct dependency, a development-only dependency,
a version outside the advisory's range (the lockfile record and the advisory text carry those), a one-hop
decision or a directory prefix decoy. The nested copy task was expected to need the graph and did not: the
copy sits under a direct dependency, so the name join finds its chain; the same join's error shows up on the
hoisted copy instead. On impact tasks B has no external data to add, so it equals A. It was worse on one task: a bounded walk reached a log retention
decision through a shared logger and claimed it governs the archive index. Per-task numbers are in
`bench/results.md`; every claim with its coverage is in `bench/results.json`. C's latency includes building and
loading a graph for each task. Latency is the only number that changes between runs. The benchmark is small and synthetic, so it shows which kinds of connection need the
graph, not how often they occur.

## What is proven so far

- A Vinc subgraph is exported over the Vinc MCP with stable ids, edge direction and evidence.
- The same structure loads into a Relate file; a bounded multi-hop query returns the expected path.
- Reasoning opens the file read only; a write is refused, and an open writer locks out a second writer and any reader.
- The task directory is private (0700) and removed after the run.
- An approved write set reaches the vinc space: seven advisory records from the Vinc app lockfile were written with `create_only`, read back field for field, and a second run with the same approval wrote nothing.
