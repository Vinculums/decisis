# vinc-relate

Check out task-relevant knowledge from a Vinc graph, reason over it in an ephemeral [Relate](https://github.com/relatedb/relate) graph, and keep only verified findings.

Vinc stays the persistent store. Relate holds one task's subgraph in a private single-file database under tmpfs, is read only while the agent reasons, and is deleted when the task ends.

## Run

```
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/vinc-relate paths fixtures/vinc_subgraph.json record:tls-advisory-example concept:service-api
```

The fixture is synthetic, so the tests and the demo run without a Vinc account.

With a Vinc account, set a read-only key and a space, then check out real seeds:

```
VINC_API_KEY=<read-only key> VINC_SPACE=<space id> .venv/bin/vinc-relate checkout <node id> ... --out snapshot.json
.venv/bin/vinc-relate paths snapshot.json <from id> <to id>
```

## Impact of a code change

```
.venv/bin/vinc-relate impact fixtures/impact/vinc.json api/graph_algo.py store/ --format text
```

`impact` answers "this code path changes; what governs it". It loads the snapshot into a throwaway
Relate file, opens it read only and deletes it after the run. For each path it lists the nodes whose
`code_ref` names the path, then the decisions and records within `--hops` (default 3) of them, each
with its edge path in the snapshot's edge direction and the evidence on every edge. Results are
ordered by hop count, then decision, record, concept. A `code_ref` matches when it names the same
path, lies under a queried directory (`store/` matches `store/embedded_backend.py`, `api` does not
match `api_gateway/`), or is a directory holding the queried path. A repository prefix
(`Demo:api/server.py`) and a symbol suffix (`store/embedded_backend.py:_vector_query_guard`) are
dropped before matching; `--repo Demo` skips refs that name another repository. Output is JSON by
default; `--format text` prints the short form.

## Dependency policy audit

```
.venv/bin/vinc-relate audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo
```

The audit loads three things into one throwaway graph: the Vinc snapshot (decisions about the
repository, found through a concept whose `code_ref` names it), the npm lockfile (direct and
transitive `DEPENDS_ON`, nested copies resolved) and OSV advisories (`AFFECTED_BY`, with source URL,
fetch time and content hash). A path query finds each advisory the repository reaches, then the
verifier checks the installed version against the advisory ranges and applies each governing
decision: a decision with a machine-checkable `rule` is `violated` or `not_violated`, one without a
rule is only `relevant`. Development-only paths do not violate a rule scoped to shipped dependencies.

## Record after approval

```
.venv/bin/vinc-relate audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --out report.json
.venv/bin/vinc-relate propose report.json --repo Demo --space <space id> --out plan.json
VINC_API_KEY=<full key> .venv/bin/vinc-relate commit plan.json --approve <digest>
```

`propose` turns only `affected` findings into records (anything else is held back and listed) and
prints the exact write set with an approval digest over the space, nodes and edges. `commit` refuses
unless the digest matches the plan file as it stands now, so an edited plan needs a new approval. It
writes with `create_only` and an operation id derived from the digest, leaves ids that already exist
alone, then reads every new node and its edges back and exits non-zero if anything differs.

Run the demo against a synthetic space; write to a real space only after its owner approves the
printed write set.

## What is proven so far

- A Vinc subgraph is exported over the Vinc MCP with stable ids, edge direction and evidence.
- The same structure loads into a Relate file; a bounded multi-hop query returns the expected path.
- Reasoning opens the file read only; a write is refused, and an open writer locks out a second writer and any reader.
- The task directory is private (0700) and removed after the run.
- An approved write set reaches the vinc space: seven advisory records from the Vinc app lockfile were written with `create_only`, read back field for field, and a second run with the same approval wrote nothing.
