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

## What is proven so far

- A Vinc subgraph is exported over the Vinc MCP with stable ids, edge direction and evidence.
- The same structure loads into a Relate file; a bounded multi-hop query returns the expected path.
- Reasoning opens the file read only; a write is refused, and an open writer locks out a second writer and any reader.
- The task directory is private (0700) and removed after the run.
