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

## What is proven so far

- A Vinc subgraph is exported over the Vinc MCP with stable ids, edge direction and evidence.
- The same structure loads into a Relate file; a bounded multi-hop query returns the expected path.
- Reasoning opens the file read only; a write is refused, and an open writer locks out a second writer and any reader.
- The task directory is private (0700) and removed after the run.
