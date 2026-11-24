# Architecture

decisis keeps two kinds of memory apart. Vinc is the persistent layer: decisions, concepts, records
and the evidence on their edges, kept across tasks. A Relate file is the ephemeral layer: one task's
slice of Vinc joined with outside data, built for that task, read only while the agent reasons, and
deleted when the task ends. The only way back from the second to the first is a write set a person
approves by its digest.

```mermaid
sequenceDiagram
    participant A as Agent or person
    participant V as Vinc (MCP)
    participant X as Lockfile and OSV
    participant R as Relate file (tmpfs)
    A->>V: checkout seeds, depth (read-only key)
    V-->>A: snapshot.json
    A->>X: parse lockfile, fetch or read cached advisories
    A->>R: one writer loads snapshot + packages + advisories, then closes
    A->>R: read-only connections run bounded Cypher
    R-->>A: paths, findings with sources
    A->>R: delete the directory
    A->>R: propose: re-derive each record in a fresh graph, then delete it
    A->>A: propose: write set + digest
    A->>V: commit --approve digest (full key): create_only, read back
```

## Modules

| File | What it does |
|---|---|
| `src/decisis/cli.py` | The `decisis` command: `init`, `checkout`, `paths`, `impact`, `audit`, `propose`, `commit`, `demo`, `compare`. |
| `src/decisis/checkout.py` | `VincMCP`, a small JSON-RPC client for the Vinc MCP endpoint; `checkout` calls `vinc_graph` once per seed and `normalize` merges the results into a `Subgraph` (deduplicated by id, known edge types only, edges with a missing endpoint dropped). `dump` and `load` read and write the snapshot file. |
| `src/decisis/sandbox.py` | `Sandbox`: creates the private task directory, loads a `Subgraph` once with a single writer connection, answers queries over read-only connections in a query process with a time limit, and deletes the directory. `sandbox()` is the context manager every command uses. `Limits` holds the size caps and the time limit; `sweep()` removes task directories a killed run left. |
| `src/decisis/inventory/` | One reader per inventory format (npm lockfile, CycloneDX, SPDX, `uv.lock`, `Cargo.lock`, `go.mod` with `go.sum`). Each turns the file into `Repository` and `Package` nodes and `DEPENDS_ON` edges of the same shape; `inventory.read` tells the format from the content and file name. |
| `src/decisis/external.py` | Fetches OSV advisories with one batch query, each package under its own ecosystem, and one record per advisory, or reads them from an `--osv-cache` file and refuses the network. `parse_npm_lock` stays importable here. |
| `src/decisis/pep440.py` | Orders PyPI versions by PEP 440 for OSV `ECOSYSTEM` ranges. |
| `src/decisis/semver.py` | Checks an installed version against OSV `SEMVER` and `ECOSYSTEM` ranges, ordered the way the package's ecosystem orders versions; a version it cannot order gives `unresolved`. |
| `src/decisis/audit.py` | Composes the snapshot, the lockfile and the advisories into one graph, adds `DESCRIBED_BY` from the repository to each Vinc node whose `code_ref` names it, runs the dependency and governance queries, and judges each finding against each governing decision. |
| `src/decisis/impact.py` | Answers "this code path changes; what governs it": matches `code_ref`, `subject_path` and `also_touches` against the queried paths, keeps only the edges that carry governance (`CARRIES`), orients them from the governing node to the governed one, and walks back from the matching nodes. |
| `src/decisis/init.py` | `init`: one reader per source (ADRs, CODEOWNERS, postmortems), each returning nodes and edges in snapshot shape, and `build`, which merges and sorts them and lists what it could not read. |
| `src/decisis/codeowners.py` | GitHub's CODEOWNERS matching: which line owns each file, and the fewest paths that cover each owner set. |
| `src/decisis/commit.py` | `propose` turns `affected` findings into record nodes and `relates_to` edges, with a digest over the space, nodes and edges. `commit` checks the digest, writes with `create_only` and an operation id derived from the digest, and reads every node and edge back. |
| `src/decisis/checker.py` | The Checker that `propose` and the demo share: `check_plan` re-derives each record from a loaded sandbox (advisory hash and severity, version, dependency path and scope, decision target); it finds each record's package by name and version in the sandbox and checks the version under that package's ecosystem, `withhold` moves a failed record and its edges to `held` and recomputes the digest, and `rederive` builds the fresh sandbox `propose` checks in. |
| `src/decisis/fake_vinc.py` | An in-process stand-in for Vinc's `vinc_node`, `vinc_graph` and `vinc_ingest`, used by the demo and the tests. It stores a record's edge the way Vinc returns it (`ATTACHES_TO` with a role). |
| `src/decisis/demo.py` | The judge demo: the whole procedure against the fake Vinc and the fixtures, with a Checker step (`checker.check_plan`) and a transcript. |
| `src/decisis/compare.py` | The A/B/C benchmark over `bench/tasks.json`. |
| `src/decisis/queries/*.cypher` | The Cypher the commands run. Hop and result bounds are substituted as integers; every other value is a query parameter. |

## The sandbox lifecycle

1. `Sandbox()` first removes stale task directories under the same root (see below). It then makes
   `decisis-<random hex>/` with mode 0700 under `/dev/shm` when that directory exists and is writable,
   otherwise under the system temporary directory, and writes `owner.json` (process id, process start
   time where the platform gives one, host name) into it. The database is `task.rl` inside it.
2. `load()` first compares the snapshot with the node and edge caps and raises `TooLarge` before it
   opens the database. It then opens one writer connection, creates the nodes grouped by kind (the kind becomes the label)
   and the edges grouped by type, counts what landed and closes. A second `load()` on the same sandbox is
   refused. If the counts differ from the snapshot, the error names repeated ids and edges with a missing
   endpoint.
3. `query()` sends the query to a query process, which opens a new connection with `read_only=True`
   for it and closes it after. A write through that connection fails with `WriteOnReadOnly`. Relate
   1.0.2 has no query timeout or interrupt in its Python API, and a signal handler does not run while a
   query is executing, so the time limit is kept by a separate process: when a query runs past the limit,
   the process is killed and `QueryTimeout` is raised. One query process serves every sandbox in a
   command and starts while the graph loads, so the cost is one Python start (about 0.1 s on Linux) per
   command, not per query. The query process exits when the command's process ends.
4. `destroy()` removes the directory. The context manager calls it in a `finally`, so an exception in
   the task, a refused load or a stopped query still removes it.

A directory is stale when its name is exactly `decisis-` or `decisis-serve-` and 32 hex digits (the
second is the parent directory `decisis serve` makes with `owned_dir`, which records its owner the same
way), it is a real directory (not a symbolic link) owned by the current user, it is older than the grace period (10 minutes), its
`owner.json` is a regular file of the same user on the same host, and that process is gone: no process
has the id, or on Linux the process with that id started at another time (the id was reused). A live
process, an unreadable record or a missing record keeps the directory. Removal uses
`shutil.rmtree`, which does not follow symbolic links. Removal needs `os.getuid` and a symlink-safe
`rmtree`, so it runs on Linux and macOS and is skipped on Windows. `decisis gc [--root DIR] [--grace
SECONDS]` runs the same removal on demand.

Relate's single file is locked by an open writer: a second writer and any reader get `storage locked`
until it closes (`tests/test_sandbox.py`). That is why loading and reasoning are separate steps.

## The queries

| Query | Used by | Finds |
|---|---|---|
| `paths_between` | `paths` | Paths of 1 to `--hops` edges in either direction between two ids, shortest first, at most `--limit`. |
| `dependency_paths` | `audit`, `demo` | Every `repo -DEPENDS_ON*-> package -AFFECTED_BY-> advisory` chain up to `--depth` (default 8). |
| `governing_decisions` | `audit` | Decisions `ABOUT` a Vinc node the repository is `DESCRIBED_BY`. |
| `decision_to_advisory` | `demo` | The shortest path from one decision through the repository and its dependencies to one advisory. |
| `governing_nodes` | `impact` | Decisions and records within `--hops` of a node whose code paths match, over governance edges only. |

## Findings and verdicts

`audit` takes each dependency chain the query returns and checks the installed version against the
advisory's ranges: `affected`, `not_affected`, or `unresolved` when the version cannot be compared. For
each governing decision it gives a verdict: a decision with a machine-checkable `rule`
(`advisory_severity_at_least`, optionally `dependencies: shipped`) is `violated` or `not_violated`, one
without a rule is `relevant`. A dependency reached only through development dependencies does not
violate a rule about shipped ones. The verdict is computed in Python from the graph's answers, not by the
query.

## The write path

`propose` writes nothing; it produces a plan file and prints it. Only `affected` findings become records;
the rest are listed under `held`. Each record carries the advisory's source URL, fetch time and content
hash, the dependency paths, and the decisions it violates.

`commit` needs the digest. It recomputes the digest from the plan file and refuses when either differs,
so an edited plan needs a new approval. It skips ids that already exist, writes the rest with
`create_only` and an operation id derived from the digest, then reads each new node back and compares
every property, and checks out each record again to confirm each edge with its type and direction. Any
difference makes the exit code non-zero and is listed under `problems`.

Before it prints the digest, `propose` runs a Checker. It builds a fresh sandbox from the snapshot, the
lockfile and OSV (or `--osv-cache`), and for each record compares the advisory hash and severity with the
OSV record in that graph; checks that each version is a package of that name in the lockfile, inside the
advisory's ranges and reached by one of the record's paths; checks that each dependency path runs from the
repository to the record's own package and advisory, exists in the graph, and has development flags that
match the record's scope; and confirms each `relates_to` target is a decision in the snapshot. A record that fails any check is left out with its
edges and listed under `held` with the failed checks, the digest covers only what is left, and `propose`
exits non-zero. The demo runs the same `checker.check_plan` in its own sandbox.

## The comparison

`compare` gives B and C the same lockfile parsing, version check and policy rule, so only the join
differs: A is the snapshot with a one-hop neighbourhood and no outside data, B joins flat records by
package name, C is the Relate graph. Each task in `bench/tasks.json` lists its expected paths, policy links and findings,
which were committed before the first run. The README gives the numbers and their caveats.
