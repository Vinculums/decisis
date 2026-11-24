# What is tested, and what is not built yet

Proven by the tests in `tests/` (run offline in CI on Python 3.11 and 3.12) and by the runs in [benchmark.md](benchmark.md):

- A Vinc subgraph is exported over the Vinc MCP with stable ids, edge direction and evidence, and a
  snapshot whose counts disagree with its lists is refused.
- The snapshot loads into a Relate file; the loader compares what landed with the snapshot and names a
  repeated id or an edge with a missing endpoint. A bounded multi-hop query returns the expected path.
- Reasoning opens the file read only and a write is refused; an open writer locks out a second writer
  and any reader.
- The task directory is private (0700), under `/dev/shm` when it is writable, and removed after the run.
- A graph over the node or edge cap is refused before anything is written, a query over the time limit
  is stopped, and in both cases the task directory is removed and the command exits non-zero.
- Each task directory, and the parent directory of `decisis serve`, records its owner process. On Linux
  and macOS a new sandbox, a new server or `decisis gc` removes `decisis-*` and `decisis-serve-*`
  directories under the same root whose owner is gone, so a server killed with SIGKILL is cleaned up
  too; it leaves another user's directory, a live run's directory, a `decisis-*` entry that is a
  symbolic link, and anything a symbolic link inside a task directory points to. A root that is itself a symbolic link is followed and used as
  the root.
- The audit joins the snapshot, the lockfile or SBOM (nested npm copies resolved) and OSV, checks the
  installed version against the advisory ranges (semantic versions, and PEP 440 for PyPI), and keeps each
  advisory's source URL, fetch time and content hash.
- `propose` re-derives each record in a fresh graph built from the snapshot, the lockfile and OSV: the
  advisory's content hash and severity, each version as a lockfile package inside the advisory's ranges,
  each dependency path from the repository to the record's own package and advisory, the record's scope
  against the development flags on its paths, and each `relates_to` target as a decision in the snapshot. A record that fails is held back with the failed
  checks, and `propose` exits non-zero. The demo runs the same checks.
- `check` judges `review_required` against the reviewers given and `imports_forbidden` on Python,
  JavaScript, TypeScript and JSX imports, absolute, relative, from a nested package root and through the
  nearest `tsconfig.json` and its `extends`; on Go imports, single and grouped, with alias, dot and blank
  names, through the module path of the nearest `go.mod` in either form of its `module` directive; and on
  Rust `use`, `mod` and `extern crate` declarations, through the tree of `mod` declarations from the crate
  root (with `#[path]`, `cfg_attr` paths and inline modules), the items and `use` bindings of each module,
  and into other crates of the repository by their `Cargo.toml` names, `package` renames and workspace
  dependencies. It does so without running the repository's code or its git hooks. An import computed at
  run time, a file the scanner cannot finish, a Go path under the module path with no directory, a Rust
  path with a name that is no module, item or `use` binding of the module it reaches, and a specifier a
  plain text search finds where the scanner did not are `unresolved`, never clean; a superseded decision
  is not judged.
- The action's comment, against a fake GitHub: a hostile decision title and file path reach it only as
  escaped text, the body stays under GitHub's limit and says what it cut, the bot's own marked comment is
  found across pages and updated (a marked comment by anyone else is left alone), only the latest approving
  review of each user other than the author counts, a pull request inside a repository that is itself
  a fork still gets a comment, and a fork or a refused write leaves the result in the job summary.
- `init` reads MADR and Nygard ADRs (front matter, a bold `Status` line, `Superseded by` links), CODEOWNERS
  with GitHub's matching rules, and postmortems, and lists each file it skipped with the reason. Against a
  fake GitHub, `init --github` sends only GET requests to api.github.com, refuses a next page or a redirect
  to another host, and never prints or stores the token.
- Each format under the inventory table in [data-model.md](data-model.md#inventories) is read from a fixture in `fixtures/inventory/`
  into the same nodes and edges, and audited offline against a committed OSV cache; a binary `bun.lockb`, a
  `pom.xml` with a DOCTYPE and a YAML lockfile with an anchor are refused before they are parsed.
- The MCP server lists four tools and no write. `query` is refused a write three separate ways, each tested
  on its own: by the text check, by Relate's `EXPLAIN` plan, and by the read-only connection. Every reply
  stays under 1 MiB, and a server stopped during a call, or killed, leaves no sandbox behind.
- The Mermaid and HTML views of `impact`, `check`, `paths` and `audit` match committed copies in
  `tests/golden/`; hostile titles are escaped in both, and the HTML is one offline file whose only links are
  the findings' sources.
- `decisis compare` gives the committed results of both benchmarks (`bench/results.json`, and
  `bench/holdout/results.json` in the slow test).
- `commit` refuses a digest that does not match the plan as it stands, writes with `create_only`, and
  fails when a node, a property or an edge's type or direction does not come back.
- A live run against a real Vinc space wrote and read back seven records with `create_only`, and a second
  run with the same approval wrote nothing. That space is not public; `decisis demo --approve` is the
  reproducible version.

Future work, not built:

- Removing stale task directories on Windows; there `decisis gc` says so and removes nothing.
- Encrypted scratch storage with key destruction for sensitive data (see `docs/threat-model.md`).
- Transitive dependencies for a Gradle lockfile or a `pom.xml`; generate CycloneDX JSON for those.
- Advisories for Terraform providers: OSV has no Terraform ecosystem, so providers are checked against
  `package_denied` and `package_allowed` only.
- Imports in languages other than Python, JavaScript, TypeScript, Go and Rust: `check` reads none, so a
  Java or Kotlin file under an `imports_forbidden` glob gives no verdict. Rust macros that expand to
  `use` or `mod`, items a macro generates (these are `unresolved`), and Go `go.work` workspaces and
  `replace` directives, are not followed.
- Go packages under `vendor/`, and modules that a `replace` directive or `go.work` places inside the
  repository, are read as external, so no `to` glob can name them.
- A memory limit on the query process (see `docs/threat-model.md`).
- A listing on the GitHub Marketplace; refer to the action by repository and commit.
- A benchmark that exercises the `RELATED_TO` carry rule and the audit policy rules on real repositories;
  method B and the coverage check of `compare` read npm lockfiles only.
