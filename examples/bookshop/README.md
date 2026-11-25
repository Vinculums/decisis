# Bookshop: decisis on a small application

Bookshop is an invented web shop, small enough to read in a few minutes. It has what a real repository has and
decisis reads: ADRs that carry rules, a lockfile, a workflow and a code owners file. This page runs `init`,
`check` and `audit` on it, then lets an agent ask the same questions over MCP. Every output is committed in this
directory, and a test (`tests/test_examples.py`) runs the commands again and fails if they print anything else.

```
examples/bookshop/
  app/                          the application: this is what `init`, `check` and `audit` read
    docs/adr/                   four ADRs; each has a `rule:` in its front matter
    docs/postmortems/           one postmortem that names ADR 0002
    .github/CODEOWNERS
    .github/workflows/ci.yml    the workflow `audit` judges
    package-lock.json           the lockfile `audit` judges
    src/bookshop/               ui, db, api and payments, a few lines each
  osv-cache.json                the advisories `audit` reads, so nothing needs the network
  snapshot.json                 what `init` writes (committed so the MCP server can start on it)
  .mcp.json                     the MCP server configuration for Claude Code
  outputs/                      what each command prints
```

The company, the people and the two packages `bookshop-ui-kit` and `bookshop-spec-runner` are made up. The
advisories in `osv-cache.json` are copied from `fixtures/audit/osv-cache.json` (fetched from api.osv.dev on
2026-11-17) and are about `lodash`, which the made-up packages depend on; the list of GitHub Actions names with
advisories is copied from `fixtures/inventory/ci/osv-cache.json` (fetched from OSV's GitHub Actions export on
2026-11-24). Install decisis, then run the commands below from this directory. Add `> file` to keep an output.
`--today` fixes the date that waivers are judged on, so the outputs stay the same from day to day; leave it off
in real use.

## 1. `init`: build the snapshot from what the repository already records

The four ADRs are the decisions. Each names the code or file it is about and carries one rule:

| ADR | Rule | Judged by |
|---|---|---|
| [0001](app/docs/adr/0001-the-user-interface-does-not-import-the-database-layer.md) | `src/bookshop/ui/**` must not import `src/bookshop/db/**` | `check` |
| [0002](app/docs/adr/0002-payment-changes-need-a-payments-review.md) | a change under `src/bookshop/payments/**` needs a review from `@alice` or `@bookshop/payments` | `check` |
| [0003](app/docs/adr/0003-no-high-advisories-in-shipped-dependencies.md) | no HIGH advisory in a shipped dependency | `audit` |
| [0004](app/docs/adr/0004-pin-github-actions-to-a-commit.md) | every workflow `uses:` is a full commit SHA | `audit` |

```
$ decisis init --repo-dir app --repo Bookshop --out snapshot.json
{
 "out": "snapshot.json",
 "nodes": 7,
 "edges": 1,
 "problems": []
}
```

[`snapshot.json`](snapshot.json) holds seven nodes: the four decisions, the postmortem, and two concepts for the
code owners. The one edge is the postmortem naming ADR 0002. `problems` is empty because nothing was left out.

## 2. `check`: judge a change before it is committed

Say a change touches the catalog screen and the payment code, and the only reviewer so far is `@bob`:

```
$ decisis check snapshot.json --repo-dir app --changed src/bookshop/ui/catalog.py src/bookshop/payments/charge.py --reviewers @bob --format text
2 changed file(s); reviewers: @bob
governing decisions: 2
  decision:bookshop-docs-adr-0001-the-user-interface-does-not-import-the-database-layer  The user interface does not import the database layer  (src/bookshop/ui/catalog.py)
  decision:bookshop-docs-adr-0002-payment-changes-need-a-payments-review  Payment changes need a review from the payments team  (src/bookshop/payments/charge.py)
rules that cover a changed file: 2
violations: 3
  src/bookshop/payments/charge.py  decision:bookshop-docs-adr-0002-payment-changes-need-a-payments-review  review_required: src/bookshop/payments/** needs a review from @alice or @bookshop/payments; none of them is among the reviewers given
  src/bookshop/ui/catalog.py:4  decision:bookshop-docs-adr-0001-the-user-interface-does-not-import-the-database-layer  imports_forbidden: src/bookshop/ui/** must not import src/bookshop/db/**; from bookshop.db import models is src/bookshop/db/models.py
  src/bookshop/ui/catalog.py:5  decision:bookshop-docs-adr-0001-the-user-interface-does-not-import-the-database-layer  imports_forbidden: src/bookshop/ui/** must not import src/bookshop/db/**; from ..db.session import open_session is src/bookshop/db/session.py
cannot be judged: 1
  src/bookshop/ui/catalog.py:9  decision:bookshop-docs-adr-0001-the-user-interface-does-not-import-the-database-layer  imports_forbidden: import_module() with a computed name: the specifier is computed at run time; it cannot be judged
```

The command exits 1 because three rules are violated: the payment change lacks a review from the payments team,
and the catalog screen imports the database layer twice (`from bookshop.db import models` and the relative
`from ..db.session import open_session`). The fourth line is not a pass: `import_module(name)` has a computed
name, so `check` says it cannot judge it. Imports that follow the rule, such as `from bookshop.api import client`,
are not listed. The same report as JSON, SARIF, Mermaid or HTML comes from `--format`.

## 3. `audit`: judge the lockfile and the workflow

```
$ decisis audit snapshot.json app/package-lock.json --repo Bookshop --osv-cache osv-cache.json --today 2026-11-25
```

prints [`outputs/audit-lockfile.json`](outputs/audit-lockfile.json). `bookshop-ui-kit` depends on `lodash` 4.17.15,
which has three HIGH advisories, so ADR 0003 has three violations. The dev-only copy of `lodash` that
`bookshop-spec-runner` brings is not judged against that rule, which says `"dependencies": "shipped"`. The Mermaid
view draws the paths from the decision to the advisories:

```
$ decisis audit snapshot.json app/package-lock.json --repo Bookshop --osv-cache osv-cache.json --today 2026-11-25 --format mermaid
```

prints [`outputs/audit-lockfile.md`](outputs/audit-lockfile.md), which GitHub draws. The workflow is an inventory
too:

```
$ decisis audit snapshot.json app/.github/workflows/ci.yml --repo Bookshop --osv-cache osv-cache.json --today 2026-11-25
$ decisis audit snapshot.json app/.github/workflows/ci.yml --repo Bookshop --osv-cache osv-cache.json --today 2026-11-25 --format mermaid
```

prints [`outputs/audit-workflow.md`](outputs/audit-workflow.md), and without `--format`, the JSON report in
[`outputs/audit-workflow.json`](outputs/audit-workflow.json): `actions/setup-node@v4` is pinned to a tag, which
breaks ADR 0004. `actions/checkout` is pinned to a full commit SHA and is not reported.

## 4. The MCP tools on the same files

[`.mcp.json`](.mcp.json) starts the server on the committed snapshot and cache, with `--root app` so that `audit`
reads the lockfile and `check` reads the changed files under `app/`. Open this directory as the project in Claude
Code, or put the same entry in the config file of your tool ([setup for each tool](../../docs/mcp.md#set-up-your-tool)).
The relative paths are read from the directory the server starts in, so start it here.

```json
{
  "mcpServers": {
    "decisis": {
      "command": "decisis",
      "args": ["serve", "--mcp", "--snapshot", "snapshot.json", "--osv-cache", "osv-cache.json", "--root", "app"]
    }
  }
}
```

The agent reasons and the tools answer; none of them writes. These are the four calls it makes for the questions
a person asks, and [`outputs/mcp-session.json`](outputs/mcp-session.json) records what the server returned to each:

- "What governs `src/bookshop/payments/charge.py`?"

  ```
  {"tool": "impact", "arguments": {"code_paths": ["src/bookshop/payments/charge.py"]}}
  ```

- "I changed the catalog screen and the payment code. Is that allowed?"

  ```
  {"tool": "check", "arguments": {"changed": ["src/bookshop/ui/catalog.py", "src/bookshop/payments/charge.py"], "reviewers": ["@bob"], "today": "2026-11-25"}}
  ```

- "Does the lockfile break a decision?"

  ```
  {"tool": "audit", "arguments": {"lockfile": "package-lock.json", "repo": "Bookshop", "today": "2026-11-25"}}
  ```

- "Which postmortems point at a decision?" This is a question the fixed tools do not answer, so the agent uses the
  read-only `query` tool:

  ```
  {"tool": "query", "arguments": {"cypher": "MATCH (r:Record)-[e:ABOUT]->(d:Decision) RETURN r.id AS record, d.id AS decision, e.evidence AS evidence"}}
  ```

The replies are the `summary` the tools give by default: counts, ids and titles. Ask for `"detail": "full"` to get
the report the command prints. [When to use `query` and when the fixed tools](../../docs/mcp.md#when-to-use-query-and-when-the-fixed-tools).

## Change the example

If you change a file under `app/`, `osv-cache.json` or a command above, the outputs move. Rewrite them and read the
diff before committing it:

```
DECISIS_GOLDEN=write python -m pytest -q tests/test_examples.py
```
