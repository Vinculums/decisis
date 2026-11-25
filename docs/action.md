# The GitHub Action

`action.yml` at the root of this repository is a composite action. On a pull request it installs decisis,
reads a snapshot from the pull request's base commit (or builds one there with `init: true`), runs `check` on the files the pull request changes and
`audit` when you give an inventory, and keeps one comment on the pull request up to date: the decisions the
change touches, the violations, and a Mermaid path graph. The action is not on the Marketplace; refer to it
by repository and commit.

```yaml
name: decisis
on:
  pull_request:
permissions: {}
concurrency:
  group: decisis-${{ github.event.pull_request.number }}
  cancel-in-progress: true
jobs:
  decisis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Vinculums/decisis@<commit SHA>
        with:
          snapshot: decisions.json        # or init: true
          inventory: auto                 # optional: also run audit; or one path per line
          fail-on-violation: false
```

| Input | Default | What it does |
|---|---|---|
| `snapshot` | none | a snapshot file, relative to the workspace; give this or `init` |
| `init` | `false` | `true` builds the snapshot from the repository's ADRs, CODEOWNERS and postmortems |
| `decisions-from` | `base` | `base` reads the decisions from the pull request's base commit; `head` reads them from the checkout (see [Trust model](#trust-model)) |
| `github-token` | `github.token` | reads the reviews and writes the comment |
| `inventory` | none | `auto`, or a lockfile or SBOM, or several, one per line; when given, `audit` runs on each (with `osv-cache`, offline) |
| `fail-on-violation` | `false` | `true` fails the step when `check` or any audit finds a violation, after the comment is written; a waived finding is not a violation |
| `today` | today's UTC date | the date, `YYYY-MM-DD`, that decisions' waivers are judged on |
| `decisis-version` | the action's own checkout | a version to install from PyPI instead |
| `repo`, `working-directory`, `osv-cache`, `comment-author`, `python-version` | | see `action.yml` |

- The changed files are `git diff BASE...HEAD`, with the base commit from the event payload. Check out with
  `fetch-depth: 0`; on a shallow checkout the action fetches the history it needs.
- The reviewers that count for `review_required` are the users other than the author whose latest review
  approves the pull request; past 1,000 reviews the rest are not read, and the comment says so. Requested reviewers and teams are listed in the comment and do not count until they approve; a
  team handle in a rule matches only a team handle, so an approval by a team member does not satisfy it.
- The action needs only `contents: read` and `pull-requests: write`. Inputs reach Python as environment
  variables, never through `${{ }}` in a shell script, and Python runs with `-I`, so a module in the pull
  request's checkout cannot shadow decisis. Every title, path and reason in the comment is escaped, and
  mentions are broken so a title cannot notify anyone.
- On a pull request from a fork the token is read-only: the result goes to the job summary instead of a
  comment. The job summary always holds a copy.
- A pull request is a fork when its head repository is not the base repository; a pull request inside a
  repository that is itself a fork still gets a comment.
- Keep the `concurrency` block, so two runs on one pull request cannot both create a comment. Past 3,000
  comments on a pull request the action stops looking for its own and writes only the job summary.
- Violations a decision's waiver covers are listed apart, under "Waived, not counted as violations", with
  each waiver's expiry, approver and reason; they are not counted in the `violations` output or for
  `fail-on-violation`. From the day after a waiver's `expires` date the finding is a violation again.
- The comment stays under GitHub's 65,536-character limit: the graph is left out first, then the lists
  are cut, and the comment says what was cut.
- The outputs `violations` and `comment-url` are set for later steps. `violations` is the check's
  violations plus the audit violations of every inventory.

## Trust model

The decisions a run uses are the snapshot file, or the ADRs, CODEOWNERS file and postmortems `init` reads.
With `decisions-from: base`, the default, they are read from the pull request's base commit: the tip of the
branch it would merge into. Only someone who can merge into that branch can change them, so a pull request
cannot add a waiver for its own violation, drop a rule it breaks, or move a CODEOWNERS line to escape a
review. What is judged still comes from the pull request: the changed files, their imports and the
inventories.

- The files are read from the base commit's tree with git (`git ls-tree` and `git cat-file`, with hooks,
  fsmonitor and pagers off) into a private temporary directory that is removed afterwards. Nothing is checked
  out and nothing from the base commit runs. Only regular files are read; a symbolic link in the base commit
  is listed in the snapshot's problems and not followed. A `snapshot` file must be inside
  `working-directory` and committed; the action stops with an error otherwise.
- CODEOWNERS patterns come from the base commit and are matched against the files of both the base commit
  and the checkout, so a new file is owned as the base's CODEOWNERS says.
- When the pull request changes a file the decisions come from, the comment and the job summary list those
  files under "Decision changes that take effect once merged", and name each decision and waiver the pull
  request adds, changes or removes when the decisions can be read on both sides. Those changes do not change
  any verdict in the run.
- When the base commit has no snapshot file at the path, or no ADR with a decision, the comment says that no
  decisions exist on the base yet. Nothing is judged, `violations` is 0 and the step does not fail.

`decisions-from: head` reads the decisions from the checkout, as the action did before. Then the pull request
under review decides which rules and waivers judge it, so use it only where everyone who can open a pull
request may also change the decisions.

## Inventories

`inventory` takes one path, several paths one per line, or `auto`:

```yaml
        with:
          inventory: |
            auto
            web/package-lock.json
```

- A path is relative to the workspace and is read as `decisis audit` reads it. A path that cannot be
  audited (missing, unreadable, no packages) stops the step with an error, as with one path.
- `auto` audits the inventories in the root of `working-directory`: `package-lock.json`,
  `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`,
  `requirements*.txt`, `Cargo.lock`, `go.mod`, `gradle.lockfile`, `pom.xml`, `.terraform.lock.hcl`, and
  `.github/workflows` when one of its YAML files is a workflow (all the workflows there are read together).
  No other directory is searched, so fixtures and vendored code are never audited; list a nested
  lockfile as a path next to `auto`. An SBOM is never found by `auto`; give its path.
- A file `auto` finds is read only when it resolves inside `working-directory`: a symbolic link that leads
  outside is not followed, and neither is one beside it (a `go.sum`, a sibling workflow). Such a file, or
  one that cannot be audited, gets a section saying why; it is not a violation and does not stop the step.
- Each inventory has its own audit section in the comment and the job summary, and its own graph.
  `fail-on-violation` counts the violations of all of them. When `auto` finds nothing, the comment says
  so and nothing fails.
- A file found twice (by `auto` and by its path) is audited once.

`.github/workflows/decisis.yml` runs the action from this checkout on this repository's own pull requests,
with `fixtures/action/vinc.json` (synthetic decisions about decisis's own files) and the audit fixtures.
