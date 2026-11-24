# The GitHub Action

`action.yml` at the root of this repository is a composite action. On a pull request it installs decisis,
reads a snapshot (or builds one with `init: true`), runs `check` on the files the pull request changes and
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
          inventory: package-lock.json    # optional: also run audit
          fail-on-violation: false
```

| Input | Default | What it does |
|---|---|---|
| `snapshot` | none | a snapshot file, relative to the workspace; give this or `init` |
| `init` | `false` | `true` builds the snapshot from the repository's ADRs, CODEOWNERS and postmortems |
| `github-token` | `github.token` | reads the reviews and writes the comment |
| `inventory` | none | a lockfile or SBOM; when given, `audit` runs too (with `osv-cache`, offline) |
| `fail-on-violation` | `false` | `true` fails the step when `check` or `audit` finds a violation, after the comment is written |
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
- The comment stays under GitHub's 65,536-character limit: the graph is left out first, then the lists
  are cut, and the comment says what was cut.
- The outputs `violations` and `comment-url` are set for later steps.

`.github/workflows/decisis.yml` runs the action from this checkout on this repository's own pull requests,
with `fixtures/action/vinc.json` (synthetic decisions about decisis's own files) and the audit fixtures.
