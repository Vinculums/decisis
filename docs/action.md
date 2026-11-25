# The GitHub Action

`action.yml` at the root of this repository is a composite action. On a pull request it installs decisis,
reads a snapshot from the pull request's base commit (or builds one there with `init: true`), runs `check` on the files the pull request changes and
`audit` when you give an inventory, and keeps one comment on the pull request up to date: the decisions the
change touches, the violations, and a Mermaid path graph. It is on the GitHub Marketplace as
[decisis check](https://github.com/marketplace/actions/decisis-check).

Refer to it as `Vinculums/decisis@v0` to follow every 0.x release, or as `Vinculums/decisis@v0.4.2` for one
release. A tag can be moved, so for a required check pin the full commit SHA of a release instead, with the
version in a comment, as the example below does for `actions/checkout`; Dependabot and Renovate update
such pins. The action installs decisis from its own checkout, so the version it runs is the one you refer to.

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
      - uses: Vinculums/decisis@v0         # or a full commit SHA, see above
        with:
          snapshot: decisions.json        # or init: true
          inventory: auto                 # optional: also run audit; or one path per line
          fail-on-violation: false
          fail-on-unresolved: false
          warn-days: 14                   # optional: list waivers that expire within this many days; 0 turns it off
```

| Input | Default | What it does |
|---|---|---|
| `snapshot` | none | a snapshot file, relative to the workspace; give this or `init` |
| `init` | `false` | `true` builds the snapshot from the repository's ADRs, CODEOWNERS and postmortems |
| `decisions-from` | `base` | `base` reads the decisions from the pull request's base commit; `head` reads them from the checkout (see [Trust model](#trust-model)) |
| `github-token` | `github.token` | reads the reviews and writes the comment |
| `inventory` | none | `auto`, or a lockfile or SBOM, or several, one per line; when given, `audit` runs on each (with `osv-cache`, offline) |
| `fail-on-violation` | `false` | `true` fails the step when `check` or any audit finds a violation, after the comment is written; a waived finding is not a violation |
| `fail-on-unresolved` | `false` | `true` fails the step when the run finds anything that cannot be judged (see [What counts as unresolved](#what-counts-as-unresolved)), after the comment and the job summary are written |
| `today` | today's UTC date | the date, `YYYY-MM-DD`, that decisions' waivers are judged on |
| `sarif` | `false` | `true` writes `decisis.sarif` in the workspace, sets the `sarif-file` output and uploads the file to code scanning (see [Code scanning](#code-scanning-sarif)) |
| `warn-days` | `14` | the comment lists, under "Waivers that expire soon", each waiver that covers a result and expires within this many days of `today`; `0` turns it off; it never fails the step. A value that is not a whole number from 0 to 3650 stops the step before any request |
| `signature` | `true` | `true` ends the comment's footer with one line built from the run: `Checked` or `Audited`, `locally` or what the run fetched, the decisis version, `0 LLM calls`, `deterministic graph check` and a digest of the result (see [the signature](data-model.md#the-signature)); `false` leaves the line out and changes nothing else |
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
- Waivers that cover a result in this run and expire within `warn-days` days (14 by default) are listed above the
  violations, under "Waivers that expire soon", with the decision, the waiver number, the expiry date, the days
  left, the approver and the reason. A waiver is listed once, whether `check` or an audit found what it covers. The
  section is a warning only: it is not counted in any output, and it changes no result of `fail-on-violation` or
  `fail-on-unresolved`.
- An ADR in the snapshot's `meta.problems` that `init` skipped or did not read, such as one whose `rule:` or
  `waivers:` line holds JSON that does not parse, is listed under "Decision files not read" with its file and
  reason, in the comment and the job summary, and counted in the comment's first line. Its rules are not
  judged. It is not a violation: neither the `violations` output nor `fail-on-violation` counts it. The
  `unresolved` output and `fail-on-unresolved` count it, as `decisis check --fail-on-unresolved` does.
- A changed file that a CODEOWNERS owner set covers and no `review_required` rule covers is listed with its owners under
  "CODEOWNERS owners of changed files, not enforced", with a note that decisis does not enforce CODEOWNERS: turn on "Require
  review from Code Owners" in branch protection, or add a `review_required` rule to an ADR (see
  [the data model](data-model.md#codeowners-owner-sets-become-concepts)). The section is information only; it is not
  counted in any output and changes no result. It is also in the comment that says the base commit has no decisions.
- The comment stays under GitHub's 65,536-character limit: the graph is left out first, then the lists
  are cut, and the comment says what was cut.
  The footer's line is kept when the comment has to be cut.
- The comment's footer is one line: the decisis version linked to this repository, `0 LLM calls`, `deterministic graph check`,
  what the run fetched, a digest of the result, the snapshot and a note that the comment is updated on each run. The action says
  `locally` only when it contacted no host. It reads the pull request's reviews from api.github.com, so a run that
  judged anything names that, and it names api.osv.dev when an audit fetched advisories, and the origin remote when it
  fetched the base commit. Posting the comment is not counted. `signature: false` brings back the footer without the
  signature. The comment that says the base commit has no decisions carries no signature, because nothing was checked.
- The outputs `violations`, `unresolved` and `comment-url` are set for later steps, and `sarif-file` with `sarif: true`. `violations` is the
  check's violations plus the audit violations of every inventory. `unresolved` is the count described under
  [What counts as unresolved](#what-counts-as-unresolved); it is set whether or not `fail-on-unresolved` is on,
  and is 0 when the base commit has no decisions.

## Code scanning (SARIF)

With `sarif: true` the action also writes the results of `check` and of every audit as SARIF 2.1.0 to `decisis.sarif` in
`GITHUB_WORKSPACE`, sets the `sarif-file` output to its path, and uploads it with
[`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action) (pinned to a full commit SHA in
`action.yml`), so the findings show in the repository's Security tab and on the pull request. The comment, the job summary,
the outputs and the exit code are the same with and without the input; the file is written after the comment.

```yaml
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Vinculums/decisis@<commit SHA>
        with:
          snapshot: decisions.json
          inventory: auto
          sarif: true
```

- The job needs `security-events: write`. In a private repository it also needs `actions: read`, and code scanning
  must be available for the repository. The upload step uses the workflow token, not `github-token`.
- Pull requests from forks cannot upload: their token is read-only, so the upload step is skipped for them. The file is
  still written and `sarif-file` is still set, so a later step can keep it as an artifact. A token without
  `security-events: write` (a Dependabot pull request, for one) fails the upload step.
- The log has one run for `check` and one run for each inventory audited, each with its own category
  (`decisis/check/`, `decisis/audit/<inventory>/`), so the alerts of one inventory do not close the alerts of another. An
  inventory outside the repository is audited but its results have no location, and its category is
  `decisis/audit/outside-<hash>/`, where the hash is taken from its resolved path, so two such inventories keep two
  categories and two sets of fingerprints and no path appears in the log.
- Locations are repository-relative. With `working-directory` below the repository root, the directory is put before each
  changed file. A path that is absolute or leaves the repository gets no location.
- A result a waiver covers is uploaded at level `note`, with a message that starts with `Waived until <date>:` and an
  accepted suppression whose justification is the waiver. In the Security tab it appears as a note, not as an error.
  GitHub does not read the suppression, so it does not dismiss the alert on its own: dismiss it in the Security tab, or let
  it close when the violation the waiver covers is fixed. The alert is the same one the violation was, so a finding that
  turns from violated to waived, or back, is not a new alert. From the day after the waiver's expiry the suppression is gone
  and the result is an `error` again. Results that are not violated are not in the file.
- A step later in the job can read the file: `${{ steps.<id>.outputs.sarif-file }}`. When the base commit has no decisions
  the file is a valid log with no results.
- The format, the fields and the fingerprints are described in [Commands](commands.md#sarif-for-code-scanning).

## What counts as unresolved

With `fail-on-unresolved: true` the step fails when any of these is present, and the `unresolved` output is
their sum:

- a `check` result that cannot be judged (listed under "Cannot be judged"), such as an import computed at run
  time, a file the scanner cannot finish, or a `SUPERSEDES` cycle among the decisions, on the base commit or added by
  the pull request (its decisions are judged as in force, and the entry names each one and its file);
- an audit finding whose status is unresolved, in any inventory, whether or not a decision's rule covers it,
  such as an advisory whose affected versions cannot be compared with the package's version, or a Docker image
  under a `pinned_to_commit` rule;
- an unresolved package of any inventory, such as a requirements line with no pinned version or a `docker://`
  step (each package counts once per inventory);
- an entry in "Decision files not read" (counted once, though every section of the run lists it).

A waiver covers only a violation, so a waived result is never unresolved and never counts. An inventory that
`auto` found but could not audit gets a section saying why and does not count; a rule that cannot be checked,
under "Rules that cannot be checked", does not count either. The step fails after the comment and the job
summary are written, and the comment's first line after the hidden marker says which of these were found, for
example "This check fails: fail-on-unresolved is on and the run found 2 check result(s) that cannot be judged,
1 decision file(s) not read." With `false`, the default, the step and the comment are as without the input.

## Trust model

The decisions a run uses are the snapshot file, or the ADRs, CODEOWNERS file and postmortems `init` reads.
With `decisions-from: base`, the default, they are read from the pull request's base commit: the tip of the
branch it would merge into. A change the pull request makes to the decision files themselves does not count
in its own run, so it cannot waive its own violation, drop a rule it breaks, or move a CODEOWNERS line to
escape a review by editing those files. What is judged still comes from the pull request: the changed files,
their imports and the inventories.

That alone does not stop a pull request from changing how it is judged. On `pull_request` the workflow file
also comes from the pull request, so the pull request can edit the decisis step: set `decisions-from: head`,
point `snapshot:` at a path the base commit does not have (which judges nothing and passes), set
`fail-on-violation` or `fail-on-unresolved` to `false`, or remove the step. decisis cannot see or prevent that. What protects the setup
is the repository's own settings:

- Require review from the owners of `.github/workflows/` and of the decision files (the snapshot, the ADR and
  postmortem directories, `CODEOWNERS`) with CODEOWNERS and branch protection, or a ruleset that restricts
  changes to those paths.
- Make the decisis check a required status check, so a pull request that removes or breaks the step cannot
  merge. With `fail-on-violation: true` the check also fails on a violation, and with `fail-on-unresolved: true`
  on anything that cannot be judged.

The rest of this section describes how the decisions are read.

- The files are read from the base commit's tree with git (`git ls-tree` and `git cat-file`, with hooks,
  fsmonitor and pagers off) into a private temporary directory that is removed afterwards. Nothing is checked
  out and nothing from the base commit runs. Only regular files are read. What lies in an ADR directory
  besides its record files (files in subfolders, symbolic links, submodules) is listed by the same rule and the
  same bounds as `init` (see [the data model](data-model.md#a-snapshot-from-a-repository-init)), and no link is
  followed. A `snapshot` file must be inside
  `working-directory` and committed; the action stops with an error otherwise.
- git runs on the repository whose `.git` is in `working-directory` or the nearest folder above it, named
  with `--git-dir`, and that repository must be inside `GITHUB_WORKSPACE`. Implicit bare repositories and
  replace refs are refused, so a folder the pull request adds cannot pose as the repository.
- CODEOWNERS patterns come from the base commit and are matched against the files of both the base commit
  and the checkout, so a new file is owned as the base's CODEOWNERS says. The 100,000-file cap counts the base's
  files only, so files the pull request adds cannot drop the base's owners.
- When the pull request changes a file the decisions come from, the comment and the job summary list those
  files under "Decision changes that take effect once merged", and name, when the decisions can be read on both
  sides, each decision and waiver the pull request adds, changes or removes, each `SUPERSEDES` edge between
  decisions it adds or removes, the decisions that become superseded or return to force once it is merged, and
  each `SUPERSEDES` cycle it adds or removes with its decisions and files. "No decision or waiver is added,
  changed or removed" appears only when none of these applies. Those changes do not change any verdict in the
  run, except that a cycle the pull request adds is a result that cannot be judged, listed under "Cannot be
  judged", so `fail-on-unresolved: true` fails the pull request that adds it. A cycle already on the base
  commit is listed once, as it was before.
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
