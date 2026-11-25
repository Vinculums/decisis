# Commands in detail

The README has the table of commands. This page has the flags, the limits and the output formats.

## Flags

Useful flags: `init --repo-dir DIR --repo NAME --adr-dir DIR --suggest-refs --patch FILE`, `new-adr --adr-dir DIR --code-ref PATH --rule JSON --date DATE`, `init --github OWNER/REPO --label NAME --since DATE --limit N`, `impact --hops N --format text`, `check --repo-dir DIR --reviewers HANDLE... --fail-on-unresolved --warn-days N --format text`, `paths --hops N --limit N`,
`audit --osv-cache FILE --depth N --root DIR --warn-days N`, `propose --osv-cache FILE --depth N` (give `propose` the same inputs and depth as the audit),
`serve --osv-cache FILE --allow-network --root DIR`, `gc --root DIR --grace SECONDS`.

## Limits

`paths`, `impact`, `check`, `audit`, `query` and `propose` refuse a graph over 50,000 nodes or 250,000 edges before writing
anything, and stop any query that runs longer than 60 seconds; the task directory is removed either way
and the command exits with 1. Raise a limit with `--max-nodes`, `--max-edges` or `--query-timeout`, or with
`DECISIS_MAX_NODES`, `DECISIS_MAX_EDGES` or `DECISIS_QUERY_TIMEOUT`, up to 1,000,000 nodes, 5,000,000 edges
and 3,600 seconds. `audit --depth` and `propose --depth` are 1 to 16, `paths --hops` 1 to 6 and `paths --limit`
1 to 100.

## Output

`impact`, `check`, `paths`, `audit` and `query` print JSON (`impact --format text` and `check --format text` read better for people); `check` and
`audit` also print SARIF with `--format sarif`; `demo`, `propose` and `compare` print text. `decisis <command> --help` lists the rest.

## Mermaid and HTML views

`impact`, `check`, `paths` and `audit` also take `--format mermaid` and `--format html`:

- `impact --format mermaid` prints a fenced Mermaid block that GitHub draws: each code path, the nodes
  that name it and the edges to what governs them. `--format html` prints one page with each node, its
  edge path and the evidence on each edge.
- `check --format mermaid` draws what `impact` draws for each changed file, and marks each violation in red:
  the forbidden import from the file to its target, or the file to the decision whose review it lacks.
  `--format html` lists the violations, the imports that cannot be judged, the governing and superseded
  decisions, and every import read with its resolution.
- `paths --format mermaid` draws each path between the two ids; `--format html` lists each step with the
  evidence the snapshot gives for its edge, and each node's title and `source` when it has one.
- `audit --format mermaid` draws the dependency paths to each advisory and marks the ones that break a
  decision in red; `--format html` lists each finding with its path, its policies and a link to its OSV
  source. With `--out report.json` the JSON report still goes to that file and the view to stdout.

The HTML page is one file with inline styles only: no scripts, fonts or network requests, so it opens
offline. Its only links are the sources of the findings.

## SARIF for code scanning

`check --format sarif` and `audit --format sarif` print one SARIF 2.1.0 log, the format GitHub's Security tab (code
scanning) reads. The exit code is the one `--format json` gives. The log has one run with these parts:

- The tool driver is `decisis` with the installed version. Each rule kind that judged something is a
  `reportingDescriptor` whose `id` is the kind (`imports_forbidden`, `advisory_severity_at_least`, and so on); a
  kind that judged nothing in this run is left out.
- Each violated result is a `result` with `level` `error`, each result that cannot be judged one with `warning`, and each
  result a waiver covers one with `note`. A result that is not violated is left out. A `SUPERSEDES` cycle among the
  decisions is a `warning` with the rule id `supersedes_cycle`, located at the first ADR file in the cycle.
- `message.text` holds the decision id and the reason. For `audit` it also names the package and the advisory.
- `locations` hold a repository-relative file and, where one exists, a line. `check` points to the changed file and the
  line of the import; a `review_required` result has no line, so it points to the file. `audit` points to the inventory
  file, with no line. A file that is absolute, leaves the repository, names a drive or holds a backslash gets no location. The
  file is percent-encoded, so a name with a space or a `#` stays one path.
- `properties` carry the decision id, the rule kind and the path evidence in `path`: for `check`, the changed file and the
  file the import resolves to (with the `import` as written and its `target`); for `audit`, the dependency chain from the
  repository to the package and the advisory (with the `package` and the `advisory`).
- A result a decision's waiver covers is kept at `note`, not `error`, and its `message.text` starts with
  `Waived until <date>:`, the day the waiver expires. It keeps a `suppressions` entry of kind `external` and status
  `accepted` whose `justification` is the waiver number, its expiry, its approver and its reason. From the day after the
  expiry the suppression is gone and the result is a violation again, at `error`.
- What GitHub shows: a waived result appears in the Security tab as a note, not as an error. GitHub does not read the
  `suppressions` entry, so it does not dismiss the alert on its own: dismiss it in the Security tab, or let it close when the
  violation the waiver covers is fixed.
- Every result has a `partialFingerprints` value, `decisis/v1`, the SHA-256 of the decision, the rule kind, the file and the
  import (`check`) or the package and the advisory (`audit`). It does not hold the line or the level, so a finding that
  only moves down a file, or turns from violated to waived and back, stays one alert in code scanning. Two identical
  findings in one file get the second one a `:2` suffix.
- Text from a snapshot or a pull request is put into JSON values and nowhere else. In `message.text` the characters
  `\`, `[` and `]` are escaped, so no title or reason becomes a link.

With `audit --out report.json` the JSON report goes to that file and the SARIF to stdout. The GitHub Action writes the same
log with its `sarif` input; see [the Action](action.md#code-scanning-sarif). GitHub shows at most 5,000 results of a run.

## Try them on the fixtures

From a checkout of this repository:

```
decisis paths fixtures/vinc_subgraph.json record:tls-advisory-example concept:service-api
decisis impact fixtures/impact/vinc.json reports/export.py storage/ --format text
decisis check fixtures/check/vinc.json --repo-dir fixtures/check/repo --changed src/shop/ui/view.py web/src/ui/page.ts --format html > check.html
decisis audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --osv-cache fixtures/audit/osv-cache.json --out report.json --format html > audit.html
decisis check fixtures/check/vinc.json --repo-dir fixtures/check/repo --changed src/shop/ui/view.py web/src/ui/page.ts --format sarif > check.sarif
decisis audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --osv-cache fixtures/audit/osv-cache.json --format sarif > audit.sarif
decisis propose report.json fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --space demo-space --osv-cache fixtures/audit/osv-cache.json --out plan.json
```
