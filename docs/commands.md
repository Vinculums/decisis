# Commands in detail

The README has the table of commands. This page has the flags, the limits and the output formats.

## Flags

Useful flags: `init --repo-dir DIR --repo NAME --adr-dir DIR --suggest-refs`, `new-adr --adr-dir DIR --code-ref PATH --rule JSON --date DATE`, `init --github OWNER/REPO --label NAME --since DATE --limit N`, `impact --hops N --format text`, `check --repo-dir DIR --reviewers HANDLE... --fail-on-unresolved --warn-days N --format text`, `paths --hops N --limit N`,
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

`impact`, `check`, `paths`, `audit` and `query` print JSON (`impact --format text` and `check --format text` read better for people); `demo`, `propose`
and `compare` print text. `decisis <command> --help` lists the rest.

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

## Try them on the fixtures

From a checkout of this repository:

```
decisis paths fixtures/vinc_subgraph.json record:tls-advisory-example concept:service-api
decisis impact fixtures/impact/vinc.json reports/export.py storage/ --format text
decisis check fixtures/check/vinc.json --repo-dir fixtures/check/repo --changed src/shop/ui/view.py web/src/ui/page.ts --format html > check.html
decisis audit fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --osv-cache fixtures/audit/osv-cache.json --out report.json --format html > audit.html
decisis propose report.json fixtures/audit/vinc.json fixtures/audit/demo-lockfile.json --repo Demo --space demo-space --osv-cache fixtures/audit/osv-cache.json --out plan.json
```
