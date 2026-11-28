# Commands in detail

The README has the table of commands. This page has the flags, the limits and the output formats.

## Flags

Useful flags: `init --repo-dir DIR --repo NAME --adr-dir DIR --suggest-refs --patch FILE`, `new-adr --adr-dir DIR --code-ref PATH --rule JSON --date DATE`, `init --github OWNER/REPO --label NAME --since DATE --limit N`, `impact --hops N --today DATE --keep-graph FILE --force --format text`, `check --repo-dir DIR --reviewers HANDLE... --fail-on-unresolved --warn-days N --no-signature --keep-graph FILE --force --format text`, `paths --hops N --limit N --keep-graph FILE --force`,
`audit --osv-cache FILE --depth N --root DIR --warn-days N --no-signature --keep-graph FILE --export-vault DIR --force`, `query --param KEY=VALUE --profile`, `search --kind KIND --limit N --format text`, `export-vault --out DIR --lockfile FILE --repo NAME --osv-cache FILE --force`, `propose --osv-cache FILE --depth N` (give `propose` the same inputs and depth as the audit),
`serve --osv-cache FILE --allow-network --root DIR`, `gc --root DIR --grace SECONDS`.

## Limits

`paths`, `impact`, `check`, `audit`, `query` and `propose` refuse a graph over 50,000 nodes or 250,000 edges before writing
anything, and stop any query that runs longer than 60 seconds; the task directory is removed either way
and the command exits with 1. Raise a limit with `--max-nodes`, `--max-edges` or `--query-timeout`, or with
`DECISIS_MAX_NODES`, `DECISIS_MAX_EDGES` or `DECISIS_QUERY_TIMEOUT`, up to 1,000,000 nodes, 5,000,000 edges
and 3,600 seconds. `audit --depth` and `propose --depth` are 1 to 16, `paths --hops` 1 to 6 and `paths --limit`
1 to 100. `query` on a saved `.rl` file or a vault counts its nodes and edges first and refuses one over the same
caps without running the statement.

## Saved graphs and vaults

`--keep-graph FILE` (on `paths`, `impact`, `check` and `audit`) copies the sandbox's Relate database to `FILE`
before the sandbox is deleted. The name must end in `.rl`, the extension `query` reads as a saved graph. An
existing file is refused unless `--force` is given, and a file that is an input of the run (the snapshot, the
lockfile, the OSV cache, the report) is refused even with `--force`. The checks run before any work, and the copy
is written next to `FILE` and moved into place, so a failed run leaves the old file as it was. `paths` and `audit`
save the graph they loaded; `impact` and `check` save the graph they query, the snapshot's nodes with only the
edges that carry governance.

`export-vault --out DIR` and `audit --export-vault DIR` write a Relate Markdown vault: one note per node under a
folder per label, with the node's properties as YAML front matter and its edges as `[[wikilinks]]`. The vault
holds a `.decisis-vault` file at its top, and `--force` replaces only a directory that holds it. Without
`--force` a non-empty directory is refused. The current directory, a directory above it, your home directory or
one above it, the filesystem root, and any directory that holds an input of the run are refused even with
`--force`. `audit --export-vault` checks the directory before the audit runs.

Before writing, the export refuses a snapshot that the sandbox would refuse: a repeated node id (also one id
under two kinds), an edge with a missing endpoint, or a `props.id` that differs from the node's id; the error
names the ids. The vault is written to a new directory next to `DIR`, its node and edge counts are checked, and
only then is it moved to `DIR` (the old vault is removed after the move). On any failure nothing is left behind
and an old vault stays as it was. The reported `nodes` and `edges` are the counts read back from the vault.

Every node property is kept under its own name, `name`, `body` and `id` included, so a query gives the same
rows on the saved `.rl` file and on the vault. The note's file name is stored in the property `decisis_file`
(made from the id, unique per label) and the note text below the front matter in `decisis_note` (the title as a
heading and the statement or summary); a snapshot that already uses either name is refused. `title` and `domain`
are the node's own fields, as in the sandbox.

`audit` walks the shipped dependency paths on `DECISIS_SHIPPED_STEP` edges it adds in the sandbox, one for each
`DEPENDS_ON` edge whose target is not a dev package, so Relate finds them with its breadth-first search instead
of listing every path; it removes them before `--keep-graph` saves the graph. A snapshot that already has edges
of that type is refused.

`search --kind KIND` filters inside the fulltext query, so a match is found however many nodes of other kinds
rank above it. When more nodes match than `--limit`, the reply carries a `cut` note (in text, a last line) that
says so.

## Checkout

`decisis checkout SEED... --depth N --out snapshot.json` reads each seed from Vinc with one `vinc_graph` call at `detail: "full"`
and writes the snapshot. The snapshot carries, for every node the hub returns, its `id`, `kind`, `title`, `domain`, `valid_until`
and its whole `props`: `code_ref`, `subject_path`, `also_touches`, `status`, the decision's rules and waivers, and everything else
stored on the node. `impact` and `check` match a path through those props, so a node that is not the seed anchors a path as well. `impact`, `check` and
`audit` read `valid_until` of a decision, from the node's field or from `props.valid_until`, and a decision whose date is on or before
the run's date (`--today`) no longer governs: see [A decision closed by `valid_until`](data-model.md#a-decision-closed-by-valid_until). The hub's layout
and ranking fields (`x`, `y`, `z`, `ppr`, `degree`, `rev`, `tags`, timestamps) are left out. The edges keep their type, direction and
evidence. The node and edge counts and the depth are the hub's; `--depth` is passed through, and a read is one call per seed.

`detail: "full"` makes a larger reply than the default `summary`, and the hub keeps a reply inside its result size limit. When it
shrinks a reply it empties the props of nodes first. The checkout never fills them in: `meta.props_missing` lists each node
whose props the hub did not send, because it returned the node with no `props` at all (a hub that ignores `detail`), or because it
said it emptied props to fit its limit and the node arrived with empty props. An id on that list may truly have no props; an id
off it carries the props the hub holds. Read the nodes that matter by id, or seed on a node with fewer neighbours.
`meta.props_missing` is absent when nothing is missing.

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
offline. Its only links are the sources of the findings and, in the signature, this repository.

`check --format html` and `audit --format html` end with one line that says what the run did, for example
`Audited locally with decisis 0.5.1 (0 LLM calls · deterministic graph check · digest: 599582f5f4f7)`:
`locally` only when the run contacted no host, otherwise what it fetched and from where, and a digest of the
result that is the same for the same inputs. [The signature](data-model.md#the-signature) defines each part.
`--no-signature` leaves the line out of the page and changes nothing else; no other format has the line.

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
