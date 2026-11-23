# Data model

## The snapshot

Every command that reasons (`paths`, `impact`, `audit`) reads a snapshot: one JSON file with the slice
of knowledge a task needs. `checkout` writes one from Vinc, but nothing in the format is specific to
Vinc. You can write one by hand from your own notes, decisions and incident records.

```json
{
 "meta": {"seeds": ["concept:shop-web"], "space": "my-notes", "nodes": 4, "edges": 3},
 "nodes": [
  {"id": "concept:shop-web", "kind": "concept", "title": "Shop web app", "props": {"code_ref": "Shop:src/"}},
  {"id": "concept:checkout-flow", "kind": "concept", "title": "Checkout flow", "props": {"code_ref": "Shop:src/checkout/"}},
  {"id": "decision:no-high-advisories-when-shipped", "kind": "decision", "title": "No high advisories in what we ship",
   "props": {"statement": "A shipped dependency may not carry a HIGH or CRITICAL advisory.",
             "rule": {"advisory_severity_at_least": "HIGH", "dependencies": "shipped"}}},
  {"id": "record:checkout-timeout-october", "kind": "record", "title": "Checkout timed out under load", "props": {"source": "incident notes"}}
 ],
 "edges": [
  {"source": "decision:no-high-advisories-when-shipped", "target": "concept:shop-web", "type": "ABOUT", "evidence": "applies to the whole app"},
  {"source": "concept:checkout-flow", "target": "concept:shop-web", "type": "RELATED_TO", "evidence": "part of the app"},
  {"source": "record:checkout-timeout-october", "target": "concept:checkout-flow", "type": "RELATED_TO", "evidence": "the timeout was in this flow"}
 ]
}
```

Save it as `my-snapshot.json` and run, offline:

```
.venv/bin/decisis paths my-snapshot.json record:checkout-timeout-october concept:shop-web
.venv/bin/decisis impact my-snapshot.json src/checkout/pay.py --format text
.venv/bin/decisis audit my-snapshot.json fixtures/audit/demo-lockfile.json --repo Shop --osv-cache fixtures/audit/osv-cache.json
```

`paths` finds the two-hop route from the incident through the checkout flow to the app. `impact` lists
both concepts (each names a directory that holds the path), the decision one hop from the app and the
incident record one hop from the checkout flow; it does not carry governance along the `RELATED_TO`
between the two concepts, because both name code of their own. `audit` treats the demo lockfile as the
Shop repository's and reports which of the cached advisories break the decision (three findings on
shipped `lodash` violate it).
`tests/test_docs.py` runs this example, so it stays in step with the code.

### Fields

| Field | Required | Meaning |
|---|---|---|
| `nodes[].id` | yes | A unique id. Vinc ids look like `kind:slug`; any string works. |
| `nodes[].kind` | yes | Becomes the node's label in Relate (`decision` becomes `Decision`). It must start with a letter after non-alphanumeric characters become `_`. `impact` and `audit` look for `concept`, `decision` and `record`. |
| `nodes[].title` | no | A short name; shown in output. |
| `nodes[].domain` | no | A grouping such as `platform/security`. |
| `nodes[].props` | no | Free properties. Strings, numbers, booleans, null and lists of those are stored on the Relate node; other values (such as a `rule` object) stay in the snapshot, where the Python side reads them. |
| `edges[].source`, `edges[].target` | yes | Node ids in this snapshot. An edge whose endpoint is missing fails the load and is named in the error. |
| `edges[].type` | yes | The relationship type, kept with its direction. |
| `edges[].evidence` | no | Why the edge holds; carried on the Relate edge and printed with each path. |
| `meta` | no | `seeds`, `space` and `extracted_at` from `checkout`. When `meta.nodes` or `meta.edges` is a number, the load refuses a file whose lists have a different length. |

Properties the commands read:

- `code_ref` (a string or list) on any node: the code it describes, as `path`, `Repo:path` or
  `Repo:path:symbol`. `audit --repo Shop` links the repository to every node whose `code_ref` is `Shop` or
  starts with `Shop:`; `impact` matches the path part. Decisions may also name code with `subject_path`
  and `also_touches`.
- `rule` on a decision: `{"advisory_severity_at_least": "LOW" | "MODERATE" | "MEDIUM" | "HIGH" | "CRITICAL",
  "dependencies": "shipped"}` (the second key is optional), as an object or a JSON string. A decision
  without a valid rule is reported as `relevant`, never `violated`.

Edge types `checkout` keeps from Vinc: `ABOUT`, `RELATED_TO`, `PREREQUISITE_OF`, `DERIVES_FROM`,
`INHERITS_FROM`, `SUPERSEDES`, `CONNECTS_VIA`, `RETURNS_TO`. A record's edge that Vinc returns as
`ATTACHES_TO` with a role is read as that role (`relates_to` becomes `RELATED_TO`). A hand-written
snapshot may use any type; `impact` follows only `ABOUT`, `DERIVES_FROM`, `INHERITS_FROM`, a record's
`RELATED_TO`, `PREREQUISITE_OF`, `DERIVES_FROM` or `INHERITS_FROM`, and `RELATED_TO` between concepts
from one that names no code (see `CARRIES` in `src/decisis/impact.py`).

## The Relate graph of an audit

| Label | From | Key properties |
|---|---|---|
| `Concept`, `Decision`, `Record`, ... | the snapshot | `id`, `title`, `domain`, flattened `props` |
| `Repository` | the lockfile | `id` = `repo:<name>`, `source_system` `npm-lockfile`, `fetched_at`, `content_hash` of the lockfile |
| `Package` | the lockfile | `id` = `pkg:npm/<name>@<version>`, `name`, `version`, `dev`, `source_ref` (the lockfile path), `fetched_at` |
| `Advisory` | OSV | `id` = `adv:<osv id>`, `osv_id`, `severity`, `aliases`, `published`, `affected_json`, `source_url`, `fetched_at`, `content_hash` of the OSV record |

| Edge | Meaning | `evidence` |
|---|---|---|
| snapshot edges | as in the snapshot | as in the snapshot |
| `DEPENDS_ON` | the repository or a package requires a package, resolved through nested `node_modules` | the requirement as the lockfile states it |
| `AFFECTED_BY` | OSV returned the advisory for this name and version | `OSV returned <id> for this name and version` |
| `DESCRIBED_BY` | the repository to a snapshot node whose `code_ref` names it | `<node> has code_ref <ref>` |

## The OSV cache

`--osv-cache` reads a JSON object with `fetched_at` (when the advisories were read), `queries` (a
package id such as `pkg:npm/lodash@4.17.15` to the list of advisory ids OSV returned for it) and `vulns`
(an advisory id to the OSV record as `api.osv.dev/v1/vulns/<id>` returns it). A package or advisory the
file does not hold stops the run. `fixtures/audit/osv-cache.json` covers the demo lockfile.

## The report and the plan

`audit --out report.json` writes `meta`, `loaded` (node and edge counts), `governing` (decisions and the
node they reach the repository through), `summary` (counts by status), `violations`, and `findings`. A
finding has `package`, `advisory`, `severity`, `status` (`affected`, `not_affected`, `unresolved`),
`dev_only`, `path` (ids from `repo:<name>` to the advisory), `source_url`, `fetched_at`, `content_hash`,
`advisory_summary` and `policies` (one `decision`, `verdict` and `why` per governing decision).

`propose --out plan.json` writes `space`, `nodes` (records), `edges` (`relates_to` from a record to a
decision, with the verdict as evidence), `held` (findings not recorded and why) and `digest`: the first 16
hex digits of SHA-256 over the space, nodes and edges as sorted JSON. A record's id is
`record:<repo>-<package>-<shipped|development>-<advisory>`, and its props hold the claim (`entity`,
`predicate`, `value`, `statement`), the evidence (`source`, `advisory_fetched_at`, `advisory_content_hash`,
`dependency_paths`, `lockfile_hash`) and `violates`.

## The demo transcript

`demo/transcript.json` lists each step with its printed lines and counts, the approval, the findings,
and run-time stamps only under `timestamps`; `demo/expected_findings.json` is the findings part alone.
Two runs differ only in `timestamps`.
