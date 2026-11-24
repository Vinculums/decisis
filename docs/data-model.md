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
| `Repository` | the inventory | `id` = `repo:<name>`, `source_system` (see below), `source_ref`, `fetched_at`, `content_hash` of the inventory |
| `Package` | the inventory | `id` = `pkg:<purl type>/<name>@<version>`, `ecosystem`, `name`, `version`, `dev`, `licenses`, `license_expression`, `purl`, `unresolved`, `source_system`, `source_ref`, `fetched_at` |
| `Advisory` | OSV | `id` = `adv:<osv id>`, `osv_id`, `severity`, `aliases`, `published`, `affected_json`, `source_url`, `fetched_at`, `content_hash` of the OSV record |

| Edge | Meaning | `evidence` |
|---|---|---|
| snapshot edges | as in the snapshot | as in the snapshot |
| `DEPENDS_ON` | the repository or a package requires a package | the requirement as the inventory states it |
| `AFFECTED_BY` | OSV returned the advisory for this name and version | `OSV returned <id> for this name and version` |
| `DESCRIBED_BY` | the repository to a snapshot node whose `code_ref` names it | `<node> has code_ref <ref>` |

## Inventories

`audit` reads one inventory and tells its format from the content and the file name. Every reader
returns the same nodes and edges.

| Format | `source_system` | Repository | `DEPENDS_ON` | `dev` |
|---|---|---|---|---|
| npm `package-lock.json` v2 or v3 | `npm-lockfile` | the root entry | `dependencies`, `devDependencies` and `optionalDependencies`, resolved through nested `node_modules` | the lockfile's `dev` |
| CycloneDX JSON 1.4 to 1.6 | `cyclonedx-sbom` | `metadata.component` | `dependencies[].dependsOn` | scope `excluded`, or property `cdx:npm:package:development` `true` |
| SPDX JSON 2.3 | `spdx-sbom` | the packages the document `DESCRIBES` | `DEPENDS_ON`, `CONTAINS` and the `*_DEPENDENCY_OF` relationships | reached only through `DEV_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF` or `DEV_TOOL_OF` |
| `uv.lock` | `uv-lockfile` | packages with an `editable`, `virtual`, `directory` or `path` source | `dependencies`, `optional-dependencies`, `dev-dependencies` | reached only through a dependency group |
| `Cargo.lock` | `cargo-lockfile` | packages without a `source` (the workspace) | `dependencies` (`name`, `name version` or `name version (source)`) | always false; the lockfile does not mark it |
| `go.mod` with `go.sum` | `go-modules` | the module | every `require`, after `replace`; `// indirect` is kept in the evidence | always false |

Package props:

- `ecosystem` is the OSV ecosystem (`npm`, `PyPI`, `crates.io`, `Go`; from an SBOM purl also `Maven`,
  `NuGet`, `RubyGems`, `Packagist`, `GitHub Actions`, `Debian:<n>` from `distro=debian-<n>`, `Alpine:v<x.y>`
  from `distro=alpine-<x.y...>`). A purl type with no such mapping gives `""`.
- `name` is the name OSV uses: `@scope/name` for npm, the normalized name for PyPI, `group:artifact` for
  Maven, the module path for Go.
- `version` is the resolved version; Go versions drop the leading `v` (the `purl` keeps it).
- `licenses` is the list of SPDX ids in the license expression, empty when the inventory gives none
  (`uv.lock`, `Cargo.lock` and `go.mod` do not). `license_expression` keeps the expression as written.
- `purl` is the package URL without qualifiers.
- `unresolved` is empty when the package can be queried at OSV, and otherwise says why not (no ecosystem,
  no version). Unresolved packages stay in the graph, are not queried, and are listed in the report.
- `dev` is true when the package is reached only through development dependencies. When an SBOM lists
  one package id more than once, one production instance makes it shipped; it is development only when
  every instance is marked development and nothing shipped reaches it.

An SBOM component without a purl gets the id `pkg:unknown/<name>@<version>`, ecosystem `""` and
`unresolved` `the inventory gives no purl`, with its CPE when it has one. An SBOM package that nothing
depends on is linked from the repository with the evidence `listed in the SBOM with no dependency on it`.
`audit` refuses an inventory that lists no packages, or none that can be queried at OSV, instead of
reporting it clean.

For Go, `audit` is given `go.mod` and reads `go.sum` from the same directory. It stops when there is no
`go.sum`, or when a required module version has no line in it. A `replace` to a local path drops the
module; a `replace` to another module uses that module and version. Modules that appear only in `go.sum`
are not read: from Go 1.17, `go.mod` lists every module in the build.

Readers live in `src/decisis/inventory/`. Each one has `FORMAT`, `SIBLINGS` (files read from the same
directory), `detect(text, filename)` and `read(text, filename, repo, siblings=None)` returning
`(nodes, edges)`; `inventory.read` picks the first reader whose `detect` matches.

## Versions

A finding is `affected` when the version is listed in the advisory, or falls in one of its `SEMVER` or
`ECOSYSTEM` ranges. Range events are sorted by version before they are read. `SEMVER` ranges and the
`ECOSYSTEM` ranges of npm, crates.io and Go are ordered as semantic versions (a leading `v` and build
metadata are ignored; Go pseudo-versions order as pre-releases). PyPI `ECOSYSTEM` ranges are ordered by
PEP 440 (epoch, release, pre, post, dev and local segments). A version at or above a range's `limit` is
not affected. A version that cannot be ordered, or an `ECOSYSTEM` range of another ecosystem, gives
`unresolved`, never `affected`.

## The OSV cache

`--osv-cache` reads a JSON object with `fetched_at` (when the advisories were read), `queries` (a
package id such as `pkg:npm/lodash@4.17.15` to the list of advisory ids OSV returned for it) and `vulns`
(an advisory id to the OSV record as `api.osv.dev/v1/vulns/<id>` returns it). A package or advisory the
file does not hold stops the run. The keys follow the package ids, so a cache works for every ecosystem.
`fixtures/audit/osv-cache.json` covers the demo lockfile and `fixtures/inventory/osv-cache.json` covers
the examples in `fixtures/inventory/`.

## The report and the plan

`audit --out report.json` writes `meta`, `loaded` (node and edge counts), `governing` (decisions and the
node they reach the repository through), `summary` (counts by status), `violations`, and `findings`. A
finding has `package`, `advisory`, `severity`, `status` (`affected`, `not_affected`, `unresolved`),
`dev_only`, `path` (ids from `repo:<name>` to the advisory), `source_url`, `fetched_at`, `content_hash`,
`advisory_summary` and `policies` (one `decision`, `verdict` and `why` per governing decision).
`unresolved_packages` lists each package that was not queried (`package`, `reason`).

`propose --out plan.json` writes `space`, `nodes` (records), `edges` (`relates_to` from a record to a
decision, with the verdict as evidence), `held` (findings not recorded and why; a record that failed a re-derivation check has `record` and `failed`, the list of
failed checks) and `digest`: the first 16
hex digits of SHA-256 over the space, nodes and edges as sorted JSON. A record's id is
`record:<repo>-<package>-<shipped|development>-<advisory>`, and its props hold the claim (`entity`,
`predicate`, `value`, `statement`), the evidence (`source`, `advisory_fetched_at`, `advisory_content_hash`,
`dependency_paths`, `lockfile_hash`) and `violates`.

## The demo transcript

`demo/transcript.json` lists each step with its printed lines and counts, the approval, the findings,
and run-time stamps only under `timestamps`; `demo/expected_findings.json` is the findings part alone.
Two runs differ only in `timestamps`.
