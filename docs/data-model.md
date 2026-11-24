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
| `meta` | no | `seeds`, `space` and `extracted_at` from `checkout`; `source`, `repo` and `problems` from `init`. When `meta.nodes` or `meta.edges` is a number, the load refuses a file whose lists have a different length. |

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

## A snapshot from a repository: `init`

```
decisis init --repo-dir . --repo Shop --out snapshot.json
decisis impact snapshot.json src/payments/retry.py --repo Shop --format text
```

`init` reads three kinds of file a repository often already has and writes a snapshot that every other
command loads. It reads no code and no prose beyond the fields below, and it never guesses: a file it cannot
read or parse is listed in `meta.problems` with the reason and left out. Each entry has `file`, `reason` and
`action`: `skipped` (the file or line is not in the snapshot), `kept without code paths` (the node is there
but no code path anchors it), `no edge` (a reference did not resolve to exactly one ADR), `no effect` (a
CODEOWNERS line that owns no file) or `not read`.
`fixtures/init/shop` is an example repository with each format and each kind of problem.

| Flag | Meaning |
|---|---|
| `--repo-dir DIR` | the repository to read (default: the current directory) |
| `--repo NAME` | put `NAME:` before each code path that names no repository, so `impact --repo` and `audit --repo` match it; letters, digits, `-` and `_` |
| `--adr-dir DIR` | read ADRs only from this directory, relative to `--repo-dir` (default: every one of `docs/adr`, `docs/decisions`, `adr`, `doc/adr` that exists) |
| `--postmortem-dir DIR` | read postmortems only from this directory, relative to `--repo-dir` (default: `docs/postmortems`) |
| `--github OWNER/REPO` | also read merged pull requests from this GitHub repository (below); without `--repo-dir`, read only them |
| `--label NAME` | with `--github`: the label that selects a pull request (default: `decision`, any case) |
| `--since DATE` | with `--github`: only pull requests merged on or after this date (UTC), such as `2026-01-31` |
| `--limit N` | with `--github`: read at most N closed pull requests, most recently updated first (default 100, 1 to 5,000) |
| `--out FILE` | where the snapshot goes; the command prints its counts and problems |

Every `.md` file directly in those directories is read, except `README.md`, `index.md` and names that
contain `template`. Every node carries `source_file` (the path from the repository root) and
`content_hash` (`sha256:` and the hex digest of the file it was read from). Ids come from the repository name and the file path, such as
`decision:shop-docs-adr-0003-retry-payment-calls-once`, so they stay the same while the file keeps its
path. Nodes, edges and problems are sorted and nothing depends on the clock, so two runs on the same tree
write the same bytes.

### ADRs become decisions

| Field | From front matter | Or, without it, from the Markdown |
|---|---|---|
| `title` | `title` | the first `# ` heading |
| `status` | `status` | a `Status:` line under the title (MADR 2), or the first line of the `## Status` section (Nygard); lower case |
| `date` | `date` | a `Date:` line under the title |
| `deciders` | `deciders` or `decision-makers` (a list, or names split at commas) | a `Deciders:` or `Decision-makers:` line under the title |
| `statement` | | the first paragraph of `## Decision` or `## Decision Outcome` |
| `code_ref`, `subject_path`, `also_touches` | the keys of the same name, a path or a list of paths from the repository root | none: code paths come only from front matter |
| `rule` | `rule`, an inline JSON object, kept as it is | |

An ADR without code paths is kept and listed under `kept without code paths`; `impact` reaches it only
through an edge. An ADR that replaces another gets a `SUPERSEDES` edge from the new one to the old one when
either says so: front matter `supersedes`, `superseded_by` or `superseded-by`, a front matter `status` such as
`superseded by [ADR-0002](0002-use-postgres.md)` or `superseded by ADR-0002` (MADR 3 and 4), or a `Supersedes ...` or
`Superseded by ...` line in `## Status` (the adr-tools form) or in a `Status:` line under the title (MADR 2). A status that is only
`Superseded by` reads as `superseded`. A reference may be a Markdown link to the file, the file name with or
without `.md`, or a number such as `3`, `0003` or `ADR-0003`, which matches the file whose name starts with
that number. A reference that matches no ADR or more than one makes no edge and is listed.

`impact` gives each listed decision its `status` when the snapshot has one. A decision whose `status` starts
with `superseded`, or that is the target of a `SUPERSEDES` edge, is not listed under `governing`: it goes
under `superseded`, with `superseded_by` (the decisions that replace it), so a path shows what governs it now
and, apart, what used to. `--format text` prints it after the governing nodes; Mermaid draws it dashed with
the `SUPERSEDES` edge, and HTML lists it in its own part. The `superseded` key is left out when it would be
empty, so a snapshot without superseded decisions gives the same output as before.

### CODEOWNERS owner sets become concepts

`init` reads the first of `.github/CODEOWNERS`, `CODEOWNERS` and `docs/CODEOWNERS` that is inside the
repository, as GitHub does, and lists the others as `not read`. It matches every line against the files in
`--repo-dir` the way GitHub does and gives each file the owners of the last line that matches it:

- a pattern with a `/` at the start or in the middle is anchored at the root; any other pattern matches at
  any depth (`apps/`, `*.js`);
- a trailing `/` matches a directory and everything below it;
- `*` and `?` match within one path segment; `**` matches any number of segments (`**/logs`, `docs/**`);
- a pattern whose last segment is a plain name also owns everything below a directory of that name
  (`/apps/github`); one whose last segment has a wildcard matches files only (`docs/*` owns `docs/a.md`
  but not `docs/b/c.md`);
- a line with a pattern and no owners leaves its files without an owner.

The files are what `git ls-files --cached --others --exclude-standard` lists when `--repo-dir` is in a git
work tree, and otherwise every file below it outside `.git`. A tree of more than 100,000 files is listed and
its owners are not read.

Each distinct set of owners becomes one concept. Its `code_ref` is the fewest paths that cover exactly the
files that set owns: a directory (with a trailing `/`) when every file below it has that owner set, otherwise
the single file. It also has `owners` (sorted), `source_lines` (the lines that own those files), and
`source_file` and `content_hash` of the CODEOWNERS file. Its id is `concept:<repo>-codeowners-`, the owners
as a slug, and the first 12 hex digits of the SHA-256 of the owners, so two owner sets never share an id.
Title: `Owned by` and the owners.

A line is listed and skipped when GitHub does not support its pattern (`!` negation, `[...]` ranges, `\`
escapes) or when an owner is not `@user`, `@org/team` or an email address. A line that matches no file, or
whose files are all owned by later lines, is listed under `no effect`. The concepts have no edges, so an
owner never carries a decision to the code it owns; `impact` lists them at hop 0 for the paths they cover.

### Postmortems become records

A postmortem gives a record with `title`, `date` and the three code path keys, read as for an ADR. It gets
an `ABOUT` edge to each decision it names: the `decisions` front matter key (a list of references as for
`supersedes`), an `ADR-<number>` in the text, or a Markdown link to an ADR file. A name in front matter or
text that matches no ADR is listed under `no edge`; a link to a file that is not an ADR is ignored.
`impact` follows the edge from the record to the decision, so a path that a decision names also lists the
postmortems about it.

### Merged pull requests become decisions

With `--github OWNER/REPO`, `init` lists the repository's closed pull requests through the GitHub REST API,
most recently updated first, and keeps each merged one that has the `--label` label or a `## Decision` or
`## Decision Outcome` section with text in its description. HTML comments are dropped first, so a template's
empty section selects nothing. It sends `GITHUB_TOKEN` when the variable is set; a public repository needs no
token, at GitHub's lower limit for anonymous requests.

| Field | From the pull request |
|---|---|
| `title` | its title |
| `statement` | the text of its `## Decision` or `## Decision Outcome` section, left out when it has none |
| `valid_from` | `merged_at`, as GitHub gives it (`2026-03-21T16:00:00Z`) |
| `deciders` | `@` and the author's login, then each reviewer whose last review is `APPROVED`, sorted |
| `code_ref` | each changed file from `/pulls/{n}/files`, with `--repo` before it as for ADRs |
| `source` | `https://github.com/OWNER/REPO/pull/{n}` |
| `content_hash` | `sha256:` and the hex digest of the number, title, description, merge time, merge commit, labels, author, files and reviews that were read |

Its id is `decision:github-<owner>-<repo>-<key>-pr-<number>`, where `<key>` is the first 8 hex digits of the
SHA-256 of `owner/repo` in lower case, so it stays the same across runs, never meets an ADR's id, and differs
between repositories whose names slug alike (`a-b/c` and `a/b-c`, `foo.bar` and `foo_bar`). No fetch time is stored, so the same answers from GitHub give the same bytes.

The listing follows GitHub's `Link` headers and stops at `--limit` closed pull requests, or at the first one
last updated before `--since`; a stop at the limit is listed as `not read` on `github:OWNER/REPO`. GitHub
lists at most 3,000 changed files of a pull request; a pull request at that cap is kept and listed. `init`
reads at most 1,000 reviews of a pull request; one with more is kept and listed as `not read`, since its
`deciders` can miss an approval. A changed file whose path has a colon (`C:/win`, `a:b/c.py`) is left out of
`code_ref` and listed as `skipped`, because a `code_ref` reads what comes before a colon as a repository. A rate
limit (HTTP 429, or 403 with `x-ratelimit-remaining: 0` or `retry-after`) stops the read: the pull requests
read before it stay in the snapshot, and the stop is listed as `not read` with GitHub's reset time. Any other
error answer, a broken or cut-off answer, an answer that is not JSON or is nested too deeply to read, and a
redirect or `Link` to another host stop the command with exit code 1 and write nothing.

### The front matter subset

Front matter is the block between a first line `---` and the next `---` or `...`. `init` reads a subset of
YAML and needs no YAML library:

- `key: value` at the start of a line, each key once; lines that start with `#` are comments;
- a value is plain text (a trailing ` # comment` is dropped), `'single quoted'` (`''` is a quote) or
  `"double quoted"` (JSON escapes);
- a list is `[a, b]`, a JSON array, or `- item` lines under a `key:` with no value;
- `rule` is one inline JSON object, such as `{"advisory_severity_at_least": "HIGH"}`.

Anything else is refused with the line number and the file is skipped: nested mappings, block text (`|`,
`>`), anchors and aliases (`&`, `*`), tags (`!`), nested lists, and text that holds `: ` without quotes.
Keys other than those above are ignored.

## The Relate graph of an audit

| Label | From | Key properties |
|---|---|---|
| `Concept`, `Decision`, `Record`, ... | the snapshot | `id`, `title`, `domain`, flattened `props` |
| `Repository` | the inventory | `id` = `repo:<name>`, `source_system` (see below), `source_ref`, `fetched_at`, `content_hash` of the inventory |
| `Package` | the inventory | `id` = `pkg:<purl type>/<name>@<version>`, `ecosystem`, `name`, `version`, `dev`, `licenses`, `license_expression`, `purl`, `unresolved`, `source_system`, `source_ref`, `fetched_at` |
| `Workspace` | a pnpm, Yarn or Bun lockfile | `id` = `workspace:<repo>:<path>`, `name` (empty for pnpm, which does not record it), `path`, `source_system`, `source_ref`, `fetched_at` |
| `Advisory` | OSV | `id` = `adv:<osv id>`, `osv_id`, `severity`, `aliases`, `published`, `affected_json`, `source_url`, `fetched_at`, `content_hash` of the OSV record |

| Edge | Meaning | `evidence` |
|---|---|---|
| snapshot edges | as in the snapshot | as in the snapshot |
| `DEPENDS_ON` | the repository, a workspace or a package requires a package or a workspace; the repository holds each workspace | the requirement as the inventory states it, with `(dev)`, `(optional)` or `(peer)` for those kinds; `workspace <path>` from the repository |
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
| `gradle.lockfile`, `settings-gradle.lockfile` | `gradle-lockfile` | the build | the repository to every locked `group:artifact:version`, with its configurations in the evidence | every configuration is a test one (`test...`, `...Test...`), compile-only (`compileOnly`, `compileClasspath`) or an annotation processor (`annotationProcessor`, `kapt`, `ksp`) |
| `pom.xml` | `maven-pom` | the project | the repository to every entry of `<dependencies>` (not profiles or plugins) | scope `test` or `provided` |
| `poetry.lock` 1.x or 2.x, with `pyproject.toml` when present | `poetry-lockfile` | the project in `pyproject.toml`; without it, packages that nothing in the lock requires | `[package.dependencies]`; from the repository, `tool.poetry` dependencies, dev-dependencies and groups, and `project` dependencies, optional dependencies and `dependency-groups` | `category` other than `main` (1.x), `groups` without `main` (2.1), or reached only through a non-main group in `pyproject.toml`; with none of these, false and noted |
| `requirements*.txt` | `pip-requirements` | the file and the files it includes with `-r` | the repository to each requirement line; no transitive edges | always false |
| `pnpm-lock.yaml` v6 or v9 | `pnpm-lockfile` | importer `.`; every other importer is a `Workspace` | importers' `dependencies`, `optionalDependencies` and `devDependencies` (`link:` goes to a workspace); each package's `dependencies` and `optionalDependencies` (v9: `snapshots`), a name in its `peerDependencies` marked peer | reached only through `devDependencies`; v6 `dev: true` |
| `yarn.lock` v1 | `yarn-lockfile` | the root `package.json`; each workspace `package.json` is a `Workspace` | the `package.json` fields, then each entry's `dependencies` and `optionalDependencies` by `name@range`; v1 does not record peers | reached only through `devDependencies` |
| `yarn.lock` Berry | `yarn-berry-lockfile` | the `workspace:.` entry; every other `workspace:` entry is a `Workspace` | each entry's `dependencies` by descriptor, `dependenciesMeta` optional, `peerDependencies` to the locked package of that name | a workspace dependency listed only under `devDependencies` of its `package.json` |
| `bun.lock` | `bun-lockfile` | workspace `""`; every other workspace is a `Workspace` | workspaces' four dependency fields, and each package's `dependencies`, `optionalDependencies` and `peerDependencies`, resolved through nested keys such as `debug/ms` | reached only through `devDependencies` |

Package props:

- `ecosystem` is the OSV ecosystem (`npm`, `PyPI`, `crates.io`, `Go`, `Maven`; from an SBOM purl also
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
- `dev` is true when the package is reached only through development dependencies. Workspaces have no
  `dev`; the repository always holds them. When an SBOM lists
  one package id more than once, one production instance makes it shipped; it is development only when
  every instance is marked development and nothing shipped reaches it.

A requirements line that is not a `name==version` pin gets the id `pkg:pypi/<name>@` with an empty
`version` and an `unresolved` that names the file, the line and what it gives; a direct URL or path
without a name gets `pkg:unknown/<target>@`. A ranged line for a name that another line pins links to
that pin instead. `-r` includes are read through the sibling reader (below). A Poetry package from a
`directory`, `file`, `url` or `git` source is unresolved.

An SBOM component without a purl gets the id `pkg:unknown/<name>@<version>`, ecosystem `""` and
`unresolved` `the inventory gives no purl`, with its CPE when it has one. An SBOM package that nothing
depends on is linked from the repository with the evidence `listed in the SBOM with no dependency on it`.
`audit` refuses an inventory that lists no packages, or none that can be queried at OSV, instead of
reporting it clean.

The `Repository` node has `inventory_notes`, a list of strings, when the reader saw a gap in what the
inventory covers: a requirements file lists direct dependencies only, an include was not followed, a
local project or constraints file was not read, or a `poetry.lock` does not say which packages are
development ones.

A reader gets the files it needs next to the inventory as `siblings`. `inventory.load(path, root=None)`
reads the fixed names a reader lists (`go.sum`, `pyproject.toml`) and keeps a reader function for other
files, such as `-r` includes, and a resolve function that names the real file. Both take a path relative
to the inventory's directory. They refuse absolute paths and any path, symbolic links included, that
resolves outside the root: `root`, or else the nearest directory above the inventory that holds a `.git`
entry (found without running git), or else the inventory's directory. The CLI sets it with `--root`. The
reader returns nothing when the file does not exist. Includes are keyed by the resolved file, so a loop
through a symbolic link ends, and they are followed 64 levels deep. A leading UTF-8 byte order mark is
dropped from the inventory and every file read beside it. A caller can pass its own functions, as the
MCP server does with its `--root` check: `inventory.gather(text, filename, reader, resolve)`.

For Go, `audit` is given `go.mod` and reads `go.sum` from the same directory. It stops when there is no
`go.sum`, or when a required module version has no line in it. A `replace` to a local path drops the
module; a `replace` to another module uses that module and version. Modules that appear only in `go.sum`
are not read: from Go 1.17, `go.mod` lists every module in the build.

A Gradle lockfile lists `group:artifact:version=configurations` lines; `empty=` lines and comments are
skipped, and any other line stops the run. It does not say which dependency brings in which, so every
package hangs off the repository.

A `pom.xml` is refused when it holds a DOCTYPE or an entity declaration, before it is parsed. A version
is read when it is a literal or uses properties defined in the same file (`<properties>`, `project.version`,
`project.groupId`, `project.parent.version` and the like, also nested), or when the file's own
`<dependencyManagement>` gives it. Otherwise the package keeps its `group:artifact` name, gets version
`""` and an `unresolved` reason: no version (with the parent and imported BOMs it would come from), a
property the file does not define, properties that refer to each other in a loop or expand past 256
characters, a version range, or
`LATEST`/`RELEASE`. Transitive dependencies are not read.

Both JVM readers give the same id and purl as a CycloneDX Maven component (`pkg:maven/<group>:<artifact>@<version>`,
purl `pkg:maven/<group>/<artifact>@<version>`), and the report of either carries a `notes` entry saying that
transitive dependencies are not resolved and pointing to `cyclonedx-gradle-plugin` or
`cyclonedx-maven-plugin` for the full graph.

Readers live in `src/decisis/inventory/`. Each one has `FORMAT`, `SIBLINGS` (files read from the same
directory), `detect(text, filename)` and `read(text, filename, repo, siblings=None)` returning
`(nodes, edges)`; `inventory.read` picks the first reader whose `detect` matches. A reader may also have
`sibling_names(read, resolve)`, which names the files to read in place of `SIBLINGS`: the Yarn reader
returns the root `package.json` and the `package.json` of each directory its `workspaces` globs match
(outside `node_modules`). `inventory.gather` reads them with the same bounded reader as every other
sibling, so the CLI reads them only under the repository root and `serve --mcp` only under its `--root`;
a match that leads outside is skipped. Every inventory is read as strict UTF-8 with a leading BOM
removed; a file that is not UTF-8 is refused. A binary `bun.lockb`, told by its name or its
`bun-lockfile-format` header, is refused with the command that writes `bun.lock`, by the CLI and by
`serve --mcp` before either reads it as text.

The pnpm, Yarn and Bun readers give each package the npm ecosystem and the id the npm reader gives the
same name and version, `pkg:npm/<name>@<version>`. An npm alias (`foo@npm:minimist@1.2.5`) gets the id of
the package it names. A version that is not a registry version (a git,
tarball, file or link source) keeps its node and is `unresolved`. pnpm and Yarn Berry lockfiles are read
through `decisis.yamltext` with PyYAML's `BaseLoader`, which builds only mappings, lists and strings, so no
value turns into a boolean, number or object. Before anything is built, the event stream is scanned: a
lockfile larger than 64 MiB, nested deeper than 64 levels, or with any YAML anchor or alias is refused, so
an alias bomb never expands. `yamltext.load(..., aliases=True)` allows aliases for other YAML (such as
GitHub workflows) up to 100,000 expanded nodes.

## Versions

A finding is `affected` when the version is listed in the advisory, or falls in one of its `SEMVER` or
`ECOSYSTEM` ranges. Range events are sorted by version before they are read. `SEMVER` ranges and the
`ECOSYSTEM` ranges of npm, crates.io and Go are ordered as semantic versions (a leading `v` and build
metadata are ignored; Go pseudo-versions order as pre-releases). PyPI `ECOSYSTEM` ranges are ordered by
PEP 440 (epoch, release, pre, post, dev and local segments). Maven `ECOSYSTEM` ranges are ordered like
Maven's `ComparableVersion`: the version is split into number and qualifier tokens at `.`, `-` and
digit-letter changes, trailing zeros and empty qualifiers are dropped, and qualifiers order as
`alpha` (`a1`) < `beta` (`b1`) < `milestone` (`m1`) < `rc` = `cr` < `snapshot` < release (`""`, `ga`,
`final`, `release`) < `sp` < any other word, alphabetically. A qualifier sorts below a number and `-1`
below `.1`, so `2.0.a` < `2-1` < `2.0.1` < `2.1`; a missing position counts as `0` or as the release
qualifier. A version at or above a range's `limit` is
not affected. A version that cannot be ordered, or an `ECOSYSTEM` range of another ecosystem, gives
`unresolved`, never `affected`.

## The OSV cache

`--osv-cache` reads a JSON object with `fetched_at` (when the advisories were read), `queries` (a
package id such as `pkg:npm/lodash@4.17.15` to the list of advisory ids OSV returned for it) and `vulns`
(an advisory id to the OSV record as `api.osv.dev/v1/vulns/<id>` returns it). A package or advisory the
file does not hold stops the run. The keys follow the package ids, so a cache works for every ecosystem.
`fixtures/audit/osv-cache.json` covers the demo lockfile, `fixtures/inventory/osv-cache.json` covers
the examples in `fixtures/inventory/`, and `fixtures/inventory/jvm/osv-cache.json` the Gradle and Maven
examples next to it.

## The report and the plan

`audit --out report.json` writes `meta`, `loaded` (node and edge counts), `governing` (decisions and the
node they reach the repository through), `summary` (counts by status), `violations`, and `findings`. A
finding has `package`, `advisory`, `severity`, `status` (`affected`, `not_affected`, `unresolved`),
`dev_only`, `path` (ids from `repo:<name>` to the advisory), `source_url`, `fetched_at`, `content_hash`,
`advisory_summary` and `policies` (one `decision`, `verdict` and `why` per governing decision).
`unresolved_packages` lists each package that was not queried (`package`, `reason`), and
`inventory_notes` lists sentences on what the inventory does not cover, from the reader (an include not followed,
a dev split that is unknown) or from its format (the Gradle and Maven readers do not resolve transitive
dependencies); it is empty when there are none.

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
