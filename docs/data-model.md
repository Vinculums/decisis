# Data model

## The snapshot

Every command that reasons (`paths`, `impact`, `check`, `audit`, `query`, `propose`, and the tools of
`serve --mcp`) reads a snapshot: one JSON file with the slice
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
  `Repo:path:symbol`. `audit --repo Shop` links the repository to every node whose `code_ref` is a string
  that is `Shop` or starts with `Shop:`; `impact` matches the path part. Decisions may also name code with `subject_path`
  and `also_touches`. A snapshot from `init` needs no such link: see [Which decisions an audit judges](#which-decisions-an-audit-judges).
- `rule` on a decision: what the decision forbids, in the format below. A decision without a `rule` is
  reported as `relevant`, never `violated`.

### Rules

A `rule` is a mapping, a list of mappings, or a JSON string of either. Each mapping names one or more rule
kinds and may add the modifier `dependencies`:

| Kind | Value | Judges | Violated when |
|---|---|---|---|
| `advisory_severity_at_least` | `LOW`, `MODERATE`, `MEDIUM`, `HIGH` or `CRITICAL` | each package and advisory pair | the package is `affected` and the advisory's severity is at or above the value |
| `license_denied` | a list of SPDX license ids | each package | the package's license expression cannot be met without a listed license |
| `license_allowed` | a list of SPDX license ids | each package | the package's license expression cannot be met with listed licenses only |
| `package_denied` | a list of `{"ecosystem", "name", "versions"}` (`versions` optional) | each package | the package has that ecosystem and name, and, when `versions` is given, one of those versions |
| `package_allowed` | a list of `{"ecosystem", "name"}` | each package of an ecosystem the list names | the package's name is not in the list for its ecosystem |
| `pinned_to_commit` | `true` | each `GitHub Actions` package | the ref is not a full 40-character lowercase commit SHA (a tag or a branch) |
| `review_required` | `{"paths": [globs], "reviewers": [handles]}` | each changed file (`check`) | a `paths` glob covers the file and none of `reviewers` is among the reviewers given |
| `imports_forbidden` | `{"from": [globs], "to": [globs]}` | each import of a changed file (`check`) | a `from` glob covers the file and the import resolves to a file a `to` glob covers |

`dependencies` is `shipped` or `all` (the default). With `shipped`, a package reached only through
development dependencies is `not_violated` for that rule. Examples:

```json
{"advisory_severity_at_least": "HIGH", "dependencies": "shipped"}
[{"license_denied": ["GPL-3.0-only", "AGPL-3.0-only"], "dependencies": "shipped"},
 {"package_denied": [{"ecosystem": "npm", "name": "event-stream", "versions": ["3.3.6"]},
                     {"ecosystem": "PyPI", "name": "pycrypto"}]}]
[{"pinned_to_commit": true},
 {"package_allowed": [{"ecosystem": "GitHub Actions", "name": "actions/checkout"},
                      {"ecosystem": "Terraform", "name": "hashicorp/aws"}]}]
```

License expressions are read as SPDX expressions with `AND`, `OR`, `WITH` and parentheses; operators are
read without regard to case, and ids are compared without regard to case. An `OR` expression passes when
any branch passes, an `AND` expression when every part passes, and `X WITH exception` is judged as `X`. Ids
are compared as written: `GPL-2.0+` and `GPL-2.0-or-later` are different ids. When the inventory gives no
expression but a list of ids, the ids are read as joined by `AND`. A package whose license is empty,
`NOASSERTION`, `NONE` or not an SPDX expression (such as `SEE LICENSE IN LICENSE.md`) is `unresolved`
for both license kinds, never `violated`.

`audit` judges the first four kinds and `check` the last two; each command ignores the other's kinds.

Globs in `review_required` and `imports_forbidden` follow the CODEOWNERS rules, matched against the path
relative to the repository root: a leading or middle `/` anchors the glob at the root, otherwise it
matches at any depth; a trailing `/` matches a directory and everything below it; `*` and `?` stay within
one path segment and `**` spans segments. A glob whose last segment is literal also covers everything
below a directory of that name, and one whose last segment has a wildcard matches files only. So
`src/payments/**` covers every file below `src/payments/`, `src/payments` covers the same files, and
`*.sql` covers every SQL file. `!`, `\`, `[` and `]` are refused as a rule problem.

A reviewer handle matches without regard to case and with or without a leading `@` (`@Alice`, `alice`).
A team handle, `@org/team`, matches only when written exactly the same. One listed reviewer is enough.

`imports_forbidden` reads Python files (`.py`, `.pyi`) with `ast`; JavaScript and TypeScript files
(`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`) with a scanner that skips comments,
strings, template literals, regular expressions and JSX text (JSX is read in every file but `.ts`, `.mts`
and `.cts`, where `<` starts a type); and Go (`.go`) and Rust (`.rs`) files with scanners that skip
comments, strings and character literals (Go raw strings and runes; Rust raw strings such as `r#"..."#`,
byte and C strings, nested block comments, and lifetimes told apart from character literals). It reads
`import`, `from ... import`, and `importlib.import_module` or `__import__` with a literal name in Python;
`import ... from`, `import "x"`, `export ... from`, and `require` or `import()` with a literal specifier in
JavaScript and TypeScript; single `import "path"` lines and grouped `import ( ... )` blocks, with an alias,
a dot or a blank name, in Go; and `use` declarations (with `{...}` groups, `self`, `*` and `as` expanded
into one path each), `mod x;` declarations and `extern crate x;` in Rust.

A Python module resolves to a file under the root of the importing file's package (the first directory
above it without an `__init__.py`), the nearest directory above the file with a `pyproject.toml`,
`setup.py` or `setup.cfg` and its `src/`, the repository root or `src/`; a relative import resolves from the
file's own package. A module found under none of them is external, unless its first name is a package or
module somewhere else in the repository and not a standard library module: then it is `unresolved`.

A relative JavaScript specifier resolves to the file, the file with a usual extension, the `.ts` file of a
`.js` specifier, or an `index` file. Other specifiers go through `paths` and `baseUrl` of the nearest
`tsconfig.json` or `jsconfig.json` above the file, with its `extends` chain followed through relative
paths inside the repository (at most 16 deep). `baseUrl` is read relative to the config that sets it, and
`paths` relative to `baseUrl`, or to their own config when there is no `baseUrl`. A specifier that
matches a `paths` pattern but names no file is `unresolved`. Any other specifier is an external package:
not a violation, unless a `to` glob that names `node_modules` covers `node_modules/<specifier>`.

A Go import path resolves against the nearest `go.mod` above the file. A path equal to or under its
`module` path names the package directory below that `go.mod` (`example.com/shop/svc/internal/db` with
`module example.com/shop/svc` in `svc/go.mod` is `svc/internal/db`), given as `target` with a trailing `/`.
It matches a `to` glob when the directory, with or without the `/`, or a `.go` file directly in it
matches, so `svc/internal/db/**` and `svc/internal/db/*.go` both cover it. Any other path (the standard
library, another module, a `replace` target) is external and never a violation. With no `go.mod` above the
file, a path whose first element has no `.` is the standard library and external, and any other path is
`unresolved`.

A Rust path is read inside the crate of the nearest `Cargo.toml` above the file that has a `[package]`.
The crate root is `src/lib.rs` (or the `[lib]` `path`) for files under its directory, `src/main.rs`
for files under `src/` in a crate without a library, a target a `[[bin]]`, `[[test]]`, `[[example]]` or
`[[bench]]` `path` declares, and, unless the matching `auto*` flag is `false`, a file directly in `src/bin/`,
`tests/`, `examples/` or `benches/` or the `main.rs` of its subdirectory. The crate's modules are the tree
of `mod` declarations followed from that root: `mod x;` names `x.rs` or `x/mod.rs` in the module's
directory, a `#[path = "..."]` or `#[cfg_attr(..., path = "...")]` attribute names a file read from the
declaring file's directory (or the inline module's directory), and `mod x { ... }` is an inline module.
A name can have several meanings when they are gated by `cfg`: `cfg_attr` paths that name more than one
existing file, two `mod` declarations of the same name, or two `use` bindings of the same name. The path is
followed through every one of them, also through a name bound to such a module or a glob `use` of it, and
every file it reaches is matched against the `to` globs. `mod` declarations and items inside an item-level macro
call (`cfg_if! { ... }`, `wrapper! { ... }`) are read; the body of a `macro_rules!` definition is not. The
importing file's own module is found in that tree, by its place under the root or else by walking the
tree.

A path that starts with `crate::` is read from the crate root, `self::` from the current module, and each
`super::` one module up. Any other first name is looked up in the current module, then taken as a crate of
the repository, then as external; `std`, `core` and `alloc` are always external. Each name of the path is looked up in turn in the module reached so far,
as a child module, as an item the module declares (`struct`, `enum`, `trait`, `type`, `fn`, `const`,
`static`, `union` or `macro_rules!`), as a name it binds with `use`, `pub use` or `extern crate` (followed to
what it binds, also through a `use` inside a function), or as a name a `use ...::*` in it brings in. A
child module moves on to that module. An item ends the path at the file that declares it, so
`crate::db::models::Order` is `src/db/models.rs` and `crate::Error` is `src/lib.rs` when `lib.rs`
declares or re-exports `Error`. A name found none of those ways is `unresolved`, never the root file: a
module that does not exist, an item a macro generates, and a module whose file leads outside the
repository are not judged. A module file `a/b.rs` found as `mod b;` also matches a `to` glob that covers
its directory `a/b/`, so the verdict does not depend on which of the two layouts the crate uses.

A crate of the repository is named by its `[package]` `name` or `[lib]` `name` (with `-` read as `_`), or
by the name the current crate gives a dependency: with `path`, with `package = "..."` naming a crate of the
repository, or with `workspace = true` and the entry of that name in the nearest `[workspace.dependencies]`
above; target-specific dependency tables count too. A path into such a crate, with or without a leading
`::`, is read from its library root the same way. Any other path (`std`, a crate from a registry) is
external and never a violation.

A plain text search for the same import forms runs over each JavaScript, TypeScript and Go file, and over
each Rust file for `use` paths that start with `crate`, `self`, `super`, the name of a crate in the
repository or a name the file binds, and for `mod x;`. A specifier it finds that the scanner did not read as code (in a comment or a
string, or after a point the scanner misread) is `unresolved` with the reason "the scanner and the text
search disagree" and the file it would name as `target`; it is `not_violated` only when that target is
known and no `to` glob covers it. A Go or Rust hit that would be external is not listed, since read as an
import it could not be a violation.

`unresolved` is also given to an import whose specifier is computed at run time, a relative import that
names no file, a file that cannot be parsed or scanned to its end (an unclosed string, template literal,
comment, regular expression, JSX element, raw string or character literal), a config that cannot be read,
extends a package or extends itself, and a file that leads outside the repository through a symbolic link.
In Go it is given to a path under the module path with no directory in the repository, a path with `.`,
`..` or an empty element, a path with an escape sequence, and a `go.mod` whose `module` directive is
missing or cannot be read (both the one-line and the `module ( ... )` block form are read). Go packages
under `vendor/`, and modules a `replace` directive or `go.work` places inside the repository, are external
like any other path outside the module, so no `to` glob can name them. In Rust it is given to a `crate::`,
`self::` or `super::` path or a `mod` declaration in a file with no `Cargo.toml` above it or whose nearest
`Cargo.toml` has no `[package]` or cannot be read, a path with a name found no way above, a crate with no
root file the scanner finds, a `super::` above the crate root or from a file the tree does not reach, a
`mod x;` with no file, one whose file leads outside the repository, a path that one of several `cfg_attr`
files of a module cannot resolve, a repository crate with no library root, and a
`use` declaration that cannot be read (such as `use $x;` in a macro). No code of the repository is run.

`package_denied` compares the ecosystem without regard to case and the name as OSV does (PyPI names are
normalized). `versions` is a list of exact versions, as in an OSV record's `versions` field, not ranges. A
version matches when it is the same string, or when it orders equal under the package's ecosystem (`v1.0.0`
and `1.0.0` for npm, `6.0` and `6.0.0` for PyPI). Without `versions` every version is denied.

`package_allowed` is an allowlist per ecosystem: a package of an ecosystem the list does not name is
`not_violated`, so one rule can allow a set of GitHub actions without judging npm packages. Names are
compared as for `package_denied`; GitHub Actions names are compared without regard to case, and a Terraform
provider name without a host (`hashicorp/aws`) means `registry.terraform.io/hashicorp/aws`.
`pinned_to_commit` judges only `GitHub Actions` packages. A workflow `uses:` that names no action keeps the
`GitHub Actions` ecosystem with an empty version, and the two kinds judge it by what it is: a local `./`
action is `not_violated` by both (it is in the repository and read at the workflow's commit); a
`docker://` image is `unresolved` under both (a digest pin is not checked, and an allowlist names actions);
a `uses:` built from an expression, or one that is not a name, is `unresolved` under both, never
`not_violated`.

A rule that cannot be read is never dropped: an unknown kind, a value of the wrong shape, a `dependencies`
other than `shipped` or `all`, an empty list, or a string that is not JSON gives a policy with verdict
`relevant` and the reason in `why`, on every finding the decision governs, and an entry in the report's
`rule_problems`. Other entries of the same rule are still judged. Kinds are entries of the table `KINDS` in
`src/decisis/rules.py`: each names the findings it judges (`advisory`, `license`, `package` for
`package_denied`, `allowlist` for `package_allowed`, `pin` for `pinned_to_commit`, and `review` or `import` for the
`check` kinds), how its value is read,
and how one package, file or import is judged. A finding's `kind` is that subject, and `propose` turns an `affected`
`package`, `allowlist` or `pin` finding into a record with the predicate `uses_denied_package`,
`uses_unlisted_package` or `not_pinned_to_commit` and the value `<ecosystem>:<name>`, which the checker
judges again against the decision's rules.

### Waivers

A decision's `props` may carry `waivers`: a list (or a JSON string of one) of exceptions to its own rules. A
waiver records a violation the team accepts for a while, such as an advisory with no patched release yet.
Each waiver is a mapping with these keys:

| Key | Value |
|---|---|
| `reason` | why the violation is accepted, one line of text (required) |
| `expires` | the last day the waiver holds, a date `YYYY-MM-DD` (required) |
| `approved_by` | who accepted it, one line of text such as `@org/security` (required) |
| `package` | for `audit`: `{"ecosystem", "name", "versions"}`, `versions` optional |
| `advisory` | for `audit`, with `package`: one OSV id, such as `GHSA-p6mc-m468-83gw`, without `adv:` |
| `path` | for `check`: one path glob |
| `to` | for `check`, with `path`: one path glob that names the forbidden import target |
| `rule` | optional: the one rule kind the waiver covers |

A waiver names `package` or `path`, never both. It covers a `violated` result of the decision that holds it,
and of no other decision, when every part it names matches:

- `package` matches the finding's package as `package_denied` matches it: ecosystem without regard to case,
  the name as OSV compares it, and, when `versions` is given, one of those exact versions (or one that orders
  equal). Without `versions` it covers every version of that one package. Without `advisory` and `rule` it
  covers every `audit` kind of the decision on that package.
- `advisory` narrows a package waiver to `advisory_severity_at_least` findings of that one advisory, compared
  as written.
- `path` matches the changed file with the same globs and rules as `review_required` and `imports_forbidden`
  (see above). Without `to` and `rule` it covers both `check` kinds on the files it matches.
- `to` narrows a path waiver to `imports_forbidden` results, and covers one only when the glob names every
  file the rule forbids that import through. A Rust module file `a/b.rs` and its directory `a/b/` count as one
  module, and a Go package directory and its `.go` files as one package, so the glob may name either; a Rust
  path that reaches several `cfg` files is covered only when the glob names each of them. For an external
  package the glob is matched against `node_modules/<specifier>`.
- `rule` names one kind: an `audit` kind for a package waiver (`advisory_severity_at_least` only with
  `advisory`), a `check` kind for a path waiver (`imports_forbidden` only with `to`).

A covered violation judged on or before its `expires` date gets the verdict `waived`, with the rule's `why`
and `waiver`: the waiver's position in the list (`waiver`, from 1), `reason`, `expires` and `approved_by`.
When several waivers cover it, the one that lasts longest is shown. From the day after `expires` it is
`violated` again, its `why` ends with which waiver expired and when, and it carries `expired_waiver` with the
same keys. `unresolved` and `not_violated` results are never waived. "Today" is the UTC date, or the date
`--today YYYY-MM-DD` gives (`audit`, `check`, the MCP `today` argument and the Action's `today` input), and
the reports name it as `today`. The demo judges waivers on the date its OSV cache was fetched and the
benchmark on a fixed date, so neither changes from day to day.

`waived` is never a violation: it is not counted in `violations`, in the `check` exit code, in the Action's
`violations` output or for `fail-on-violation`.

A waiver with a missing, unknown or unreadable key, a date that is not a real `YYYY-MM-DD` date, both or
neither of `package` and `path`, `to` with a package, `advisory` with a path, a glob the rules refuse, or a
`rule` the waiver cannot cover waives nothing and is listed under `rule_problems` with `rule` set to
`waivers` and the reason. Other waivers of the same decision still hold. Example:

```json
[{"package": {"ecosystem": "npm", "name": "lodash", "versions": ["4.17.15"]}, "advisory": "GHSA-p6mc-m468-83gw",
  "reason": "no patched release we can take before the migration", "expires": "2026-12-31", "approved_by": "@shop/security"},
 {"path": "src/legacy/**", "rule": "review_required",
  "reason": "frozen code, removed in Q1", "expires": "2027-01-31", "approved_by": "@shop/leads"}]
```

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
read or parse is listed in `meta.problems` with the reason and left out. The one reader of prose is
`--suggest-refs` (below), which marks every code path it adds as suggested and keeps the sentence it came from. Each entry has `file`, `reason` and
`action`: `skipped` (the file or line is not in the snapshot), `kept without code paths` (the node is there
but no code path anchors it), `no edge` (a reference did not resolve to exactly one ADR), `no effect` (a
CODEOWNERS line that owns no file), `not suggested` (a path an ADR names that `--suggest-refs` left out), `ignored`
(a front matter key `init` does not read, or an entry in an ADR directory that is not a record file; both below) or
`not read`.
An entry about an ADR file also has `kind: "decision"`. An ADR whose entry is `skipped` or `not read`, such as one
whose `rule:` or `waivers:` line holds JSON that does not parse, is not in the snapshot, so neither is its rule;
`check` and `audit` list each such file under `unread_decisions` so it does not drop out silently. A front matter key
close to `rule` or `waivers`, such as `rules:` or `waiver:`, is also `not read`: the decision is in the snapshot,
but what that key holds is not judged, so the file is listed under `unread_decisions` as well (see
[The front matter subset](#the-front-matter-subset)). A snapshot
written before `kind` existed has no `kind` on any entry; there an `.md` file directly in `docs/adr`,
`docs/decisions`, `adr` or `doc/adr` counts as an ADR file, and an ADR read from another `--adr-dir` is not
listed.
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
| `--suggest-refs` | give each ADR that states no code path the existing files and directories its text names (below) |
| `--out FILE` | where the snapshot goes; the command prints its counts and problems |

Every `.md` file directly in those directories is read, except `README.md`, `index.md` and names that
contain `template`. What else lies in an ADR directory is listed by one rule, which `init` applies to the
working tree and the Action applies to the base commit's tree (`Survey` in `src/decisis/init.py`), so both list
the same entries with the same reasons:

| Entry | Listed as |
|---|---|
| a regular `.md` record file in a folder below the ADR directory (`docs/adr/archive/0007-old.md`) | `ignored`: ADRs in subfolders are not read; move it up or pass its folder with `--adr-dir` |
| a symbolic link with a record name, directly in the ADR directory | `skipped`: decisions are read only from regular files |
| a symbolic link with a record name in a folder below it | `ignored`, as a file in a subfolder |
| an ADR directory that is itself a symbolic link or a git submodule | `not read`: none of its ADRs are read, so it is listed under `unread_decisions` and counts for `--fail-on-unresolved` |
| any other symbolic link at any depth (`docs/adr/v1.2`, `docs/adr/LICENSE`) | `ignored`: it is not followed |
| a git submodule inside an ADR directory | `ignored`: decisis does not read ADRs from it |

Folders and links whose name contains `template`, and everything below such a folder, are left out without an
entry. `ignored` entries carry `kind: "decision"` and stay in `meta.problems`, but they are not listed under
`unread_decisions`, so an `archive/` folder never fails `--fail-on-unresolved`. A link directly in the ADR
directory with a record name is `skipped`, so it does show there. git does not record what a symbolic link points at
as a file or a folder, so neither reader follows any link or guesses which kind it is. In a working tree, a folder that
holds its own `.git` counts as a submodule. A submodule that was never checked out is an empty folder there and is
not listed, but the Action lists it from the base commit.

ADRs in subfolders are listed and not read because reading them would change how existing repositories are
judged. Take `docs/adr/archive/0007-old.md` next to `docs/adr/0007-new.md`: a reference such as
`supersedes: ["#7"]` would match two ADRs and make no edge, so a superseded decision would be judged again. And
`docs/adr/api/v2.md` would take the id `decision:shop-docs-adr-api-v2` from `docs/adr/api_v2.md`, so the waivers
and records that name that id would point at other content. Ids and `SUPERSEDES` edges stay what they are when
only the files directly in an ADR directory are read. To read a folder of ADRs, name it with `--adr-dir`.

The listing is bounded in both readers, which walk the entries in git's order and stop at the same one. Below each ADR
directory, at most 100,000 files, links and submodules outside `template` folders are looked at, and at most 20
are listed. Past either bound, one more `ignored` entry on the ADR directory says where the listing stopped.
More than 5,000 ADR record files directly in the ADR directories, or more than 5,000 postmortem record files,
stops the command with an error, and the Action reading the base commit stops at the same count. Postmortems are
read only from the files directly in their directory. Every node carries `source_file` (the path from the repository root) and
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
| `code_ref`, `subject_path`, `also_touches` | the keys of the same name, a path or a list of paths from the repository root | none, unless `--suggest-refs` is given: then `code_ref` lists the paths the text names (below) |
| `rule` | `rule`, an inline JSON object, kept as it is | |
| `waivers` | `waivers`, an inline JSON list of objects, kept as it is and read as described in [Waivers](#waivers) | |

The `Status:`, `Date:`, `Deciders:` and `Decision-makers:` lines under the title may stand alone or be list items
(`- ` or `* `), and the key may be bold with the colon inside or outside the bold: `- **Status:** accepted`,
`* **Status**: accepted` and `**Status:** accepted` read like `Status: accepted`. They are read only between the
title and the first `## ` heading.

An ADR without code paths is kept and listed under `kept without code paths`; `impact` reaches it only
through an edge. An ADR that replaces another gets a `SUPERSEDES` edge from the new one to the old one when
either says so: front matter `supersedes`, `superseded_by` or `superseded-by`, a front matter `status` such as
`superseded by [ADR-0002](0002-use-postgres.md)` or `superseded by ADR-0002` (MADR 3 and 4), or a `Supersedes ...` or
`Superseded by ...` line in `## Status` (the adr-tools form) or in a `Status:` line under the title (MADR 2). A status that is only
`Superseded by` reads as `superseded`. `Superceded` and `Supercedes`, in any case, read as `superseded` and
`supersedes`. A reference may be a Markdown link to the file, the file name with or without `.md`, or a number
such as `3`, `0003` or `ADR-0003`, which matches the file whose name starts with
that number. A reference that matches no ADR or more than one makes no edge and is listed.

`impact` gives each listed decision its `status` when the snapshot has one. A decision whose `status` starts
with `superseded`, or that is the target of a `SUPERSEDES` edge, is not listed under `governing`: it goes
under `superseded`, with `superseded_by` (the decisions that replace it), so a path shows what governs it now
and, apart, what used to. `--format text` prints it after the governing nodes; Mermaid draws it dashed with
the `SUPERSEDES` edge, and HTML lists it in its own part. The `superseded` key is left out when it would be
empty, so a snapshot without superseded decisions gives the same output as before.

### Suggested code refs: `--suggest-refs`

Real ADRs rarely carry `code_ref`, so with `--suggest-refs` `init` reads the text of each ADR that states no
`code_ref`, `subject_path` or `also_touches` and suggests the files and directories it names. A code path the
ADR states itself is never changed, and nothing is suggested for postmortems or pull requests.

- A candidate is a backticked token, a word with a `/` or a file extension (`config/payments.toml`,
  `retry.py`), or the target of a Markdown link: relative to the ADR file, from the repository root when it
  starts with `/`, or the path in a `github.com/OWNER/REPO/blob/...` or `/tree/...` URL. Image links, other
  URLs and paths that leave the repository are not candidates. In a fenced code block only words with a `/`
  count, so a directory listing or a command does not suggest every file name in it. `./`, a leading or
  trailing `/`, a `#anchor` and a `:line` suffix are dropped; a glob such as `pkg/**/*.go` or
  `src/auth/{login,logout}` names the directory before its first wildcard.
- A candidate matches the file or directory with that path from the repository root. When there is none, a
  candidate with a `/` or an extension also matches every path that ends with it (`handler.py`,
  `v7/push`); a bare backticked word (`command`) matches only at the root.
- The paths searched are what `git ls-files --cached --others --exclude-standard` lists in a git work tree,
  and otherwise every file below `--repo-dir` except what the root `.gitignore` lists (a negated `!` line is
  listed as `not read` and not applied), with the directories above them. Anything under `.git`,
  `node_modules` or `vendor` is skipped in both cases. A tree of more than 100,000 files is listed as `not
  read` and nothing is suggested.
- Paths in the ADR's own directory (other ADRs, their images) are records, not code, and are not suggested.
- A candidate that matches more than 5 paths, or that is only a bare common name (`src`, `test`, `README`,
  `docs`, `lib`, `main`, in any case), is not suggested. It is listed under `not suggested` with the number
  of paths it matched, and `init` prints it with the other problems.

The decision gets each suggested path in `code_ref` (sorted, with `--repo` before it and a trailing `/` on a
directory), `code_ref_source` set to `suggested`, and `code_ref_evidence`: one `{"code_ref": ..., "sentence": ...}`
per path, the first sentence of the ADR that named it. An ADR with suggested paths is not listed under
`kept without code paths`. On the five held-out repositories the suggestions match the hand mapping with
precision 0.622 and recall 0.778 (`bench/holdout/suggest-refs.md`), but the matching rules above were chosen
while looking at those repositories, so the score is in-sample and says nothing yet about other repositories.
Review the suggestions before relying on them.

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
- `rule` is one inline JSON object, such as `{"advisory_severity_at_least": "HIGH"}`. The value is kept as it is and read as described in [Rules](#rules).
- `waivers` is one inline JSON list of objects on one line. The value is kept as it is; a waiver that cannot be
  read is a rule problem of the decision, as described in [Waivers](#waivers).

Anything else is refused with the line number and the file is skipped: nested mappings, block text (`|`,
`>`), anchors and aliases (`&`, `*`), tags (`!`), nested lists, and text that holds `: ` without quotes.

The keys an ADR's front matter may hold are those in the table above, `decisions`, and MADR's `consulted` and
`informed`, which are read and not used. Keys are compared as written, so `Rule:` is not `rule:`. Each other key
of an ADR is listed in `meta.problems` with `key` (the key as written) and `may_mean` (the known keys whose
spelling is close to it, compared in lower case, at most three, possibly none), and the reason names both. The
entry is `not read` when `may_mean` holds `rule` or `waivers`, so a rule or waiver under a misspelled key, such
as `rules:` or `waiver:`, shows under `unread_decisions` in `check` and `audit`; any other key is `ignored`.
Words that front matter often holds for other tools are never matched to `rule` or `waivers`, so `role:` is
`ignored` and fails no check (`COMMON_KEYS` in `src/decisis/init.py`: `role`, `roles`, `tags`, `type`, `author`,
`owner`, `category`, `layout`, `slug`, `id`, `draft`, `summary`, `description`, `version` and a few more).
The value of such a key may also be inline JSON, so `waiver: [{...}]` does not stop the file from being read.
Postmortems are not checked for other keys. Example entry:

```json
{"file": "docs/adr/0005-ui-imports.md", "kind": "decision", "action": "not read", "key": "rules", "may_mean": ["rule"],
 "reason": "front matter key rules is not a key decisis reads, so a rule or waiver written there is not judged; it may mean rule"}
```

## A new ADR: `new-adr`

```
decisis new-adr "Review payment changes" --code-ref src/payments/ \
  --rule '{"review_required": {"paths": ["src/payments/**"], "reviewers": ["@shop/payments"]}}'
```

`new-adr` writes one MADR file and prints its path. It goes in `--adr-dir` (relative to `--repo-dir`, made
when it does not exist, refused outside the repository), or else in the first of `docs/adr`,
`docs/decisions`, `adr` and `doc/adr` that exists, the first directory `init` reads. Its name is the next
number after the highest number that starts a `.md` file name there, as wide as that number (four digits
when there is none), then the title in lower case with each run of other characters as `-`:
`0004-review-payment-changes.md`. A file of that name is never overwritten: the command stops and writes
nothing.

| Flag | Meaning |
|---|---|
| `--repo-dir DIR` | the repository (default: the current directory) |
| `--adr-dir DIR` | the ADR directory, relative to `--repo-dir` |
| `--code-ref PATH` | a path from the repository root the decision governs; repeat it for more |
| `--rule JSON` | one JSON object, the `rule` front matter key |
| `--waiver JSON` | one JSON object, a waiver in the `waivers` front matter key; repeat it for more |
| `--date DATE` | the `date` front matter key (default: today) |

The front matter has `status: proposed`, `date`, and `code_ref`, `rule` and `waivers` when they are given, as
inline JSON; the body is the `# ` title and empty `## Context and Problem Statement`, `## Considered Options` and
`## Decision Outcome` sections. Before anything is written the rule is read with the same reader `audit` and
`check` use, and a rule with an unknown kind or a bad value is refused with its reason, as is a waiver that
would waive nothing; a `code_ref` that is
not a path relative to the repository root is refused as `init` refuses it; and the whole front matter is
read back with `init`'s reader. `init` then reads the file into a decision with the same `code_ref` (with
`--repo` before each path), `rule` and `waivers`.

## The Relate graph of an audit

| Label | From | Key properties |
|---|---|---|
| `Concept`, `Decision`, `Record`, ... | the snapshot | `id`, `title`, `domain`, flattened `props` |
| `Repository` | the inventory | `id` = `repo:<name>`, `source_system` (see below), `source_ref`, `fetched_at`, `content_hash` of the inventory |
| `Package` | the inventory | `id` = `pkg:<purl type>/<name>@<version>`, `ecosystem`, `name`, `version`, `dev`, `licenses`, `license_expression`, `purl`, `unresolved`, `source_system`, `source_ref`, `fetched_at` |
| `Workspace` | a pnpm, Yarn or Bun lockfile | `id` = `workspace:<repo>:<path>`, `name` (empty for pnpm, which does not record it), `path`, `source_system`, `source_ref`, `fetched_at` |
| `Advisory` | OSV | `id` = `adv:<osv id>`, `osv_id`, `severity`, `severity_source` (only when the severity is not the record's own), `aliases`, `published`, `affected_json`, `source_url`, `fetched_at`, `content_hash` of the OSV record |

| Edge | Meaning | `evidence` |
|---|---|---|
| snapshot edges | as in the snapshot | as in the snapshot |
| `DEPENDS_ON` | the repository, a workspace or a package requires a package or a workspace; the repository holds each workspace | the requirement as the inventory states it, with `(dev)`, `(optional)` or `(peer)` for those kinds; `workspace <path>` from the repository |
| `AFFECTED_BY` | OSV returned the advisory for this name and version | `OSV returned <id> for this name and version` |
| `DESCRIBED_BY` | the repository to a snapshot node whose `code_ref` names it | `<node> has code_ref <ref>` |
| `RECORDS` | the repository to each decision of an `init` snapshot that governs it (see below) | `decisis init read <file> from the repository <name>` |

### Which decisions an audit judges

A decision governs the repository `audit --repo NAME` reads in one of two ways:

- **A snapshot from `init`** (`meta.source` is `decisis init`) holds the decisions of the one repository
  `init` read. When `meta.repo` is `NAME` (letters compared without case), or `init` ran without `--repo` so
  the repository has no name in the snapshot, each of its decisions whose `rule` holds a kind `audit` judges
  (or a rule entry that cannot be read) governs the repository: `audit` adds a `RECORDS` edge from
  `repo:NAME` to it. The decision's `code_ref`, `subject_path` and `also_touches` do not matter, and a
  `code_ref` that names part of the repository, such as `Shop:src/payments/`, does not narrow a dependency
  rule: an inventory is the dependencies of the whole repository, so the rule covers all of it. A
  superseded decision (its status says `superseded`, or it is the target of a `SUPERSEDES` edge) does not
  govern. In the report its `governing` entry has `via` set to the ADR file and `link` set to `RECORDS`.
- **A hand-written snapshot** links a decision through a path `repo:NAME -DESCRIBED_BY-> node <-ABOUT-
  decision`, where `DESCRIBED_BY` comes from the node's string `code_ref` as above. Its `governing` entry
  has `via` set to that node.

A decision whose rule holds a kind `audit` judges but that governs nothing in this audit is listed under
`not_governing` in the report, with `decision`, `title` and `reason`: an `init` snapshot of another
repository, a superseded decision of an `init` snapshot, or a hand-written decision with no path to the
repository. Its rules are not judged.

## Inventories

`audit` reads one inventory and tells its format from the content and the file name. Every reader
returns the same nodes and edges.

| Format | `source_system` | Repository | `DEPENDS_ON` | `dev` |
|---|---|---|---|---|
| npm `package-lock.json` v2 or v3 | `npm-lockfile` | the root entry | `dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies` (marked optional or peer; from the root they are shipped like `dependencies`), resolved through nested `node_modules` | reached only through `devDependencies` or entries the lockfile marks `dev`; a package nothing reaches keeps the lockfile's `dev` |
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
| GitHub Actions workflows (`*.yml`, `*.yaml` with top-level `on` and `jobs`) and `action.yml` | `github-actions-workflow` | the repository | the repository to each `uses:` of `jobs.<id>.steps[]`, of `jobs.<id>` (a reusable workflow) and of an `action.yml`'s `runs.steps[]`, with the file, job and step in the evidence | always false |
| `.terraform.lock.hcl` | `terraform-lockfile` | the repository | the repository to each `provider` block, with its `constraints` in the evidence | always false |

Package props:

- `ecosystem` is the OSV ecosystem (`npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `GitHub Actions`, and
  `Terraform`, which OSV does not have; from an SBOM purl also
  `NuGet`, `RubyGems`, `Packagist`, `GitHub Actions`, `Debian:<n>` from `distro=debian-<n>`, `Alpine:v<x.y>`
  from `distro=alpine-<x.y...>`). A purl type with no such mapping gives `""`.
- `name` is the name OSV uses: `@scope/name` for npm, the normalized name for PyPI, `group:artifact` for
  Maven, the module path for Go, `owner/repo` for a GitHub action (also for `owner/repo/path@ref`), and
  the full provider address for Terraform (`registry.terraform.io/hashicorp/aws`).
- `version` is the resolved version; Go versions drop the leading `v` (the `purl` keeps it). A GitHub
  action keeps its ref as written (`v4`, `v4.1.0`, `main` or a commit SHA).
- `licenses` is the list of SPDX ids in the license expression, empty when the inventory gives none
  (`uv.lock`, `Cargo.lock` and `go.mod` do not). `license_expression` keeps the expression as written.
- `purl` is the package URL without qualifiers.
- `unresolved` is empty when the package can be queried at OSV, and otherwise says why not (no ecosystem,
  no version). Unresolved packages stay in the graph, are not queried, and are listed in the report.
- `dev` is true when the package is reached only through development dependencies: every route from the
  repository (or a workspace) to it passes through a development package or a development dependency,
  whatever the inventory's own flag for it says. One route that passes through none makes it shipped.
  Workspaces have no `dev`; the repository always holds them. When an inventory lists one package id
  more than once, a production instance makes it shipped only when a shipped route reaches that
  instance. A package nothing reaches is development only when every instance is marked development.

A requirements line that is not a `name==version` pin gets the id `pkg:pypi/<name>@` with an empty
`version` and an `unresolved` that names the file, the line and what it gives; a direct URL or path
without a name gets `pkg:unknown/<target>@`. A ranged line for a name that another line pins links to
that pin instead. `-r` includes are read through the sibling reader (below). A Poetry package from a
`directory`, `file`, `url` or `git` source is unresolved.

An SBOM component without a purl gets the id `pkg:unknown/<name>@<version>`, ecosystem `""` and
`unresolved` `the inventory gives no purl`, with its CPE when it has one. An SBOM package that nothing
depends on is linked from the repository with the evidence `listed in the SBOM with no dependency on it`.
`audit` refuses an inventory that lists no packages, or none that can be queried at OSV, instead of
reporting it clean. A Terraform lock file is the exception: its reader sets `ADVISORIES = False`, since
OSV has no Terraform ecosystem, and its providers are judged against rules only.

A workflow `uses:` that is a local `./` path, a `docker://` image, built from an expression (`${{ ... }}`)
or not an `owner/repo[/path]@ref` name (such as `../x@v1`) gets the id `pkg:unknown/<uses>@`, ecosystem
`GitHub Actions`, an empty version and an `unresolved` reason. An action's `name` is `owner/repo` in lower
case, as GitHub matches it, and its id and purl use that name; the evidence keeps the `uses:` as written.
OSV tells case apart and stores some names in mixed case, so OSV is asked under the spelling it stores
(see the OSV cache below), and the package gets `osv_index`, which says which spellings were asked, or
that the name is not in OSV's list and so has no advisory. A workflow file
that is not valid YAML, or has neither `jobs` nor `runs.steps`, gets the id `pkg:unknown/<file>@` with the
parser's message as the reason, and the other workflows are still read. So does a workflow beside it that
cannot be read: not UTF-8, or a symbolic link that leads outside the root. Every Terraform provider has the
`unresolved` reason that OSV has no Terraform ecosystem.

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
purl `pkg:maven/<group>/<artifact>@<version>`), and the report of either carries an `inventory_notes` entry saying that
transitive dependencies are not resolved and pointing to `cyclonedx-gradle-plugin` or
`cyclonedx-maven-plugin` for the full graph.

Readers live in `src/decisis/inventory/`. Each one has `FORMAT`, `SIBLINGS` (files read from the same
directory), `detect(text, filename)` and `read(text, filename, repo, siblings=None)` returning
`(nodes, edges)`; `inventory.read` picks the first reader whose `detect` matches. A reader may also have
`sibling_names(read, resolve, listing, filename)`, which names the files to read in place of `SIBLINGS`:
the Yarn reader returns the root `package.json` and the `package.json` of each directory its `workspaces`
globs match (outside `node_modules`), and the GitHub Actions reader returns every other `*.yml` and
`*.yaml` file in the workflow's directory (at most 256; none for an `action.yml`). `listing` lists a
directory relative to the inventory under the same root as the reader; `inventory.load` passes one, and
a caller that does not (such as `serve --mcp`) gets only the file it names. Of those files, the ones with
top-level `on` and `jobs` are read as workflows. A file a reader names but that cannot be read (not
UTF-8, or outside the root) is kept in `Siblings.unread` with the reason; the GitHub Actions reader lists
such a workflow under `unresolved_packages`, and for every other format `inventory.read` adds an
`inventory_notes` entry, so no named file is dropped without a word. `inventory.gather` reads them with the same bounded reader as every other
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
qualifier. `GitHub Actions` `ECOSYSTEM` ranges are ordered as semantic versions, with the ref read as a
version (`v4.1.0` is `4.1.0`). A major or minor tag (`v4`, `v4.1`) moves to each new release under it,
so it is read as the span from `4.0.0` up to the next major (or minor): it is `affected` or not when no range
event falls inside the span, and `unresolved` otherwise. A branch or commit SHA cannot be ordered and is
`affected` only when the record's `versions` lists it. A version at or above a range's `limit` is
not affected. A version that cannot be ordered, or an `ECOSYSTEM` range of another ecosystem, gives
`unresolved`, never `affected`.

## Severity

An advisory's `severity` is the OSV record's `database_specific.severity` when it has one (GHSA records
do). A record without one (PYSEC, RUSTSEC and GO records) takes, in this order:

1. the `database_specific.severity` of a GHSA record in the same OSV data (the records this run fetched, or
   the `--osv-cache` file) that the record names in `aliases` or that names the record in its own `aliases`;
   the first such GHSA id in sorted order wins;
2. the band of the CVSS v3.0 or v3.1 base score of its `CVSS_V3` vector, computed with the formula of the
   CVSS v3.1 specification: `LOW` from 0.1, `MODERATE` from 4.0, `HIGH` from 7.0, `CRITICAL` from 9.0, as
   GHSA bands them; a score of 0.0 gives `UNKNOWN`;
3. otherwise `UNKNOWN`. `CVSS_V4` and `CVSS_V2` vectors are not scored.

When the severity does not come from the record itself, the advisory node and each finding on it carry
`severity_source`, such as `GHSA alias GHSA-248v-346w-9cwc in the same OSV data`,
`CVSS v3 base score 7.5 of CVSS:3.1/...`, or the reason it stayed `UNKNOWN`.

## The OSV cache

`--osv-cache` reads a JSON object with `fetched_at` (when the advisories were read), `queries` (a
package id such as `pkg:npm/lodash@4.17.15` to the list of advisory ids OSV returned for it) and `vulns`
(an advisory id to the OSV record as `api.osv.dev/v1/vulns/<id>` returns it). A package or advisory the
file does not hold stops the run. The keys follow the package ids, so a cache works for every ecosystem.
OSV returns nothing for a GitHub Actions query with a version, so `audit` asks for those by name only.
OSV also matches names with case, so `audit` first reads which names OSV stores from OSV's export
`https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip`: once per run, only when
the inventory has GitHub Actions packages, read up to 64 MiB, at most 100,000 records of at most 4 MiB
each, every record parsed as JSON. Each action is asked under every spelling OSV stores for its
lower-case name; a name OSV does not store is not queried. The cache keys are the id without the
version, in OSV's spelling (`pkg:githubactions/Azure/setup-kubectl`), and the `AFFECTED_BY` evidence
says the version is compared by decisis. A cache holds that list as `names`: an ecosystem to
`{"fetched_at", "names"}`. A cached run with GitHub Actions packages and no `names` entry for them stops
with the same refusal as a missing query.
`fixtures/audit/osv-cache.json` covers the demo lockfile, `fixtures/inventory/osv-cache.json` covers
the examples in `fixtures/inventory/`, `fixtures/inventory/ci/osv-cache.json` the workflows and
Terraform lock file in `fixtures/inventory/ci/` (real records of `tj-actions/changed-files`), and `fixtures/inventory/jvm/osv-cache.json` the Gradle and Maven
examples next to it.

## The report and the plan

`audit --out report.json` writes `meta`, `loaded` (node and edge counts), `today` (the date waivers were
judged on), `governing` (decisions and the node they reach the repository through, see
[Which decisions an audit judges](#which-decisions-an-audit-judges)), `summary` (counts by
status), `violations` (violated policies over all findings), `waived` (waived policies over all findings),
and `findings`. When a decision's rule cannot be read, `rule_problems` lists each
problem (`decision`, `rule`, the kind or null, and `problem`); the key is absent otherwise. When the
snapshot's `meta.problems` says an ADR file was `skipped` or `not read` (see [`init`](#a-snapshot-from-a-repository-init)),
`unread_decisions` lists each such file once with `file`, `reason` and `action`, sorted by file; the key is
absent otherwise. Such a decision is not in the snapshot, so none of its rules are judged. `audit --out`
prints the count of these files as `unread_decisions` when there are some. `not_governing` lists each
decision with a rule `audit` judges that governs nothing in this audit, with the reason; the key is absent
when there is none, and `audit --out` prints its count as `not_governing`. For an `init` snapshot `meta`
also has `snapshot_repo` (the snapshot's `meta.repo`) and `recorded_links` (the `RECORDS` edges added).

An advisory finding has `package`, `advisory`, `severity`, `severity_source` (only when the severity was
derived, see [Severity](#severity)), `status` (`affected`, `not_affected`, `unresolved`), `dev_only`, `path`
(ids from `repo:<name>` to the advisory, see below), `source_url`, `fetched_at`, `content_hash`, `advisory_summary`
and `policies`: one `decision`, `verdict` and `why` for each `advisory_severity_at_least` rule of each
governing decision, one `relevant` policy for a decision without a rule, and one `relevant` policy with
`rule` for each rule entry that cannot be read. A decision whose rules judge only licenses or packages adds
no policy to an advisory finding.

A license or package finding has `kind` (`license` or `package`), `package`, the facts it was judged on
(`ecosystem`, `license_expression` and `licenses`, or `ecosystem`, `name` and `version`), `status`, `dev_only`, `path`
(ids from `repo:<name>` to the package, see below), `source_system`, `fetched_at` of
the inventory, and `policies`, each of which names its `rule` kind. Verdicts are `violated`,
`not_violated`, `unresolved` (an unknown license), `waived` (see [Waivers](#waivers)) or `relevant`. A
`waived` policy has `waiver`, and a `violated` one whose waiver expired has `expired_waiver`. `status` is `affected` when at least one
rule of that kind matches the package, whatever its `dependencies` modifier says, and `unresolved` when
none matches and at least one cannot judge it. A package that no rule matches and every rule can judge
gives no finding, and a report whose decisions have no license or package rules has none of these
findings. A package that the repository does not reach within `--depth` gives no finding, as for advisories. Example:

```json
{"kind": "license", "package": "pkg:npm/gpl-lib@1.0.0", "ecosystem": "npm", "license_expression": "GPL-3.0-only",
 "licenses": ["GPL-3.0-only"], "status": "affected", "dev_only": false,
 "path": ["repo:Shop", "pkg:npm/gpl-lib@1.0.0"], "source_system": "npm-lockfile",
 "fetched_at": "2026-11-25T09:00:00Z",
 "policies": [{"decision": "decision:no-gpl", "verdict": "violated", "rule": "license_denied",
               "why": "license GPL-3.0-only cannot be used without a denied license (GPL-3.0-only)"}]}
```

A finding's `path` is the shortest path within `--depth` that fits its scope: for a package that is not
`dev_only`, the shortest path on which no package is a development dependency, so a shipped package that
is also reached through a development tool keeps its shipped route. When no path fits, the shortest is
kept. Among paths of the same length, a license or package finding shows the first one a breadth-first
search reaches, visiting each package's dependencies in id order.

`unresolved_packages` lists each package that was not queried (`package`, `reason`), and
`inventory_notes` lists sentences on what the inventory does not cover, from the reader (an include not followed,
a dev split that is unknown) or from its format (the Gradle and Maven readers do not resolve transitive
dependencies); it is empty when there are none.

`propose --out plan.json` writes `space`, `nodes` (records), `edges` (`relates_to` from a record to a
decision, with the verdict as evidence), `held` (findings not recorded and why; a record that failed a
re-derivation check has `record` and `failed`, the list of failed checks) and `digest`: the first 16 hex
digits of SHA-256 over the space, nodes and edges as sorted JSON. Only `affected` findings become records,
waived ones too: their record lists the decisions whose violation is waived in `waived` (absent when there are
none), not in `violates`, and their edge evidence starts with `waived:`;
one record covers every version of a package in one scope with the same claim.

| Finding | Record id | `predicate` | `value` |
|---|---|---|---|
| advisory | `record:<repo>-<package>-<shipped\|development>-<advisory>` | `affected_by_advisory` | the OSV id |
| license | `record:<repo>-<purl type>-<package>-<scope>-license-<expression slug>` | `licensed_under` | the license expression |
| package | `record:<repo>-<purl type>-<package>-<scope>-denied-package` | `uses_denied_package` | `<ecosystem>:<name>` |

An expression slug longer than 24 characters is cut to 16 and ends with 7 hex digits of the expression's SHA-256. Every
record's props hold the claim (`entity`, `predicate`, `value`, `scope`, `versions`, `statement`), the
evidence (`dependency_paths`, `measured_at`, `measured_ref`, `lockfile_hash`, `subject_path`) and
`violates`. An advisory record adds `severity`, `source` (the OSV page), `advisory_fetched_at` and
`advisory_content_hash`. A license or package record adds `ecosystem` (so one name in two ecosystems gives two records), `rules` (the rule kinds behind its edges),
`source` (the inventory path), `source_system` and `inventory_fetched_at`.

Before the write set is shown, `propose` derives every record again from a fresh sandbox built from the
snapshot and the inventory. For an advisory record it checks the advisory hash and severity, each version
inside the advisory's ranges, each path and its scope, and each edge target. For a license or package
record it checks that each version is a package of the record's ecosystem in the inventory whose license expression (or ecosystem
and name) is the record's `value`, that each path is in the graph and matches the scope, that each
decision in `violates` or `waived` has a rule of that kind the package violates, and each edge target. A
waived finding's record is checked like any other, scope and paths included.

## The check report

`check` prints one JSON object:

- `loaded`, `hops`, `repo`: as in `impact`.
- `base`: the `--base` ref, or null with `--changed`. `changed`: the changed files, relative to `--repo-dir`,
  sorted. `reviewers`: the handles given.
- `governing`: each decision that `impact` reaches from a changed file, with `decision`, `title`, `status`
  when it has one, and `files`. `superseded`: the same for superseded decisions, with `superseded_by`;
  these are never judged.
- `rules`: each `review_required` and `imports_forbidden` rule judged, with `decision`, `rule`, its value
  (`paths` and `reviewers`, or `from` and `to`) and the changed `files` its `paths` or `from` globs cover.
  Every decision in the snapshot that is not superseded is judged, whether or not `impact` reaches it,
  because a rule's globs name the files it covers.
- `imports`: each import read from a changed file that a `from` glob covers, with `file`, `line`,
  `import`, `resolution` (`repository`, `external` or `unresolved`), `target` (a repository path, a Go
  package directory ending in `/`, `node_modules/<specifier>` for an external JavaScript package, or null)
  and `why` when it is unresolved. A Rust `import` is written `use <path>` or `mod <name>`.
- `today`: the date waivers were judged on.
- `violations`, `unresolved` and `waived`: one entry per file, import and rule, with `file`, `line` (null for
  `review_required`), `decision`, `rule`, `verdict`, `why`, `import` and `target` (both null for
  `review_required`). A `waived` entry adds `waiver`, and a violation whose waiver expired adds
  `expired_waiver` (see [Waivers](#waivers)).
- `summary`: the count of `violated`, `unresolved`, `waived` and `not_violated` results.
- `impact`: the `impact` result for each changed file.
- `rule_problems`, only when there are some: as in the audit report, for every decision in the snapshot that is
  not superseded, whatever it governs: a rule entry that cannot be read (an unknown kind, a kind with a value of
  the wrong shape, an `audit` kind as well as a `check` kind) and each waiver that cannot be read.
- `unread_decisions`, only when there are some: as in the audit report, each ADR file the snapshot's
  `meta.problems` says was `skipped` or `not read`, with `file`, `reason` and `action`. The text view lists
  them under `decision files not read`, the HTML view in their own section, and the Mermaid view as one
  node each.

`check` exits 1 when `violations` is not empty and 0 otherwise, including when no rule applies or every
violation is waived. An
`unresolved` result, a rule problem or an unread decision file does not change the exit code, unless
`--fail-on-unresolved` is given: then an `unresolved` result or an entry of `unread_decisions` also exits 1.
`summary.unresolved` counts results only, not unread decision files. A CI gate that must not pass what it could not judge
uses that flag. With `--base REF`, the changed files
are `git diff --name-only --relative REF...HEAD` in `--repo-dir`, so a commit not yet made is not
included; a REF that starts with `-` is refused.

## The query result

`query` and the MCP `query` tool return one JSON object:

| Key | Meaning |
|---|---|
| `loaded` | the node and edge counts the sandbox loaded |
| `columns` | the column names of the statement's `RETURN`, in order |
| `row_count` | how many rows the statement gave |
| `rows` | the rows, each a mapping from column name to value; a node comes back as its labels and properties, an edge as its type and properties, a path as its `nodes` and `relationships` |
| `cut` | only when `rows` is shorter than `row_count`: how many rows are shown, and that results stop at 500 rows and 1 MiB |

## MCP replies

Every tool of `serve --mcp` takes `detail`. With `"full"` the reply is the report the command prints:
the `impact`, `paths`, `check` or `audit` JSON above, or the query result. With `"summary"`, the default over MCP,
the reply has `"detail": "summary"`, the counts, ids and titles of the report, at most 10 items of each
list, and a `note` that says how to get the rest. The `check` summary keeps `summary`, `base` and
`reviewers`, counts each list (`changed_count`, `governing_count`, `violations_count`, `unresolved_count`,
`rules_count`, `rules_covering_a_change`, `imports_count`), and lists the first 10 violations and
unjudged entries with `file`, `line`, `decision`, `rule`, `why` and `import`. The `check` and `audit`
summaries keep `rule_problems` and `unread_decisions` when the report has them, as
`rule_problems_count` and `unread_decisions_count` with the first 10 entries; the `audit` summary also keeps
`not_governing` as `not_governing_count` and the first 10 entries. When the snapshot file
changed and failed to reload, the reply also has `reload_failed`: the reason, and that the reply comes
from the snapshot loaded before. A reply that would pass 1 MiB as the server sends it has
its longest list shortened from the end, and a `cut` entry names each list that was shortened. A refused
argument comes back as an MCP error result that names it, not as a report.

## The benchmark task file

`compare --tasks FILE` reads one JSON task file; `bench/tasks.json` is the default and
`bench/holdout/tasks.json` the held-out set. A task has an `id`, a `kind` (`audit` or `impact`), a
`subject` (a package id or a code path), the `connection` it tests, `graph_expected_to_help` (set before
the first run), a `why`, and `expected`: the `paths`, `policy_links` and, for audit tasks, `findings` a
correct answer gives. The file names its inputs: `inputs` in the synthetic set, `repos` with each
repository's snapshots, lockfile and OSV cache in the held-out set. The results JSON keeps the task file's
SHA-256, each method's scores and claims per task, the totals and the `c_vs_b` lists; `results.md` is its
table.

## The demo transcript

`demo/transcript.json` lists each step with its printed lines and counts, the approval, the findings,
and run-time stamps only under `timestamps`; `demo/expected_findings.json` is the findings part alone.
Two runs differ only in `timestamps`.
