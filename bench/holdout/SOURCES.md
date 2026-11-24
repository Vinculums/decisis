# Held-out benchmark: sources, licenses and attribution

The held-out tasks in `tasks.json` run on inputs taken from five public repositories. Each is pinned to the
commit below and licensed under MIT or Apache-2.0. Each repository's files are copyright their authors; the
excerpts stored here are used under the repository's license. The notices that license requires are reproduced below.

| Directory | Repository | Commit | License | ADRs read | Lockfile at that commit | Stored here |
|---|---|---|---|---|---|---|
| `cf-cli/` | [cloudfoundry/cli](https://github.com/cloudfoundry/cli) | `5b69b945ed793811a1d5896ebe0238fb48389259` | Apache-2.0 | `doc/adr/` (12) | `go.mod`, `go.sum` | snapshot, mapping |
| `turtles/` | [rancher/turtles](https://github.com/rancher/turtles) | `be75f9a24befacfb5b1c571fb410a2e218f1f45e` | Apache-2.0 | `docs/adr/` (18) | `go.mod`, `go.sum` | snapshot, mapping |
| `weave-gitops/` | [weaveworks/weave-gitops](https://github.com/weaveworks/weave-gitops) | `936e848c4e001355fccdfee61c0d54e4a9917183` | Apache-2.0 | `doc/adr/` (16) | `go.mod`, `go.sum` | snapshot, mapping |
| `supabase-multitenant/` | [supabase-multitenant/supabase-multitenant](https://github.com/supabase-multitenant/supabase-multitenant) | `96d6f94063eb1356649d710b21eb513e3e1fa415` | MIT | `docs/adr/` (3) | `package-lock.json` (v3) | snapshot, mapping, lockfile, OSV cache |
| `karma-sabarivka-reporter/` | [kopach/karma-sabarivka-reporter](https://github.com/kopach/karma-sabarivka-reporter) | `6fb805a9f27e3a15027e01a4fa56a80542d55ee2` | MIT | `doc/adr/` (4) | `package-lock.json` (v2) | snapshot, mapping, lockfile, OSV cache |

Copyright and license notices. The two MIT notices and the one NOTICE file found at the pinned commits are
reproduced exactly as they appear in each repository's LICENSE or NOTICE file at that commit.

### supabase-multitenant/supabase-multitenant (MIT)

From `LICENSE` at `96d6f94063eb1356649d710b21eb513e3e1fa415`; it covers `supabase-multitenant/package-lock.json` and the
ADR excerpts in `supabase-multitenant/`:

```
MIT License

Copyright (c) 2026 WebBoxes Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### kopach/karma-sabarivka-reporter (MIT)

From `LICENSE` at `6fb805a9f27e3a15027e01a4fa56a80542d55ee2`; it covers `karma-sabarivka-reporter/package-lock.json`
and the ADR excerpts in `karma-sabarivka-reporter/`:

```
MIT License

Copyright (c) 2020 Ihor Kopach https://github.com/kopach

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### cloudfoundry/cli (Apache-2.0)

Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0). The repository has a
`NOTICE` file at `5b69b945ed793811a1d5896ebe0238fb48389259`, reproduced here:

```
Copyright (c) 2015-Present CloudFoundry.org Foundation, Inc. All Rights Reserved.

This project contains software that is Copyright (c) 2013-2015 Pivotal Software, Inc.

This project is licensed to you under the Apache License, Version 2.0 (the "License").

You may not use this project except in compliance with the License.

This project may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and 
conditions of the subcomponent's license, as noted in the LICENSE file.
```

### rancher/turtles (Apache-2.0)

Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0); see the repository's
LICENSE file. There is no NOTICE file at `be75f9a24befacfb5b1c571fb410a2e218f1f45e`.

### weaveworks/weave-gitops (Apache-2.0)

Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0); see the repository's
LICENSE file. There is no NOTICE file at `936e848c4e001355fccdfee61c0d54e4a9917183`.

## Advisory data

Advisory data in the two `osv-cache.json` files comes from [OSV](https://osv.dev) (api.osv.dev), queried on
2026-11-25 for exactly the packages decisis reads from each stored lockfile. OSV aggregates sources; the npm
records here come from the GitHub Advisory Database, licensed CC-BY-4.0.

## What is stored, and how it was made

`build_inputs.py` made every stored file from a shallow clone at the pinned commit; `compare` reads only the stored
files and never the network.

- `snapshot.json`: the output of `decisis init` (ADRs and CODEOWNERS; none of the five has a postmortem directory,
  and `--github` was not used) with each node cut down to its id, kind, title and these props: `source_file`,
  `status`, `date`, `code_ref`, `content_hash`, and `statement` cut to 200 characters. No whole document is stored.
  Deciders' names are dropped. `meta.problems` keeps what init reported, such as ADRs that name no code paths.
- `mapping.json`: **hand-made.** ADRs in these repositories carry no `code_ref` front matter. Where an ADR's text
  names a file or directory, the mapping lists that path under the ADR, with the sentence it was copied from;
  `build_inputs.py` checks that each sentence is in the ADR and that the path is in the sentence, then adds the
  paths to the decision as `code_ref`. No path was added that the ADR does not name, and an ADR's spelling is kept
  even where the code lives elsewhere (cf-cli ADR 11 says `action/v7action`; the directory is `actor/v7action`).
  Paths an ADR names in another repository (turtles ADR 9 names Rancher's `pkg/image/origins.go`) and paths in an
  example layout the ADR calls an example (weave-gitops ADR 9) were not taken. The mappings were written before
  `compare` was run on the held-out tasks.
- `package-lock.json` (npm repositories only): the repository's lockfile with each package entry cut to the keys
  decisis reads (`name`, `version`, `dev`, `optional`, `devOptional`, `peer`, `link`, `license` and the dependency
  maps); `resolved`, `integrity`, `engines`, `funding`, `bin` and the like are dropped. `build_inputs.py` checks
  that the trimmed lockfile gives the same packages and edges as the original.
- `osv-cache.json` (npm repositories only): the querybatch answer for every package, and each advisory record cut
  to `id`, `summary`, `aliases`, `published`, `modified`, `affected` (package, ranges, versions) and
  `database_specific.severity`. Advisory details and references are dropped.

- `suggest-refs.json` and `suggest-refs.md`: the score of `decisis init --suggest-refs` against each `mapping.json`,
  made by `score_suggest_refs.py` from the same clones. For each suggestion the mapping does not have it keeps the
  ADR sentence the suggestion came from, as an excerpt; no whole document is stored.

The three Go repositories have impact tasks only. Their lockfile is `go.mod` with `go.sum`, which decisis can
audit, but `compare`'s text join (method B) and its evidence check read npm lockfiles only, so audit tasks on
them would measure that limit rather than the graph; their lockfiles are not stored.

Repositories looked at and left out: Maptio/maptio (AGPL-3.0, although GitHub lists MIT), skupperproject/skupper
and grafana/oats (their ADRs name no path in the repository), and repositories whose only lockfile is yarn.lock or
pnpm-lock.yaml, which decisis does not read.
