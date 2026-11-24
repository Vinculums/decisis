# Benchmarks

## Synthetic set

```
decisis compare
```

`compare` runs nine tasks from `bench/tasks.json` three ways, offline and without a model:
**A** answers from the Vinc snapshot alone (nodes whose `code_ref`, `subject_path` or `also_touches` matches the
subject, then one hop; a matching decision or record is reported itself, as `impact` reports it at zero hops);
**B** adds the lockfile and the advisories as flat records joined by package name, with the same version
range check and policy rule as C; **C** loads all three into a Relate graph and queries it. The tasks and
their expected findings were committed before the first run. A path or a policy link counts when it
equals an expected one; any other claim is unsupported; a claim is covered when its evidence is a
connected chain of edges that exist in the inputs.

| Method | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |
|---|---|---|---|---|---|---|
| A | 5/13 | 5/17 | 0/5 | 0/10 | 10/10 | 0.6 |
| B | 9/13 | 15/17 | 5/5 | 1/30 | 27/30 | 0.8 |
| C | 13/13 | 17/17 | 5/5 | 0/35 | 35/35 | 225.9 |

Against B, C is better on 2 tasks, the same on 7 and worse on none. It helped where a connection spans
sources: a vulnerable package reached only through a shared transitive dependency, and a decision two
hops from the code it governs. Per-task numbers are in `bench/results.md`, every claim with its
coverage in `bench/results.json`. Latency is the only number that changes between runs; C's includes
building and loading a graph for each task.

Read the numbers with these caveats:

- **B's policy-link score is generous.** On the shared transitive dependency B claims a wrong chain
  (through test-kit, which has its own nested copy), yet both of its policy links on that task still
  count as correct because they name the right decision and advisory. Their evidence chain is the wrong
  one; the coverage column (27/30) is where that shows.
- **"C against B" compares paths, policy links and unsupported claims only.** Findings, coverage and
  latency are not part of that label.
- **The impact rule was fitted after seeing the decoy.** `impact` follows a `RELATED_TO` edge only from a
  concept that names no code of its own. That condition was chosen after the overreach decoy task had
  been run, because edge type and direction alone cannot tell the expected path from the decoy. The
  expected findings were not changed, but the rule is fitted on this benchmark; a held-out set is
  needed to show it generalises. The held-out set below does not exercise that rule, so it is still
  unshown.
- **The benchmark is small and synthetic.** Nine hand-built tasks show which kinds of connection need a
  graph, not how often they occur in real repositories. The held-out set below is a first look at that.

## Held-out set: five open-source repositories

```
decisis compare --tasks bench/holdout/tasks.json
```

Run it from a checkout of this repository; the held-out inputs are not in the wheel. The 30 tasks (20 impact,
10 audit) run on cloudfoundry/cli, rancher/turtles, weaveworks/weave-gitops, supabase-multitenant and
karma-sabarivka-reporter at pinned commits (Apache-2.0 and MIT; sources, licenses and attribution in
`bench/holdout/SOURCES.md`). Each snapshot is `decisis init` on the repository, cut to ids, paths, titles and
short statements. ADRs there carry no `code_ref`, so a hand-made mapping adds the paths each ADR's own text
names, quoting the sentence. Impact expectations were written from the ADR text; audit expectations from an npm
resolution of the lockfile worked out without decisis and the advisories OSV returned. They were committed
before the first run, and the results were committed as they came out. Scoring and the impact carry rules are
the same as for the synthetic set.

| Method | Set | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |
|---|---|---|---|---|---|---|---|
| A | synthetic | 5/13 | 5/17 | 0/5 | 0/10 | 10/10 | 0.6 |
| A | held-out | 19/44 | 19/28 | 0/14 | 4/42 | 4/42 | 1.4 |
| B | synthetic | 9/13 | 15/17 | 5/5 | 1/30 | 27/30 | 0.8 |
| B | held-out | 26/44 | 19/28 | 14/14 | 5/64 | 25/64 | 83.7 |
| C | synthetic | 13/13 | 17/17 | 5/5 | 0/35 | 35/35 | 225.9 |
| C | held-out | 35/44 | 19/28 | 14/14 | 0/68 | 30/68 | 5836.0 |

Against B on the held-out set, C is better on 8 tasks, the same on 22 and worse on none. Per-task numbers are
in `bench/holdout/results.md`, every claim in `bench/holdout/results.json`. Where C did not beat A or B, or
won for a reason other than the graph:

- **C's lead is the 8 tasks marked in advance as expected to help, and no more.** The first run of this set had
  C better on 21 tasks. Thirteen of those were not the graph's doing: in an `init` snapshot the ADR's decision is
  itself the node that names the path, and A (and B, which is A for impact) reported the neighbours of a matching
  node but not the matching node, so it returned nothing where C listed that decision at zero hops. A now reports
  the matching decision or record itself, and those 13 tasks are the same for all three methods. Only A's
  retrieval changed; the inputs, the expectations, the carry rules, the scoring and C's claims are the same as in
  the first run, which is in the history of `bench/holdout/results.json`.
- **The graph mattered on those 8 tasks.** On two weave-gitops tasks A and B return ADR 15 but also ADR 5, which
  ADR 15 supersedes (2 unsupported claims each); C does not follow `SUPERSEDES`. On six audit tasks the affected
  package is three to seven hops from the repository, and B's join through a direct parent finds no chain (on one
  it claims a wrong one); C finds every expected chain. So on impact C beats B on 2 of 20 tasks, on audit on 6 of 10.
- **C was the same as B on 22 tasks.** On 13 impact tasks every method lists the decision that names the path. On
  four audit tasks the chain is one or two hops, which B's join finds. On five impact tasks a decision governs the
  path by its text but names no path, and no method found anything.
- **Every method missed the same 9 of 28 policy links, and C 9 of 44 paths.** All nine are decisions that govern
  the path by their text without naming it: the five tasks above, cf-cli ADR 11 (which spells the actor directory
  `action/` where the code is in `actor/`), and turtles ADR 12 (which names no path for the embedded clusterctl
  config).
- **Evidence coverage is low for every method on impact: C 30/68, B 25/64, A 4/42.** Each method makes the same
  38 zero-hop impact claims, which have no edge to cite, and a claim with no evidence counts as uncovered. The only
  impact claims A and B have covered are the 4 ADR 5 claims above, which are wrong.
- **C is slower: 5.8 s against 0.1 s for B.** Each audit task takes 0.4 to 0.7 s to build the graph for a
  lockfile of 700 to 1,250 packages and query paths up to eight hops. The first run, before the loader built
  edges by internal id, took 204.6 s, 9 to 28 s per audit task; C's claims are the same in both runs.
- **The audit policy logic is untested here.** No held-out ADR states a machine-checkable dependency rule or
  names an affected package, and an `init` snapshot links no decision to the repository, so the audit tasks
  expect no policy links and every method returns none.
- **The carry rules are barely exercised.** The five snapshots hold one edge between them: weave-gitops ADR 15
  `SUPERSEDES` ADR 5, which two tasks use (none of the repositories has postmortems, and `--github` was not used). The `RELATED_TO` rule fitted on the
  synthetic decoy never comes into play, so this set does not show that it generalises.
- **The stored snapshots predate a later `init` fix.** They were built before `init` read a bold `Status` line and
  the `Superceded` spelling. Rebuilt with that fix, the three supabase-multitenant ADRs gain a status (two of them a date
  too), and weave-gitops ADR 3 gains the status superseded and a `SUPERSEDES` edge from ADR 11; the other three
  snapshots are unchanged. The stored snapshots were kept so that the change in the numbers above comes from A
  alone. On the ten impact tasks of those two repositories, the rebuilt snapshots give every method the same scores.
- **`init --suggest-refs` is scored in-sample on this set, not held out.** Run on the five clones, the code refs
  it suggests are scored against the hand mapping (`bench/holdout/score_suggest_refs.py`, which needs the clones;
  the result is `bench/holdout/suggest-refs.json`). Four of its matching rules were chosen after looking at these
  five repositories: reading link and GitHub URL targets, counting only words with a `/` in fenced code blocks,
  matching a bare word only at the root, and skipping the ADR's own directory. The mapping was written before
  `--suggest-refs` existed, but the rules were fitted on it, so the score below shows how well the rules fit
  this set and does not show that they generalise. The snapshots, tasks and results above are not rebuilt from
  it.

| Repository | Suggested | Mapped | Matched | Precision | Recall |
|---|---|---|---|---|---|
| cf-cli | 18 | 16 | 13 | 0.722 | 0.812 |
| karma-sabarivka-reporter | 0 | 0 | 0 | n/a | n/a |
| supabase-multitenant | 4 | 4 | 4 | 1.000 | 1.000 |
| turtles | 6 | 3 | 2 | 0.333 | 0.667 |
| weave-gitops | 17 | 13 | 9 | 0.529 | 0.692 |
| total | 45 | 36 | 28 | 0.622 | 0.778 |

  Seven of the 8 mapped paths it misses are not in the repository at the pinned commit (the ADR's spelling, such
  as cf-cli's `action/v7action`, or a file that is not there at that commit, such as weave-gitops's
  `.github/workflows/helm.yaml`); the eighth is cf-cli's `Makefile`, written without
  backticks or an extension. Of the 17 suggestions the mapping does not have, some name real paths the mapping
  left out (cf-cli's `actor` and `resources` directories) and some are plain misses: a file name that matches
  several files (`index.js`, `Chart.yaml`) or an API version that is also a directory (`management/v3`).
- **Small and hand-mapped.** Five repositories, two of them npm (the Go repositories have impact tasks only,
  because B and the coverage check read npm lockfiles only), and one person's reading of which ADR governs
  which path.
