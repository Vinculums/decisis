| Repository | Suggested | Mapped | Matched | Precision | Recall |
|---|---|---|---|---|---|
| cf-cli | 18 | 16 | 13 | 0.722 | 0.812 |
| karma-sabarivka-reporter | 0 | 0 | 0 | n/a | n/a |
| supabase-multitenant | 4 | 4 | 4 | 1.000 | 1.000 |
| turtles | 6 | 3 | 2 | 0.333 | 0.667 |
| weave-gitops | 17 | 13 | 9 | 0.529 | 0.692 |
| total | 45 | 36 | 28 | 0.622 | 0.778 |

In-sample, not a held-out result: the matching rules of `--suggest-refs` (link and GitHub URL targets, only words with a `/` in fenced code blocks, bare words only at the root, the ADR's own directory skipped) were chosen after looking at these five repositories.

Made with `python bench/holdout/score_suggest_refs.py CLONES --out bench/holdout/suggest-refs.json --table bench/holdout/suggest-refs.md`.
