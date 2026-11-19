| Method | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |
|---|---|---|---|---|---|---|
| A | 5/13 | 5/17 | 0/5 | 0/10 | 10/10 | 0.2 |
| B | 9/13 | 15/17 | 5/5 | 1/30 | 27/30 | 0.6 |
| C | 13/13 | 17/17 | 5/5 | 0/35 | 35/35 | 85.0 |

| Task | Graph expected to help | A paths, links, unsupported | B paths, links, unsupported | C paths, links, unsupported | C against B |
|---|---|---|---|---|---|
| audit-direct-dependency | no | 0/1, 0/2, - | 1/1, 2/2, 0/4 | 1/1, 2/2, 0/4 | same |
| audit-transitive-shipped | yes | 0/2, 0/2, - | 0/2, 2/2, 1/4 | 2/2, 2/2, 0/5 | better |
| audit-nested-dev-copy | yes | 0/1, 0/2, - | 1/1, 2/2, 0/4 | 1/1, 2/2, 0/4 | same |
| audit-dev-only-direct | no | 0/1, 0/2, - | 1/1, 2/2, 0/4 | 1/1, 2/2, 0/4 | same |
| audit-version-outside-range | no | 0/1, 0/2, - | 1/1, 2/2, 0/4 | 1/1, 2/2, 0/4 | same |
| impact-two-hop-decision | yes | 0/2, 0/2, - | 0/2, 0/2, - | 2/2, 2/2, 0/4 | better |
| impact-one-hop-decision | no | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | same |
| impact-directory-prefix-decoy | no | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | same |
| impact-overreach-decoy | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
