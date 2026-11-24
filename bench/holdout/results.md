| Method | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |
|---|---|---|---|---|---|---|
| A | 19/44 | 19/28 | 0/14 | 4/42 | 4/42 | 1.4 |
| B | 26/44 | 19/28 | 14/14 | 5/64 | 25/64 | 83.7 |
| C | 35/44 | 19/28 | 14/14 | 0/68 | 30/68 | 5836.0 |

| Task | Graph expected to help | A paths, links, unsupported | B paths, links, unsupported | C paths, links, unsupported | C against B |
|---|---|---|---|---|---|
| cf-cli-command-file | no | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | same |
| cf-cli-command-test | no | 3/3, 3/3, 0/6 | 3/3, 3/3, 0/6 | 3/3, 3/3, 0/6 | same |
| cf-cli-actor-named-wrongly | no | 1/2, 1/2, 0/2 | 1/2, 1/2, 0/2 | 1/2, 1/2, 0/2 | same |
| cf-cli-api-layer | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| cf-cli-integration-test | no | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | 2/2, 2/2, 0/4 | same |
| turtles-proxy-types | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| turtles-clusterctl-config | no | 1/2, 1/2, 0/2 | 1/2, 1/2, 0/2 | 1/2, 1/2, 0/2 | same |
| turtles-clusterctlconfig-controller | no | 0/1, 0/1, - | 0/1, 0/1, - | 0/1, 0/1, - | same |
| turtles-import-controller | no | 0/2, 0/2, - | 0/2, 0/2, - | 0/2, 0/2, - | same |
| weave-gitops-auth-superseded | yes | 1/1, 1/1, 2/4 | 1/1, 1/1, 2/4 | 1/1, 1/1, 0/2 | better |
| weave-gitops-server-cmd | yes | 1/1, 1/1, 2/4 | 1/1, 1/1, 2/4 | 1/1, 1/1, 0/2 | better |
| weave-gitops-buf | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| weave-gitops-release-workflow | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| weave-gitops-cli-verb-noun | no | 0/1, 0/1, - | 0/1, 0/1, - | 0/1, 0/1, - | same |
| supabase-replaced-session-auth | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| supabase-prisma-schema | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| supabase-auth-route | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| supabase-coolify | no | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | 1/1, 1/1, 0/2 | same |
| supabase-authjs-config | no | 0/1, 0/1, - | 0/1, 0/1, - | 0/1, 0/1, - | same |
| karma-source-file | no | 0/2, 0/2, - | 0/2, 0/2, - | 0/2, 0/2, - | same |
| supabase-direct-dev-dependency | no | 0/1, -, - | 1/1, -, 0/2 | 1/1, -, 0/2 | same |
| supabase-two-hop-tinypool | no | 0/2, -, - | 2/2, -, 0/4 | 2/2, -, 0/4 | same |
| supabase-two-hop-mocker | no | 0/2, -, - | 2/2, -, 0/4 | 2/2, -, 0/4 | same |
| karma-two-hop-extract-zip | no | 0/2, -, - | 2/2, -, 0/4 | 2/2, -, 0/4 | same |
| karma-three-hop-trim-newlines | yes | 0/1, -, - | 0/1, -, 0/1 | 1/1, -, 0/2 | better |
| karma-two-chains-babel-traverse | yes | 0/2, -, - | 0/2, -, 1/2 | 2/2, -, 0/3 | better |
| karma-four-hop-once | yes | 0/1, -, - | 0/1, -, 0/1 | 1/1, -, 0/2 | better |
| karma-four-hop-async | yes | 0/1, -, - | 0/1, -, 0/1 | 1/1, -, 0/2 | better |
| karma-six-hop-lodash-template | yes | 0/2, -, - | 0/2, -, 0/2 | 2/2, -, 0/4 | better |
| karma-two-chains-http-cache-semantics | yes | 0/2, -, - | 0/2, -, 0/1 | 2/2, -, 0/3 | better |
