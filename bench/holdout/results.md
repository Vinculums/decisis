| Method | Path discovery | Policy links | Findings | Unsupported claims | Evidence coverage | Latency (ms, all tasks) |
|---|---|---|---|---|---|---|
| A | 0/44 | 0/28 | 0/14 | 4/4 | 4/4 | 1.6 |
| B | 7/44 | 0/28 | 14/14 | 5/26 | 25/26 | 87.5 |
| C | 35/44 | 19/28 | 14/14 | 0/68 | 30/68 | 204571.5 |

| Task | Graph expected to help | A paths, links, unsupported | B paths, links, unsupported | C paths, links, unsupported | C against B |
|---|---|---|---|---|---|
| cf-cli-command-file | no | 0/2, 0/2, - | 0/2, 0/2, - | 2/2, 2/2, 0/4 | better |
| cf-cli-command-test | no | 0/3, 0/3, - | 0/3, 0/3, - | 3/3, 3/3, 0/6 | better |
| cf-cli-actor-named-wrongly | no | 0/2, 0/2, - | 0/2, 0/2, - | 1/2, 1/2, 0/2 | better |
| cf-cli-api-layer | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| cf-cli-integration-test | no | 0/2, 0/2, - | 0/2, 0/2, - | 2/2, 2/2, 0/4 | better |
| turtles-proxy-types | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| turtles-clusterctl-config | no | 0/2, 0/2, - | 0/2, 0/2, - | 1/2, 1/2, 0/2 | better |
| turtles-clusterctlconfig-controller | no | 0/1, 0/1, - | 0/1, 0/1, - | 0/1, 0/1, - | same |
| turtles-import-controller | no | 0/2, 0/2, - | 0/2, 0/2, - | 0/2, 0/2, - | same |
| weave-gitops-auth-superseded | yes | 0/1, 0/1, 2/2 | 0/1, 0/1, 2/2 | 1/1, 1/1, 0/2 | better |
| weave-gitops-server-cmd | yes | 0/1, 0/1, 2/2 | 0/1, 0/1, 2/2 | 1/1, 1/1, 0/2 | better |
| weave-gitops-buf | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| weave-gitops-release-workflow | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| weave-gitops-cli-verb-noun | no | 0/1, 0/1, - | 0/1, 0/1, - | 0/1, 0/1, - | same |
| supabase-replaced-session-auth | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| supabase-prisma-schema | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| supabase-auth-route | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
| supabase-coolify | no | 0/1, 0/1, - | 0/1, 0/1, - | 1/1, 1/1, 0/2 | better |
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
