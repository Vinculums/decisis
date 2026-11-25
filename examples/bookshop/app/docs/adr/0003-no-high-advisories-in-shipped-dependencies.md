---
status: accepted
date: 2026-02-20
decision-makers: [Ana, Chen]
subject_path: package-lock.json
rule: {"advisory_severity_at_least": "HIGH", "dependencies": "shipped"}
---
# No high advisories in shipped dependencies

## Context and Problem Statement

The shop ships its npm dependencies to customers' browsers.

## Decision Outcome

Chosen option: "Block HIGH and CRITICAL advisories in shipped dependencies", because development tools never reach a customer.
