---
code_ref: "src/logging/"
---
# Card numbers never reach the logs

* Status: accepted
* Deciders: Ben, Chen
* Date: 2026-02-10

## Context and Problem Statement

Log lines are kept for thirty days and read by support staff.

## Decision Outcome

Chosen option: "Redact card numbers in the logger", because every log line passes through it.
