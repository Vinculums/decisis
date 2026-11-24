---
code_ref: [src/payments/retry.py]
also_touches:
  - src/payments/gateway.py
deciders: [Ana, Ben]
---
# 3. Retry payment calls once, with an idempotency key

Date: 2026-03-20

## Status

Accepted

Supersedes [2. Retry payment calls three times](0002-retry-payment-calls-three-times.md)

## Context

Three blind retries charged some customers twice.

## Decision

A failed payment call is retried once, and every call carries an idempotency key.

## Consequences

A dropped call that the gateway did process is not charged again.
