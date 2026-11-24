---
code_ref: src/payments/retry.py
---
# 2. Retry payment calls three times

Date: 2026-01-20

## Status

Superseded by [3. Retry payment calls once, with an idempotency key](0003-retry-payment-calls-once.md)

## Context

The gateway drops about one call in two hundred.

## Decision

A failed payment call is retried three times, one second apart.

## Consequences

Most dropped calls succeed on a retry.
