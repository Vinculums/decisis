---
title: Customers were charged twice after gateway timeouts
date: 2026-03-14
code_ref: [src/payments/retry.py]
decisions: [0003-retry-payment-calls-once]
---
# Customers were charged twice after gateway timeouts

## What happened

The gateway processed calls it then timed out on, and the retries in ADR-0002 charged again.
