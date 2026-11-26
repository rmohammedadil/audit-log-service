# Idempotency example

## Objective

Show writer-scoped safe retry behavior.

Send the same event body and `Idempotency-Key: demo-key-001` twice as the same writer. Expected: first request 201; replay 200 with same event ID and no checkpoint advance. Change the payload while retaining the key for 409. A different writer subject can use the same key separately. Invalid/blank/oversized keys are 422 without writes. Replay applies redaction and verifies evidence before release. See idempotency route tests and [system design](../system-design.md#16-transactional-idempotency).
