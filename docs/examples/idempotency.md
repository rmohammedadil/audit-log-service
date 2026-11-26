# Idempotency example

## Objective

Show writer-scoped safe retry behavior.

Send the same event body and `Idempotency-Key: demo-key-001` twice as the same
tenant-aware writer with `CREATE_EVENT`. Expected: first request 201; replay
200 with the same opaque `eventRef` and no checkpoint advance. Change the
payload while retaining the key for 409. The key is scoped to tenant plus
authenticated writer subject, so a subject in another tenant can use the same
key separately. Invalid/blank/oversized keys are 422 without writes. Replay
reauthorizes, applies redaction, and verifies evidence before release.
