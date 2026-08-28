# L8 D6 Worker Credential Lifecycle Verification

This note covers the worker-only D6 slice that wires prepare/renew/loss/revoke
around durable `sandboxjob-v2` jobs. It does not implement Firecracker, the
guest helper, or live source resolution.

## Real operations

- Authenticated `job_start_v2` with production credential intent binds through
  the injected `JobCredentialRuntimeBinder`, persists the seed, preflights,
  persists the complete identity, then `Prepare`s. A non-nil session with nil
  error transfers ownership; the worker activates the session proof and retains
  an in-memory handle. Failure before transfer aborts the preflight.
- Authenticated `job_cancel_v2` revokes the transferred session, then clears
  private credential state. Loss on the transferred latch follows the same
  revoke/clear order.
- Restart recovery is explicit. A typed-nil `RecoveryProvider` fails closed at
  `NewL8DurableService`. A missing provider still returns
  `ErrL8RecoveryDependency` when retained credential ownership exists.
  Complete-identity restart calls `RecoverJobCredentials` then always
  `StopReapJobCredentialRuntime`. Seed-only restart skips Recover and begins
  at stop/reap. Both routes validate absence, finalize, persist a private
  recovery receipt, commit, then clear credential state. Daemon restart never
  resumes execution. A restart from the private receipt-only crash state binds
  the exact seed and calls only the idempotent commit operation before clearing
  the receipt; it does not recreate process, L7, or credential cleanup work.

## Still unsupported / documented gaps

- The worker-v2 protocol schema still has only `job_start_v2`,
  `job_resolve_v2`, `job_status_v2`, `job_logs_v2`, and `job_cancel_v2`.
  There is no reserved `job_renew_v2` or `job_revoke_v2` operation. Renew is
  available on the in-memory session handle only; it is not a protocol
  heartbeat yet.
- `job_resolve_v2` and `job_logs_v2` remain unsupported on the L8 durable
  router. `job_status_v2` is not wired in this slice.
- Prepare uses the complete identity only. Admission-authorizer and live
  `LiveSecretSource` resolution are not injected here; v2 production files
  forbid that live-secret surface.
- Default `Service` and `NewL8Service` stay inert: they do not prepare, and
  the non-durable seam still aborts preflight.

## Fake-only commands

```
go test ./internal/sandboxworker -run 'L8|JobV2|JobStartV2' -count=1
go test ./internal/sandboxworker -run 'TestL8D6Worker(Prepare|Cancel|Loss|ConcurrentStart|TypedNil|MissingRecovery|SeedOnly|CompleteIdentity|IdentityMismatch|ProtocolHasNo|NeutralService|PersistsSeed|ConcurrentReplay)' -count=1
go test -race -count=1 ./internal/sandboxworker -run 'TestL8D6Worker(ConcurrentStart|ConcurrentReplay)'
go vet ./internal/sandboxworker
```

This slice does not claim L10/L11, live Firecracker, or production absence-proof
construction. Worker tests mint absence proofs only inside fakes.
