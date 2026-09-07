# Retained controller admission deadline

DESIGN/RED only, based on `2d91b1d18671c8a2721dd01ead69f0e22c129bab`.
The accepted [controller contract](sandbox-runtime-v2-minimal-host-auth-controller.md)
already distinguishes absolute admission A/D from authenticated hard lifetime H.

`minimalControlController.authenticate` returns the exact final A after the
original caller/transport D and prelude five-second clamp. `run` currently checks
that A before local readiness publication, then discards it. A later first
original-channel `HLMINRD1` readiness handoff must still enforce the remaining A/D;
reconstructing A from `WaitReady`, a receipt timestamp or a fresh five seconds
would enlarge the original budget.

The smallest proposed GREEN copies the returned A, unchanged and before local
publication, into private `minimalControlReadiness.admissionDeadline`. No accessor,
clock injection, new timer, codec field or generic readiness authority is needed.
The field is immutable with the other published readiness scalars. The later
selected owner must independently require `now < admissionDeadline` at first
handoff alongside all actual owner/channel/generation checks. This change does
not implement that handoff, adoption, selected constructor or producer protocol.

`Current` continues checking H and actual local stream correlation, not A. After
successful admission, the authenticated stream must not expire merely because
the earlier admission budget ended. Retaining A neither creates a credential
grant nor establishes live VM, network, resource-cleanup or producer authority.

The compiling RED adds only the zero-valued private field. Actual sealed-admission,
retained Unix and shared guest crypto tests require short D to survive exactly,
and long D to retain the prelude five-second clamp. Existing per-instance owner
observations bracket that clamp and delay actual prelude delivery, distinguishing
it from a later Hello/Ready-time reconstruction without a production clock seam.
Repeated waits must return the same deadline and handle. A separate passing
control waits beyond short D and checks that local `Current` still uses H.
The original 354-line controller RED and all protocol/runtime code stay unchanged.

```sh
go test -race -p 2 -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControlControllerReadiness(RetainsAdmissionDeadline|CurrentUsesHardLifetime)$'
```

Expected RED: both retained-deadline cases complete actual authentication and
then observe the absent zero deadline; the H-lifetime control passes. Fake process
bookkeeping and caller-UID Unix fixtures are not prepared-Linux Jailer evidence.
Stop after freezing this RED for review; production GREEN is separately approved.
