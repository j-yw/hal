# Retained controller admission deadline

Based on `2d91b1d18671c8a2721dd01ead69f0e22c129bab`, with compiling RED frozen at
`2c6723ebf87159595ae2ac2395dd2e6e28093961` and the narrow GREEN described below.
The accepted [controller contract](sandbox-runtime-v2-minimal-host-auth-controller.md)
already distinguishes absolute admission A/D from authenticated hard lifetime H.

`minimalControlController.authenticate` returns the exact final A after the
original caller/transport D and prelude five-second clamp. At the RED base, `run`
checked that A before local readiness publication, then discarded it. A later first
original-channel `HLMINRD1` readiness handoff must still enforce the remaining A/D;
reconstructing A from `WaitReady`, a receipt timestamp or a fresh five seconds
would enlarge the original budget.

The GREEN copies the returned A, unchanged and before local
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
The dedicated 120-line RED and original 354-line controller RED remain unchanged,
as do wire/crypto, `Current`, lifetime handling and unavailable runtime dispatch.

```sh
go test -race -p 2 -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControlControllerReadiness(RetainsAdmissionDeadline|CurrentUsesHardLifetime)$'
```

Observed RED: both retained-deadline cases complete actual authentication and
then observe the absent zero deadline; the H-lifetime control passes. Fake process
bookkeeping and caller-UID Unix fixtures are not prepared-Linux Jailer evidence.
The only GREEN production change stores the exact returned A alongside the other
readiness scalars before publication. Event-deadline enforcement remains absent;
the future first handoff must consume this deadline, not create a new budget.
