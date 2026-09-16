# Minimal Linux workload isolation verifier

## Scope and contract

This slice starts at `8b8ccc77ad7ba3fcd7050ef6b13534b8e92c86e4` and implements
only the concrete no-request verifier required by
`sandbox-runtime-v2-minimal-workload-control.md`. The Linux completion
architecture and L8 minimal contract reset remain controlling. The independent
authenticated workload transport RED is intentionally still unresolved here.

Add `NewLinuxWorkloadIsolationVerifier(LinuxIsolationVerifierOptions)` returning
the existing `WorkloadIsolationVerifier` interface. Linux construction requires
a configured, non-typed-nil network verifier. An absent/typed-nil process
boundary retains the existing constructor's live local-process default. Both
constructors are inert: they do not inspect a process or open a raw socket.
The new constructor fails closed with unsupported-platform metadata off Linux.

The selected wrapper has no legacy `VerifyIsolation` method and constructs no
`IsolationProofRequest`. Move the existing Linux verifier body unchanged into
one private method. Both public interface methods delegate to that same body.
Retain exact status size/format validation, all four UID/GID values of 1000,
all five zero capability sets, no-new-privileges, empty supplementary groups,
and only EPERM/EACCES raw-socket denial. Network status must be verified with
all three existing topology/proxy facts. Boundary errors stay redaction-safe.

The legacy constructor still permits missing network inspection and returns
process-only results with network unavailable. Preserve existing nil-context
normalization, callback order, context checkpoints and error precedence. In
particular, the existing body returns a snapshot if its final network callback
cancels the context but returns valid results; the selected server's existing
post-callback context/lifecycle checks must reject that snapshot for work.
This factoring does not make a snapshot continuous authority or change legacy
cancellation behavior. Every invocation runs the same checks again.

## Red-first verification and limitations

Commit this design, then a compiling unavailable implementation and deterministic
equivalence tests, then the minimum shared-body implementation. Each case runs
the actual old entry first and checks independently specified results, errors
and callback order; the selected entry must match. Cover every property/failure
branch, absent/typed-nil network configuration, process-default construction,
nil/pre-canceled/expired contexts and cancellation after each boundary. Preserve
all existing tests, source guards and schemas. Add no production fixture hooks.

Focused equivalence and unchanged selected dispatch tests run under the race
detector, followed by the entire server package, relevant unchanged command
guards, vet and Darwin compilation. Fakes replace the existing three process
operations and network verifier only. No test in this slice invokes live raw
sockets, process privilege changes, mounts, network namespaces or a VM.

There are no new wire/durable schemas, resources, cleanup owners, retries,
credential authority, command routing or image claims. The later guest command
must inject the actual L7 verifier from its retained validated boot/proxy
configuration. Actual Linux backend/workspace, fresh image, prepared guest,
transport/host ownership and live workload/credential/terminal acceptance remain
separate requirements. This API alone does not complete L8, L10 or L11.

## Compiling RED checkpoint

The selected Linux constructor currently returns an inert unavailable wrapper;
its method never invokes a boundary. The off-Linux constructor preserves the
existing unsupported-platform error. The legacy Linux body is byte-identical.
Across three race repetitions, the 78 independently specified legacy cases
pass and the corresponding selected cases fail at the absent result/callback
order. The network-required constructor and retained-boundary/fresh-inspection
tests also fail. Including nested parent test events, the focused command has
480 expected failures, 237 passes and no skips. No race report is emitted.

```sh
go test -p 2 -race -count=3 -timeout=180s -json ./internal/sandboxruntime/microvm/guestagent/server -run '^TestWorkloadLinuxIsolation'
```

The nil/zero selected verifier control fails closed. Fresh-inspection mutation
checks after the initial success are specified but cannot yet be reached. These
results do not claim the shared-body GREEN or the pending transport is usable.

## Shared-body implementation

The selected constructor now requires the network dependency and retains the
same concrete inspector as the legacy constructor. The two wrappers delegate
to one private inspection body, byte-identical to the original body at the
base above. The selected wrapper exposes no legacy request method. All old
tests and the 291-line Linux RED remain unchanged.

A forward test runs the concrete inspector against explicit fake boundaries
inside actual selected `Server.Serve`. It proves the final-callback canceled
snapshot cannot authorize exec, a subsequent invalid network observation still
rejects work, and a later fresh valid observation can recover the original
permit. The real serving lifetime joins and closes its fake backend exactly
once. Another test checks that neither constructor inspects an explicit process
or network boundary.

The unchanged fake-only command guard rejected the new `!linux` test tag.
With supervisor approval, its identical test body moved to Darwin and Windows
filename-selected tests. No assertion, production behavior or guard changed.
Cross-compiling these tests does not execute unsupported-platform behavior.

Full server race testing (three repetitions) passes 1,314 test/subtest events,
with no failures or skips. The unchanged focused command guards pass 75 events
under the race detector. These scoped checks do not hide the separately run
original authenticated-transport RED: it still fails three times as expected,
after authentication/readiness with zero backend exec calls. No branch-wide
green, usable workload transport or live Linux acceptance is claimed.

## Integration diagnostic source-lock follow-up

The full default suite at `33248091` rejected the accepted shared-body source:
the legacy D7 workload lock still pinned the original `isolation_linux.go`.
Refresh that exact measured L4 file digest in both the workload lock and the
generator's exact-value table. Build the generator twice with the unchanged
pinned Go recipe, require byte-identical binaries, and retain their measured
digest. Regenerate only the existing HL8Q/source-lock outputs and the downstream
native-role artifact's embedded policy identity through their existing tools.
The syscall catalog, role rules, runtime/L7 pins, source-set membership, native
source/callsites, compiled filter and D4 installation inventory stay unchanged.

```sh
tools/microvm/l8/policy/verify-artifact.sh
go run ./tools/microvm/l8/role-bootstrap/generate -check
go test -race -count=3 ./tools/microvm/l8/policy/generate ./tools/microvm/l8/role-bootstrap/generate ./internal/sandboxruntime/microvm/guestagent/syscallpolicy
```

This refresh preserves the original deterministic-output and fail-closed HL8E
tests, including `TestL8D7PointerTakenPID1Report`. Temporary default diagnostic
fixture compilation/execution is not a native image build or VM acceptance.
No accepted verifier implementation, source guard, prepared image, syscall
policy behavior, HL8E issuance, runtime wiring or strict-security claim changes.
