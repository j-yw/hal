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
