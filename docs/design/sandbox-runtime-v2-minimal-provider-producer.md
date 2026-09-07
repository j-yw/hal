# Selected minimal provider and retained asset handoff

Design only at `b8b9cd2c0f0d2947947e9823c862b508d64f403f`. This refines the
[controller handoff](sandbox-runtime-v2-minimal-host-controller.md), under the
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md).
No provider, producer, recovery authority, default selection or test is added.
Preparation, supervisor event publication and controller integration remain
their existing owners' dependencies. Prior-epoch restart remains conditional.

## Smallest adapter and existing boundaries

Implement one constructor-injected provider in
`internal/sandboxruntime/microvm/firecrackerhost/minimal_launch_provider_linux.go`
(proposed), satisfying the existing `sandboxruntime.MinimalJobRuntimeProvider`.
Keep its selection and partial owner private. Reuse the existing authorizer,
reservation, worker manager, L7 coordinator, Jailer supervisor and cleanup client;
do not introduce a second registry client, manager, store or proof issuer.
Its prepared-host constructor supplies the retained owner directory/root key,
executable pins and Jailer host/UID policy, never worker-request paths or labels.
The selected schema requires daemon UID 0; this is not rootless Podman activation.

| Boundary | Existing source/API | What it establishes |
| --- | --- | --- |
| OCI selection | `sandboxtemplate/selection.Workflow.Select`; `acquisition/registry.Resolver.ResolveOCIArtifact` | Measured template manifest/document and selected immutable references, not possession of the referenced minimal image |
| Local assets | `localresolver.VerifyL8MinimalDistributionBundle`, `TakeLaunchLease`, `VerifiedL8MinimalLaunchLease.ConfirmCurrent/WithAssets` | Independently pinned seven-file minimal bundle plus genuine retained L7 parent; callback-scoped measured readers |
| Launch admission | `MinimalLaunchAuthorizer.ResolveSelection`, `Reserve`, `ArmDispatch`, provider binding `Start`, reservation `ClaimLaunch` | Original authenticated principal/scope, exact durable dispatch barrier and one launch claim; not preparation success |
| Network preparation | `l7network.Coordinator.Prepare`, `Session.LaunchDescriptor/ProcessNamespace` | Actual prepared topology and revocable namespace duplication, not guest-bound enforcement |
| Local process construction | Existing sealed snapshot helpers and eight-role admission; private `newMinimalControlLinuxRuntime` | Retained files, full config correlation and namespace/config equality; not active readiness |
| Authenticated readiness | `withMinimalControlController`, `WaitReady`, `Current`, `Loss`; `HLMINRD1` codec | Only current `authenticated_minimal_control`, after actual retained transport and complete transcript |
| Cleanup | Existing J `StopReap/Finalize/Commit`, L7 cleanup, neutral owner binding `Finalize` | Each component's exact owned cleanup; plain receipt fields cannot establish whole-job authority |

Paths above are under `internal/`; host APIs below are under
`sandboxruntime/microvm/firecrackerhost/` unless stated otherwise.
The actual executable still selects `unavailableMinimalControlSupervisor`
(`l8_runtime_owner_executable_linux.go`). The controller and event codec are
implemented components, not a selected production provider or event receiver.

## L9 selection to real assets

Reuse the existing OCI workflow and its bounds, origin policy, digest checks,
cache and tag-mutation checks. Its resolver fetches a template layer; it does
not download or retain the kernel/rootfs named by the template. `selection.Result`
is public mutable metadata. `runtime.launch.descriptorRef` is an immutable
reference shape, not a decoder for a minimal bundle or a B1 issuance capability.

The first local handoff needs a trusted constructor-owned association between
the exact selected template manifest/descriptor identity and:

- the independently retained `minimalprofile.Receipt.Expected`, produced by
  the accepted source build, never reconstructed from candidate JSON;
- the configured minimal bundle and verified L7 parent locations, whose actual
  files are then acquired by `VerifyL8MinimalDistributionBundle`; and
- exact template/workspace/network policy scope and runtime selection identity.

No such selected-template-to-minimal-bundle association is implemented today.
Before adding an adapter, approve its narrow constructor input and digest
meaning: OCI template manifest, any OCI runtime manifest, minimal distribution
documents and raw rootfs bytes are different objects, not interchangeable hashes.
A local trusted policy entry can explicitly bind these existing values; an
untrusted worker `TemplateLock`, candidate receipt, diagnostic image, or a source
catalog alone cannot fill that entry. Fetching arbitrary minimal archives from
`descriptorRef` would require a separately specified artifact format/acquisition
slice, not a new permissive mode on the template resolver.

`ResolveMinimalSelection` performs only trusted selection and file acquisition,
not VM/network/workspace preparation. Its private selection retains the exact
verified distribution and immutable expected policy/identity. `Current` compares
the original selection and actual retained assets; after lease transfer it uses
that lease, not a reopened directory or a copied planning descriptor.
`SelectL8MinimalDistribution` is planning-only and fails after transfer.

At claimed Start, transfer the distribution once with `TakeLaunchLease` and
snapshot kernel/rootfs inside `WithAssets`, using existing
`snapshotJailerRecoveryAsset` limits (128 MiB/4 GiB) and sealed read-only memfds.
The callback readers expire at return, including panic; never keep them or
derive a pathname to reopen. Confirm source/parent currentness through handoff.
Transfer lease ownership explicitly from selection to partial owner so closing
selection aliases cannot close an owner's sources. Report close uncertainty.
`jailer_recovery_producer_linux.go` already performs this snapshot pattern for
the seven-role route; add a selected sibling, not seven-config relabeling.

## Inputs missing from the neutral handoff

Two small contracts must be reviewed before a complete producer can compile:

1. `minimal_launch.go` selection hints and reservation identity omit the
   original credential `AdmissionGrantID/AdmissionRevision`; the worker has them
   in `handleMinimalLaunch` and stores the request's credential intent. The
   provider cannot recover those values from its arguments. Add a narrow copied
   request-correlation projection through the existing authenticated reservation
   chain, covered by its request key and exact service readback. Do not pass raw
   Exec/env/secrets, substitute `LaunchGrantID`, or add a provider-side lookup
   registry. These values are intent correlation, not completed credential grant.
   The exact requested immutable template identity also needs comparison with
   the trusted selection; policy-ID equality alone does not compare image bytes.
2. `Reserve` creates `reservation.Context()` with the preparation deadline.
   That is the provider's only owned context. It cannot represent continued
   service/authorizer/explicit cancellation after preparation expires: ignoring
   `DeadlineExceeded` loses later revocation on an already-closed channel.
   Separate retained owned cancellation from the existing absolute preparation
   budget within the same reservation, preserving current launch checks. Do not
   detach using `WithoutCancel`, tie ownership to an RPC waiter, or reset expiry.

Neither change authorizes credentials, prior-epoch recovery, a terminal write,
or a new public JSON field. Their exact interfaces require their source owner's
approval; this note does not supply missing values in a fixture constructor.

## Concrete producer ownership sequence

1. Validate the exact provider-owned selection, original reservation and
   preparation budget; call `ClaimLaunch` before the first host allocation.
   Retain one partial owner with the original identity before invoking any
   allocating dependency. Every later error/panic returns that owner; it never
   retries launch or substitutes a new runtime generation.
2. Prepare the genuine L7 session using independently selected policy/ten-field
   identity. Retain partial `Session` even on error. Take its opaque descriptor,
   `ProcessNamespace(identity)` and `DuplicateForNamespaceProcess()` pair;
   validate actual kinds and capture the same user/net device+inode tuple in
   sealed config and bootstrap SCM_RIGHTS. Never reopen `/proc` using labels.
   One consumer of `Session.Loss()` fans loss into owned cancellation. Descriptor
   creation is snapshot-only and not a fresh full L7 inspection.
3. Snapshot assets and the pinned owner executable. Generate one bounded
   host-only Ed25519 seed, public key, boot nonce and genuinely owned boot/key
   generations; no credential value is involved. Follow the existing one-call
   nonblocking entropy pattern; short/error/unavailable entropy fails without
   retry/fallback or leaked reader goroutines. Render the six L7 boot keys,
   then call shared `minimalcontrol.RenderBootCommandLine` last. Seal the final
   FC config only after rendering; retain exact 4095-byte combined boot budget,
   NIC equality, rootfs identity and independent namespace tuple.
4. Seal canonical eight-role public config with its complete digest and the
   separate FC-config digest. Reuse first seven roles on FDs 3–9; FD10 is exactly
   one 32-byte read-only, unlinked, CLOEXEC, write/grow/shrink/seal-sealed seed.
   Use distinct owned descriptors, close every partial import, wipe all private
   copies on every result, and never inherit seed into the Jailer/guest child.
   Loader admission consumes FD10 before its callback. The actual runtime serves
   inside that callback's lifetime so the controller's borrowed key cannot escape.
5. Start the one existing runtime-owner executable/channel and retain its actual
   process observation, owner directory and reconnect client. The selected
   sibling must retain the original parent seqpacket after exact revision-2
   bootstrap reply; the legacy helper's unconditional deferred close stays
   unchanged. Preparation/gate cancellation and immediate reply are dependencies,
   not permission to activate the currently unavailable entrypoint now.
6. One post-reply receiver checks bounded `HLMINRD1` on that exact channel,
   independently observed supervisor/config and all retained pins. Reconstruct
   the shared binding using only its two actual late generations and require
   the session-bound digest. Reject/close unexpected rights, truncation, replay,
   duplicate/extra messages and EOF. Continue one joined loss reader after
   readiness; the pure decoder is not that stateful receiver. Waiter cancellation
   only stops waiting. Owned cancellation revokes first, shuts down I/O, joins
   tasks outside owner locks and contains through the same supervisor.

The 25 prelaunch values have only these sources:

| Values | Source |
| --- | --- |
| sandboxId, executionId, workerId, hostId, runtimeId, runtimeGeneration, workerJobId, submissionId, planId, jobGeneration, principalId | Exact claimed reservation, originally checked selection and authenticated worker entry |
| runtimeDriver | Selected constant `microvm` |
| templatePolicyId, workspacePolicyId | Original authorizer scope/selection, compared with request |
| admissionGrantId, admissionRevision | Missing narrow original-request projection above, unchanged |
| bootGeneration, imageGeneration, imageDigest | Actual one-shot boot and trusted image selection; digest is measured rootfs SHA256, not an OCI manifest digest |
| networkPlanId, policySnapshotId, proxySessionId, proxyGenerationId, topologyGenerationId, ruleGenerationId | Original genuine L7 session/plan identity, independently selected before Prepare, not generated to satisfy a codec |

`processGeneration` and `vsockGeneration` are deliberately absent before launch.
The surviving supervisor obtains them from its same retained coordinator process
and raw-stream correlation, not producer guesses. The accepted controller owns
startup retries and transcript deadlines; event send/receive must preserve the
remaining admission budget, without resetting the owner/transport hard lifetime.

## Cleanup handoff is a separate required slice

`l7network.New` requires real guest-isolation and VM-termination verifiers even
for a coordinator used initially for Prepare. Existing production verifiers in
`l7_live_composition.go` accept the legacy bridge/lifecycle-specific bindings;
minimal readiness cannot masquerade as either. A real selected J termination
adapter and later actual raw-packet inspection remain missing. Prepared TAP/rules
and authenticated control alone must not call `InspectAfterGuestReady` as proof.

Before any launch attempt, genuine pre-VM failures may use `AbortBeforeVM`.
After a possible launch, locally latch that crossing even if no readiness was
published; L7's pre-VM bit alone is insufficient because it is cleared at guest
inspection. Quarantine first, then exact J stop/reap, then correlated
`CleanupAfterVMQuiesced`. Never infer absence from EOF, a deadline, missing record
or cleanup metadata. Keep the exact owner and occupancy on every uncertainty.

`jailerRecoveryClient.stopAndCommit` validates FinalizeAck/current record, then
immediately sends Commit. A provider must not use it unchanged and return a
receipt after its recovery record is retired. Required later ordering is:
validated J finalization and real L7 cleanup -> provider receipt -> worker
receipt persistence/CAS/readback -> exact owner's Commit acknowledgment -> final
worker terminal persistence. Existing neutral `Finalize` has no acknowledgment
method for that middle boundary; a narrow retained-handle commit handoff must be
reviewed with the terminal worker writer, not inferred from receipt fields.
L7 journal retirement/crash windows likewise require its real cleanup provenance;
an absent journal alone cannot be upgraded to successful cleanup on restart.

`RecoverMinimalJob` remains unavailable until exact original provider/identity,
J reconnect and L7 cleanup authority can be reacquired. It never resolves a new
selection, prepares L7, generates a seed, boots, authenticates a guest or replays
work. Neutral recovery wrappers and prior reserved-record syntax do not grant
prior-store authority. Partial/unproven recovery stays quarantined.

## First dependency-ordered RED batches

1. **Retained local selection/claim boundary:** after approval of the trusted
   L9 association, add the private provider selection and actual neutral
   Reserve/Arm/Start fixture. Use real verified local bundles, then replace or
   mutate child/parent files before Current, transfer and snapshot. Assert zero
   allocation for wrong scope/template/image/unclaimed/replayed/revoked input;
   exact once-only transfer and expired-reader/close behavior on the valid path.
   A compiling unavailable Start seam must be reached after successful real
   selection controls; it cannot prove later producer/cleanup negatives.
2. **Request/lifetime projection:** actual-service tests preserve the original
   credential and template correlation into that provider, reject mismatches
   before allocation, and prove preparation expiry prevents late launch while
   post-ready owned cancellation still works. No terminal schema activation.
3. **Eight-role producer:** actual snapshot/render/seal path with ordinary
   memfds, private socketpairs and namespace FDs, injected process launch only.
   Inspect all eight roles and exact bytes at the actual admission boundary;
   cover every partial failure, cancellation, successor-FD canary and retained
   partial client. No privileged constructor acceptance is inferred from fakes.
4. **Original-channel readiness and cleanup:** after supervisor dependencies
   are accepted, test actual reply/event/EOF sequencing with shared guest crypto,
   then receipt-before-Commit and L7 cleanup crash windows through the actual
   service/owner. Keep unavailable until each prerequisite is reached and proven.

Candidate files are dedicated `firecrackerhost/minimal_launch_provider*.go`,
`minimal_control_producer*.go` and `minimal_control_readiness_receiver*.go` plus
adjacent tests; any neutral request/lifetime, J-client acknowledgment, L7 verifier
or worker terminal edit requires its own reviewed coupled slice. No source-guard
exception is preapproved. This document is verified by source inspection and
`git diff --check`; no executable test, live boot, OCI pull or cleanup ran here.
