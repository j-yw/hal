# Selected pre-exec input assembler

Design only, from `62112a273e913ced98345b928f9c131581dc6bb5`.
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md),
[claimed asset handoff](sandbox-runtime-v2-minimal-template-association.md),
[seed producer](sandbox-runtime-v2-minimal-controller-seed-producer.md), and
[supervisor composition](sandbox-runtime-v2-minimal-supervisor-composition.md)
govern. This note authorizes neither implementation nor a RED before review.

## One missing edge, not another runtime

Extend the SAME `minimalTemplateAssetOwner` returned by actual binding.Start
with one retained pre-exec attempt. It already owns the genuine Claim, original
template/request, one transferred lease, and measured sealed kernel/rootfs.
Never call `launchJailerRecoverySupervisor`, transfer again, resnapshot those
assets, or construct another process manager, selection, or runtime owner.

The first slice has **no production caller**. Its private preparation entry is
called explicitly on that original owner in tests; existing Start still returns
owner plus `ErrMinimalLaunchUnavailable`. Preparation is not recovery from that
error and does not turn it into successful Start. It produces no process, work
carrier, readiness, active network proof, credential authority or cleanup receipt.
The next selected producer must consume these exact retained inputs, not copy a
prepared-looking result into another owner.

Proposed package-private shape, all in `firecrackerhost`:

```go
newMinimalPreexecHost(context.Context, *minimalLaunchProvider, minimalPreexecHostInputs) (*minimalPreexecHost, error)
(*minimalPreexecHost).close() error
(*minimalTemplateAssetOwner).prepareMinimalInputs(*minimalPreexecHost) error
```

The preparation method obtains context/P exclusively from the owner; it accepts no
replacement deadline, request, Plan, Session, descriptor or config. Nil error
means only its attached input assembly finished; it is not the neutral Start
result. No public prepared-FD constructor, provider hook, job registry, mutable
policy lookup, new neutral interface, schema discriminator or default selector
is part of this slice. Off Linux, no usable assembler exists.

## Trusted host constructor and lifetime

`minimalPreexecHostInputs` consists of deployment-owned inputs, never request
JSON, Exec/env, OCI document fields or candidate image metadata:

| Input | Source and retained meaning |
| --- | --- |
| Jailer policy and guest resources | Copied `jailerRecoveryHostPolicy`, positive vCPU/memory, fixed base boot arguments and jail path base; independent installed Jailer/Firecracker digests, UID/GID slot and trusted anchors |
| Network policy | An explicit association from scope.NetworkPolicyID to the configured policy snapshot/version and actual allowlist rules, plus the existing proxy/topology/TAP/rule tool paths and bounded options |
| Owner-state root | A preprovisioned private root directory, opened by the deployment through `openL8RuntimeOwnerDirectory`; retain its actual device/inode and a validated owned CLOEXEC duplicate |
| Stable recovery key | A deployment-provisioned, borrowed regular file handle; exact UID 0, mode 0600, one link, size 32 and stable identity under the existing key validator; retain an owned duplicate, not key bytes |
| Supervisor executable | A genuinely sealed executable snapshot plus independently trusted expected SHA256, produced with `snapshotStrictJailerExecutable` from the deployment's trusted source; verify actual snapshot/digest and retain a same-object duplicate |

The constructor fixes root trust to actual effective UID 0. It rejects a copied
provider/host, invalid or incomplete association, unsafe paths, wrong metadata,
typed-nil dependencies and host lifetime loss. The host stores the original
provider pointer and immutable complete scope/template association; preparing an
owner from a same-label replacement provider is forbidden. Deployment must own
the state-root/key/executable provenance and their acquisition lifetime; names,
matching labels or the ability to open a path do not supply that association.
No key provisioner or accepted native build receipt is invented here.

Before the constructor performs a duplicate/other allocating operation, retain
its own partial host object. Capture every returned FD even with an error; close
only owned duplicates on failure, return the partial host on cleanup uncertainty,
and leave it unusable for preparation. Borrowed input handles remain untouched.
Reject aliases to borrowed inputs or occupied slots without creating a second
owning wrapper around the same descriptor number.
Use the existing executable snapshot validator plus bounded positional hashing
against the independent digest, with context checks around read stages. Do not
resnapshot a valid immutable executable per job. Stable-key byte reading and its
separate hygiene correction remain the existing receiver's responsibility; do
not copy that reader into the assembler or derive the ephemeral seed from it.

A short host mutex serializes borrowing against host close, not network calls
or joins. Each admitted job retains its own duplicates of root/key/executable;
host close blocks new borrows, cancels the host lifetime and closes host-owned
copies after existing borrows finish. It cannot invalidate job-owned copies.
Those copies still require cleanup by the original job owner. Host cancellation
retires preparation; it neither silently detaches a job nor proves its cleanup.
Borrowed network callback capabilities must outlive all uses/cleanup; closing a
shared caller capability is not a job cleanup action.

The supervisor's original `assembleJailerRecoveryLinuxRuntime` and coordinator
already reserve the UID, record busy ownership, inspect/pin Jailer/Firecracker,
and prepare cgroup/staging/launch. Do not duplicate those authorities upstream.
Host policy validation and an executable snapshot are not UID reservation or
proof that the VM executable ran.

## Genuine per-job L7 construction

Copy the configured policy through `NewPolicyProxyPolicyInput` and existing plan
copy/sanitization helpers. The trusted association binds the scope policy name
to its actual snapshot and rules; neither name alone nor a public Plan creates
a policy. Sanitization must not silently repair contradictory configured intent.
The fixed selected intent is deny-by-default with HTTP/HTTPS through the proxy
and firewall apply, satisfying existing `planMatchesIdentity`; no advisory
fallback. Credential application routes are absent, not synthesized.

Derive the four job identity fields from the original Claim: sandbox, execution,
worker and runtime generation. Retain the independently configured policy
snapshot identity. Issue fresh network PlanID, proxy session/generation, topology
generation and rule generation for this job, independently of the launch PlanID.
Require the existing ten-field distinctness and shared 1–64-byte boot grammar.
Do not truncate/hash invalid supplied IDs into acceptance. Fresh public tokens
and boot nonce use bounded nonblocking entropy, independent of the seed and
stable key; failed/zero draws or collisions reject without retry/fallback.

For each attempt, construct the actual `policyproxy.New` adapter for that exact
copied per-job policy/Plan and `l7network.NewProductionProxy`, the existing
`linuxtopology.New`/`NewLinuxTopology`, `NewLinuxTAP`, and
`linuxrules.NewProductionExecutor`/`NewAdapter`. Use the existing journal store
and configured bounded cleanup. Construct one `l7network.Coordinator` per job:
it retains one current Session and is not a shared multi-job scheduler. Tool
paths, resolver/dial and observation dependencies are trusted constructor inputs;
production defaults remain actual implementations, not fixture verifiers.

There is a real selected-verifier gap. Old `productionL7GuestIsolationVerifier`
and `productionL7VMTerminationVerifier` require private old-runtime bridge and
tracker bindings, not selected public metadata. The existing cleanup/recovery
binding is not a new selected guest verifier either. This **pre-exec-only**
constructor hardwires explicit incapable guest/terminal verifiers returning
fixed errors; it never accepts success-shaped replacement proofs or invokes
InspectAfterGuestReady/CleanupAfterVMQuiesced. These satisfy dependency presence,
not production readiness. Real selected bindings must replace this boundary in
a separately reviewed slice before ANY exec can be wired to this assembler.

Call real `Coordinator.Prepare` using the original bounded preparation lifetime.
Retain every nonnil Session before checking its accompanying error. Successful
host preparation must have the exact identity, host_prepared state and no guest
raw-packet proof. Obtain both `LaunchDescriptor(expected)` and
`ProcessNamespace(expected)` from this same retained Session. Retain the actual
user/network duplicates returned by that namespace view; measure those exact
FDs with existing nsfs identity/pair checks and NS_GET_NSTYPE user/net checks.
Never reopen a namespace path or duplicate an unrelated descriptor as authority.
The same measured duplicate objects must later cross BootstrapStart.

One attempt-owned consumer observes the Session's Loss notification, records a
monotonic lost latch and cancels preparation; it does not enter Finalize or join
itself. A descriptor is a snapshot, not currentness. Recheck the retained Session
handoff, loss latch, contexts and namespace identities before prepared-input
publication and again at the eventual exec boundary. None is active enforcement
proof. An empty loss channel alone is not a liveness test.

## Exact config and descriptor assembly

Store the exact `reservation.Context()` and its original time.Time deadline P
on the asset owner at Claim, alongside unchanged OwnedContext. Never calculate
P from now or OwnedContext; retain its local monotonic component for admission.
Only UnixNano is serialized into the existing selected config.

Build exactly these 25 prelaunch values; the shared renderer owns their grammar:

| Keys | Independent source |
| --- | --- |
| sandboxId, executionId, workerId, hostId, runtimeId, runtimeGeneration, workerJobId, submissionId, planId, jobGeneration, principalId | Original claimed identity |
| runtimeDriver | Fixed `microvm` |
| admissionGrantId, admissionRevision | Original RequestCorrelation, canonical positive decimal revision |
| templatePolicyId, workspacePolicyId | Original provider's trusted scope |
| networkPlanId, policySnapshotId, proxySessionId, proxyGenerationId, topologyGenerationId, ruleGenerationId | Exact retained L7 identity |
| bootGeneration, imageGeneration | Fresh bounded producer correlation tokens |
| imageDigest | `sha256-` plus the independently verified/measured raw rootfs SHA256, never the OCI runtime-image digest |

ControllerKeyGeneration and the fresh nonzero 32-byte boot nonce are separate
public config/session fields, not additional map keys. LaunchGrantID and
LaunchPolicyRevision come from Claim, NOT credential-intent admission fields.
ProcessGeneration and vsockGeneration remain absent until the original
supervisor observes them. Use the accepted dedicated seed owner and its public
key copy; retain its secret FD without exposing bytes or a seed digest.

Use `firecracker.PlanPaths` with the exact claimed runtime ID and configured
jail path base before sealing; never repair paths on an already-launched owner.
Fill the existing strict FC config shape from trusted resource/base-boot inputs,
the original measured assets, exactly one root drive, fixed guest CID/vsock and
the selected entropy-device/PCI requirements. Kernel/rootfs jail paths are fixed
producer paths, not candidate paths. Preserve strict resource/page-size checks.
Use `renderMinimalL7Config` for the exact descriptor NIC/static values, then
`minimalcontrol.RenderBootCommandLine` LAST for the whole-line limit. No manual
second encoder or post-render boot append is allowed.

Seal FC JSON with `sealJailerRecoveryBytes`, retain its actual FD before checking
errors, and measure identity/digest. Build the existing eight-role selected
config with that measurement, original kernel/rootfs measurements, exact network
projection and namespace pins. Reuse `decodeMinimalControlSupervisorConfig`,
`readMinimalControlFirecrackerConfig`, `validateMinimalControlFirecrackerConfig`,
the captured selected expectation and strict coordinator/cgroup validation.
Seal the canonical selected JSON and verify actual readback; candidate FC values
cannot supply their own expected pins. Generic sealing is for public config,
never the seed or stable key. Preserve all byte/asset limits and distinct FD
objects. Receiver admission remains an additional unchanged exec-boundary gate.

After Claim, allocate a private per-job record directory using an exclusive
descriptor-relative mkdir/open under the retained state root, keyed by the
exact safe claimed runtime generation. Retain its identity/FD immediately;
validate 0700/root ownership/CLOEXEC with the existing directory validator and
compare the parent entry to the opened object. Reject preexisting names,
symlinks and replacement; never reopen/reuse as a new launch or recursively
remove a collision. The root is not the per-job record directory. This slice
retains the empty directory on disk for explicit later retirement: closing its
FD is not directory removal, and no cleanup receipt or absence claim is made.
Identity-bound directory retirement/recovery remains part of the subsequent
producer finalization, never a Start fallback on uncertainty.

The input set retains directory, sealed selected config, original kernel/rootfs,
stable-key duplicate, sealed FC config and seed, plus executable and namespace
duplicates. No socketpair or eighth-role exec occurs yet. The later original
control socket completes FD3..10 in the unchanged role order; do not call the
old seven-role command producer or introduce a ninth inherited role.

## Attempt admission and Finalize arbitration

All public identity/currentness/alias rules of the claimed owner remain. Store
P/context during original Start, but do not extend source.mu over host I/O.
Preparation admits once under source.mu: validate self/source/provider/host,
complete immutable association and original claim/template/request, sealed
assets, exact lease, current P and OwnedContext, not closed, no earlier attempt.
Attach the partial attempt, its cancel handle and setupDone before releasing the
lock or entering any allocating callback. The attempt is never reset for retry.

Setup runs synchronously outside source.mu. Its work context is a child of the
ORIGINAL preparation context, canceled also by host/OwnedContext loss and
Finalize. No replacement deadline is accepted. Check absolute P/context before
and after host borrows, callbacks and retained-lease currentness, and after waits.
Capture every returned owner/FD plus error before the next callback; panic
returns only a fixed unavailable error with that same partial owner retained.
Callbacks that allocate then panic before returning own their unreturned state.
Retaining a Coordinator cannot recover an unreturned private Session after an
internal L7 panic; do not claim that the outer panic guard proves its rollback.
Any reached fault requiring such recovery is a separate dependency correction.
No timeout goroutine abandons a callback or descriptor. Ordinary filesystem I/O
and trusted callbacks must finish; context checks do not make them interruptible.
Publish prepared state under source.mu only if the original attempt still owns
the slot and no close/loss/cancellation/expiry won. Always signal setupDone.

Finalize first takes source.mu only to mark the owner closing, retire the
attempt and capture its cancel/done handles. Release it BEFORE cancellation,
observer stops, joins, L7 calls or file/lease cleanup. Cancellation before setup
enters is rechecked before allocation; a callback already in flight must
join before its returned resource can be closed. A caller deadline while waiting
returns unavailable and retains the attempt for a later Finalize, never closes
under its active callback. Concurrent finalizers serialize the cleanup pass
outside source.mu; recheck context after that wait. No callback reenters a held
host/attempt/source mutex. Alias Close never gains the attempt's resources.

After setup joins, close owned prepared FDs, stop/join this attempt's context/
loss observers and call the same Session's `AbortBeforeVM` for actual pre-exec
rollback. Never use it after possible exec. Partial Prepare may have no armed
watcher: do not blindly wait on Loss. For successful Prepare, successful rollback
stops proxy/topology and the existing Session's completed loss notification can
be observed after this attempt's sole consumer has joined. Failed rollback
retains Session/journal/task uncertainty, not a fictional join or absent mapping;
later Finalize may retry that existing rollback. Consume file handles once and
preserve close failures without retrying raw descriptor numbers. Close original
snapshots/lease only after setup no longer borrows them. Successful pre-exec
cleanup still returns zero receipt plus unavailable; it cannot manufacture
OwnerCommitID, FinalizedRevision or whole-job terminal success.

Loss publication means the Session completed its quarantine attempt; it is not
an API joining every underlying task. Its watcher still has function/defer exit
work after publishing. Explicitly join the assembler's own observers; attribute
underlying teardown only to the actual adapter cleanup contracts and reached
tests, never to channel closure alone.

## First RED and bounded implementation ownership

First RED scope is two unavailable source scaffolds,
`minimal_preexec_host_linux.go` and `minimal_preexec_assembler_linux.go`, plus
`minimal_preexec_assembler_red_linux_test.go` and
`minimal_preexec_fixture_linux_test.go`. No existing production behavior changes
in RED. Full GREEN source ownership then adds
`minimal_preexec_config_linux.go` and dedicated sibling forward tests.
The only existing production edits proposed
are original P/context retention and attempt/Finalize arbitration in
`minimal_launch_template_handoff_linux.go`. Existing provider constructor,
selection/neutral contracts, legacy producer, supervisor/seed/config validators,
L7 algorithms, stable-key reader and all earlier RED files remain unchanged.
Any genuinely necessary dependency correction gets its own reproduced RED and
review; do not silently widen this file set.

First freeze unavailable host/assembler scaffolds, not fake successful owners.
Independent controls must execute actual provider Workflow/local verification,
authenticated Reserve/Arm/binding.Start, actual Claim consumption and one lease,
and real sealed-asset/host-FD validators. A separate actual L7 Coordinator control
uses explicit fake proxy/topology/rules, the real LinuxTAP parser with fake command
I/O, and ordinary private journals. Adapt individual existing fixture helpers;
the old config fixture's namespace duplicator deliberately panics and cannot be
used as completed namespace-transfer evidence. New topology fixtures retain real
ordinary user/net namespace FDs, return actual duplicates and record identity;
they do not enter/create namespaces or run tools. All controls close resources
and join their watchers. Lower ordinary-UID helper seams may exercise real local
FD/seed operations; production hardcodes root and cannot accept a fake root
observation. No host/network/native action is selected by default tests.

The first reachable RED is unavailable host construction through the explicitly
ordinary-UID lower helper after those controls. Production UID-0 rejection is a
separate reached control, not a skipped or forged root-positive constructor.
Later same-owner assembly assertions are requirements, not reached evidence yet:
exact 25 fields/P, real namespace/seed/config readback, retained Session/lease,
one attempt, no exec, empty receipt and explicit directory retention. GREEN must
reach them without modifying the original RED. Add reached tests for invalid/
copied/foreign owners, policy versus Plan mismatch, expired P, cancellation while
waiting and before first callback, Finalize/host-close races, returned owner/FD
plus error, partial aliases/panic, namespace/config replacement, seed wipe,
real partial L7 rollback failure/retry, and simultaneous independent jobs.
Count injected boundaries and attempted operations so an early rejection cannot
masquerade as fault coverage. Preserve borrowed/successor FD survival and join
every fixture task; rescue cleanup is not production cleanup evidence.

Run focused and adjacent races, unchanged host/command guards, vet and Darwin
compile on a fixed candidate, then integration-owned broad checks. This design
itself has source-inspection/diff-check evidence only. Actual selected L7 guest/
terminal adapters, trusted provisioning, eight-role exec/original-channel/work
composition, credential delivery, durable directory/terminal retirement and
prepared-Linux no-skip acceptance remain unimplemented here.
