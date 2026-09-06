# Sandbox Runtime v2 L8-D7 Jailer Prerequisite Foundation Verification

## Status and authority

This note verifies the package-private Jailer foundation at
`41ac0cd332d9533b3105cfd38438e1e27709c892`, the implementation head before
the verification-only commits. It records code that exists at that exact head;
it is not prepared-host evidence and does not enable a runtime.

The architecture decision remains in
[`sandbox-runtime-v2-host-owned-strict-boundary.md`](sandbox-runtime-v2-host-owned-strict-boundary.md).
That historical note is pinned to the earlier `3713cdda` baseline and remains
the authority for why the host-owned Jailer direction was selected. This
document preserves that implementation status without rewriting the trail.
The following executable-handoff increment supersedes only the historical
executable gap; it is not prepared-host acceptance.

## Executable-handoff increment

The private coordinator now calls `inspectAndPinStrictJailerHost`. The original
read-only inspector remains metadata-only. The new composition reopens each
no-follow source, requires the same inspected inode and trusted ownership,
copies at most 128 MiB per executable into an anonymous Linux memfd, measures
that copy against the separately configured digest, and seals writes, growth,
shrinkage, and further seal changes. Both initial inspection and copying have
bounded reads. A source replacement, changed bytes, unsafe ownership, missing
seals, or failed acquisition returns a sanitized failure and no launch owner.

The coordinator carries this private pair through the existing lifecycle. The
real starter requires exact Jailer/Firecracker path correlation and duplicates
both snapshots atomically with close-on-exec before launching. The creating
thread creates a separate mount namespace and makes its mount tree recursively
private **before** binding either sealed snapshot over its configured canonical
executable path. Bind mounts are read-only, nosuid, and nodev. After both binds,
the runner rechecks canonical paths, trusted root-owned directory chains, and
the exact mounted inode pair; only then can foreground exec proceed. Existing
host/jail path correlation and the Firecracker basename remain unchanged.
The source paths and parent directories remain trusted host administration
inputs; this is not protection against a malicious host root administrator.

This is necessary because upstream Jailer canonicalizes `--exec-file` and then
reopens that canonical path while copying Firecracker into the chroot. Merely
retaining a source FD or passing a memfd proc path as `--exec-file` would not
preserve the existing canonicalized path/basename contract. See the upstream
[path validation](https://github.com/firecracker-microvm/firecracker/blob/v1.15.0/src/jailer/src/env.rs#L264)
and [executable copy](https://github.com/firecracker-microvm/firecracker/blob/v1.15.0/src/jailer/src/env.rs#L430).
These source references explain the handoff; they do not verify a prepared
host's configured binary pair.

No executable, namespace, or asset descriptor is inherited across Jailer exec.
The original snapshot pair is closed on every coordinator return; the launch
duplicates are closed on every starter return. On success, the child and its
retained creating thread hold the private mounts until process exit. On any
mount, inspection, or exec failure the locked thread is retired without being
reused, releasing its private namespace, including any partial bind. There is
no host-wide mount mutation or path-based cleanup of these anonymous snapshots.

The default tests exercise actual unprivileged memfd sealing, source replacement,
read bounds, independent descriptor ownership and close behavior, plus injected
mount and launch ordering/failure paths. They do **not** execute privileged
mounts, start Jailer, or prove kernel mount/exec behavior on a prepared host.
The remaining prepared-host lane must verify that actual canonicalized
`--exec-file` consumption sees only the pinned bytes, including replacement
attempts, and that partial mount namespaces disappear after failure. Dedicated
UID/GID authority, post-drop containment, cgroups, readiness, network topology,
durable recovery, and selected live acceptance remain blockers.

## Historical implemented private foundation

All of these components remain private to
`internal/sandboxruntime/microvm/firecrackerhost`:

| Component | Implemented boundary | Truth limit |
| --- | --- | --- |
| Host inspection | The read-only host inspector checks canonical configured paths, trusted root-owned directory chains, separate expected SHA-256 identities, and safe numeric runtime identity inputs. | Inspection closes the opened binaries before launch and is not a pinned executable handoff or live proof. |
| Staging | The retained-dirfd stager exclusively creates one private jail generation, caps inputs at one GiB per staged resource and four GiB in aggregate, copies and measures the correlated config, kernel, rootfs, and support files, and retains cleanup authority over that exact root. It retains exact root authority when staging and initial cleanup both fail. After creating a runtime or root directory, it attempts exact empty-directory rollback when a creation check fails and returns a non-nil retry lease only when that rollback is incomplete. Creation-time quarantine removes only exact verified empty directories; unexpected descendants keep cleanup fail-closed. Before finalization, cleanup removes only identity-recorded staged entries and quarantines unexpected/unrecorded descendants; recursive deletion of unrecorded Jailer output is reserved for a fully finalized generation. An opened directory exact identity/type is verified before any metadata mutation; the initial opened file's pathname and FD are revalidated for exact identity, regular-file type, and single-link state before its first chmod and ledger insertion; every recorded intermediate parent and retained file/link authority is revalidated immediately before nested/file mutation. The same-UID check-use race remains an explicit dedicated/quiescent UID prerequisite. Pinned retries remain directory-handle-bound, while unresolved identity blocks reuse rather than guessing by path. For a fully staged and finalized generation, terminal cleanup recursively removes correlated staged content and Jailer-created runtime output without following symlinks. It rejects whitespace-bearing or endpoint-overlapping jail paths before filesystem mutation. | The byte budgets bound staging I/O; they are not guest runtime or cgroup enforcement, and staging proves the files it created rather than that a later live Jailer consumed them. An authority that cannot yet be revalidated remains quarantined and blocks reuse. This revalidation does not provide durable recovery or live proof. Creation quarantine is private and in-memory only and does not provide durable crash recovery. |
| Namespace launch | The network-only direct `setns` runner changes only the locked creating OS thread's network namespace, keeps initial-user-namespace root, requires a close-on-exec namespace descriptor before the exec boundary, passes an empty environment and no asset descriptors, and starts the foreground Jailer. | It has deterministic process and descriptor tests, but no prepared-host execution proof. A future provider must still duplicate the namespace descriptor atomically with close-on-exec. |
| Process lifecycle | The private strict Jailer lifecycle atomically carries the structured launch plan, authoritative host cleanup paths, and expected runtime UID through start, inspection, stop, and uncertain-start cleanup. It retires the exact terminal process record only after terminal root release and treats closed process completion as terminal proof regardless of exit status. | It owns process lifecycle state; it does not prove guest or vsock readiness. |
| Composition | The private strict Jailer coordinator validates canonical JSON field casing and config/resource correlation, permits only correlated log, metrics, and optional initrd files, rejects network-interface and non-empty entropy configuration, accepts the existing renderer's exact empty entropy object, inspects, stages, re-verifies the retained root, plans, starts, stops, and retries cleanup for one active or cleanup-pending generation. | It is the full private coordinator for this prerequisite foundation, but it is not constructed or selected by a default production runtime path. Network-enabled composition needs a typed, live-topology-correlated config handoff. |

The compatibility `NamespaceProcessRunner` and direct Firecracker compatibility
behavior is unchanged. The new runner does not reinterpret the legacy
user/network/kernel/rootfs descriptor contract.

## Historical blockers and remaining acceptance

The following are required before this foundation can support a strict runtime
claim:

1. A prepared initial-user-namespace-root live host must prove that the exact
   foreground Jailer can enter the retained network namespace and create its
   required devices and mounts. Unit coverage of the network-only runner is not
   that host proof.
2. A dedicated UID/GID authority must prove that the configured non-root
   identity is reserved for the run. Numeric validation and propagation do not
   establish dedication.
3. The measured executable handoff above must be accepted on prepared Linux.
   The historical read-only digest inspection alone still cannot authorize
   pathname execution; the real starter now rejects a missing pinned pair.
4. The required post-credential-drop crash containment must be demonstrated or
   replaced by a retained supervisor design. The locked-thread parent-death
   signal protects the foreground launch boundary, but Linux may clear it when
   Jailer changes credentials.
5. The expected-runtime-UID vsock readiness path must be composed with the
   strict process identity. Expected-UID state and socket cleanup checks exist,
   but the coordinator does not attach a production readiness session.
6. A typed network topology handoff must correlate the exact Firecracker
   interface configuration with the retained namespace generation and active
   policy proof. Until then, the foundation rejects network-interface and
   entropy configuration instead of accepting opaque device input.
7. The required runtime and cgroup resource controls must be configured and
   inspected. The new staging byte caps bound input copying only; positive guest vCPU and
   memory values are config correlation, not host runtime bounds.
8. The required durable crash reconciliation must reuse the runtime-owner and recovery
   layers to rediscover or safely quarantine a strict process and jail root
   after daemon restart. Within the live process, unresolved identity remains
   fail-closed and blocks reuse. Neither the private coordinator nor retained
   directory descriptors survive daemon restart or constitute durable crash
   recovery.
9. A no-skip prepared-host lane must prove boot, readiness, isolation, negative
   cases, and zero owned-resource leaks. The prepared-Linux acceptance has not
   run.

Existing strict runtime selection remains unchanged and default-off. No command,
factory, scheduler, worker, public metadata, evidence schema, L10 composition,
or L11 closure path consumes this coordinator.

No L8, HL8E, L10, or L11 claim is made.

## Default fake-safe verification

The focused checks are deterministic and select no live tags:

```sh
go test -count=1 ./cmd -run '^TestL8JailerFoundation'
go test -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(InspectStrictJailerHost|OSStrictJailerHostInspection|PlanStrictJailerLaunch|StrictJailer|StageStrictJailerResources|ValidateJailerStagingResources|JailerStaging|LinuxJailer)'
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Report `golangci-lint` only when `command -v golangci-lint` succeeds and the
installed tool itself completes successfully.

These checks validate contracts and compilation. They do not boot a VM, start
Jailer, or produce prepared-host evidence.

## Optional future prepared-Linux acceptance

A later implementation may add
`internal/sandboxruntime/microvm/firecrackerhost/jailer_live_acceptance_test.go`
with the exact build constraint
`linux && firecracker_live && l8_jailer_live` and the selected test
`TestL8JailerPreparedLinuxAcceptance`.

That file and selected test are not present at the implementation head. This
verification slice does not introduce a runnable live command and records no
live result. A future selected-test wrapper must discover the test exactly once,
reject missing prerequisites, and reject every skipped event. A skip would not
be acceptance evidence.

## Non-claims

This foundation does not establish:

- prepared-host boot, guest readiness, network enforcement, credential
  delivery, workspace integrity, or leak-free teardown;
- prepared-host executable pinning, dedicated host identity allocation, post-drop orphan
  containment, or runtime/cgroup resource-bound evidence;
- strict runtime selection, a public runtime capability, or a security posture
  upgrade;
- L8 acceptance, HL8E issuance, L10 live composition, or L11 final closure.

Rollback remains simple because no production selector consumes this code:
remove or disable the private composition call site in a future integrating
slice while leaving the existing direct compatibility runtime unchanged.
