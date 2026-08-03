# Sandbox Runtime v2 L8 Production Credential Delivery Verification

## Scope

This note verifies issue #49 L8 against
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. L8
produces live, job-scoped HTTP, tmpfs-file, and SSH-agent activation evidence.
It does not select the strict default; L10 consumes the resulting proof.

Default tests are fake-only. They do not open listeners, resolve or dial
destinations, read host agents, create mounts or namespaces, start a runtime,
access KVM, or read raw configured secrets. Live behavior is isolated behind
explicit build tags and prepared-host opt-in markers.

A selected live test that skips is a failure, not a pass.

## Design and source guards

The design gate locks package ownership, lifecycle states, separate
active/cleanup proof kinds, failure codes, strict worker and guest protocol v2,
no-downgrade behavior, the neutral L6 route seam, exact non-MITM HTTP protocol,
initial Pi service/consumer and numeric limits, Linux-keyring byte source,
anonymous locked memory, authenticated v2 vsock, dedicated guest identities,
fd-confined privileged helper/cgroup cleanup, restricted SSH relay,
finalization/recovery ordering, and the L10 handoff:

```sh
go test -count=1 ./cmd \
  -run '^TestL8CredentialDelivery(Architecture|Verification|DefaultGuards|SourceGuards.*)$'
```

Guards must prove:

- `internal/credentialdelivery` and `internal/sandbox/credential_proxy*.go`
  remain metadata-only;
- default L5/L7 runtime and worker constructors cannot import or construct L8
  live adapters;
- command and factory paths cannot transport raw credential bytes, callbacks,
  endpoints, or tickets in worker requests;
- `sandboxjob-v1` cannot accept or ignore production credential intent;
- v1 guest behavior and no-credential JSON remain compatible;
- handoff, simulation, env, and legacy activation cannot project L8 live
  proof;
- test-only service registries and live fixtures cannot enter production
  composition; and
- live test markers remain behind their exact build tags.

## Focused fake-only gates

The exact package set grows as D1-D6 land, but every final selector must match
at least one named L8 test:

```sh
go test -count=1 -timeout=240s \
  ./internal/credentialmemory \
  ./internal/credentialsource \
  ./internal/credentialproxy \
  ./internal/credentialdelivery \
  ./internal/factory \
  ./internal/sandboxruntime \
  ./internal/sandboxruntime/networkenforcement/applicationroute \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server/... \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./internal/sandboxworker \
  ./internal/sandboxexecution \
  ./cmd -run '^TestL8'

go test -race -count=1 -timeout=360s \
  ./internal/credentialmemory \
  ./internal/credentialsource \
  ./internal/credentialproxy \
  ./internal/sandboxruntime/microvm/guestagent/... \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./internal/sandboxworker \
  ./internal/sandboxexecution -run '^TestL8'

go test -count=25 -timeout=420s \
  ./internal/credentialmemory \
  ./internal/credentialsource \
  ./internal/credentialproxy \
  ./internal/sandboxruntime/microvm/guestagent/server/... \
  ./internal/sandboxworker -run '^TestL8'
```

Required focused areas are:

- lifecycle transition tables, idempotence, correlation, replay, revision,
  expiry, loss, mutually exclusive active/cleanup proofs, and cleanup ordering;
- safe-reference-to-keyring registry admission, direct syscall read into locked
  memory, replacement/revocation/permission races, no
  string/environment/file/subprocess/factory ingress, page-lock
  success/failure, full-capacity overwrite, unlock/unmap, borrowed-view sink
  bounds, daemon-start dumpability, cancellation, and non-stringability;
- `sandboxjob-v1` compatibility, distinct `job_*_v2` operations, strict `sandboxjob-v2`,
  credential-aware idempotency/request keys,
  unknown/duplicate/trailing JSON rejection, exact legacy unsupported-operation
  envelope, unsupported-v2 failure, no v1 retry, and client-loss recovery;
- guest-v1 compatibility, exact guest-v2 negotiation including only the bounded
  old-server error envelope, host-CID validation, signed X25519 transcript,
  AEAD sequence/replay/tamper/unauthorized-host negatives, no fallback, strict
  frames, and cross-job negatives;
- neutral route dispatch/collision/close ordering, exact deployment-prefixed
  reserved HTTP framing, fixed ticket encoding/lease/request/concurrency and
  body/response/SSE/idle limits, initial Pi Azure Responses clean-environment
  flags and sealed model, post-admission in-memory binding without RPC/job
  mutation, service catalog, HMAC digest, raw HTTP/1.1 mutable auth emission,
  destination/TLS policy, redirects, header control, L7 proof races, and generic
  CONNECT noninterference;
- dedicated agent/workload identities, non-dumpable/protected-proc agent,
  exact-PID/UID/GID/pidfd helper IPC, fd-root/pivot/seccomp loss behavior,
  cgroup race-free placement, tmpfs namespace/mount/openat2 behavior,
  ownership, linkage, path races, partial prepare, fixed resource limits,
  file-generation policy, `setsid` escape,
  `cgroup.kill`/zero-population proof, normal unmount, keeper reap, whole-VM
  fallback, and restart cleanup;
- neutral SSH codec, authenticated relay subkey, SCM_RIGHTS handoff,
  backpressure, mandatory key and algorithm/flag allowlists, filtered
  enumeration, per-connection host-agent identity, exact relay limits, loss,
  and absence proof;
- Firecracker process/vsock/network/credential generation composition;
- worker prepare-before-exec, heartbeat renewal, loss cancellation,
  revoke-before-terminal behavior, state-write failures, daemon close, and
  restart reconciliation;
- L3 finalization ordering with optional `CredentialCleanup` nil for
  compatibility, required before artifacts for live intent, and the existing
  post-publication sync-out recovery exception; and
- sanitization across manifests, worker state, status JSON, factory records,
  timelines, logs, errors, artifacts, and sync-out.

## Reproducible L8 guest assets

L8 guest protocol and filesystem/relay behavior must be present in immutable
guest assets. L7 artifacts and digests remain unchanged. L8 emits a distinct
profile and descriptor whose provenance records the exact source commit/tree
and parent L7 profile inputs without host paths.

The official verifier performs two independent offline builds with the pinned
local builder, no network, no pull, private output roots, and byte comparison
of every exported artifact:

```sh
tools/microvm/l8/verify-reproducible.sh \
  --cache "$HAL_L8_BUILD_CACHE" \
  --output "$HAL_L8_DISTRIBUTION"
```

The final-image verifier proves the exact v2 guest agent/init/helper binaries,
dedicated agent UID/GID 998 and workload UID/GID 1000, PID1 helper launch before
agent privilege drop, protected proc, exact helper capability/pivot/seccomp
policy, empty agent/workload capability sets, controller-public-key boot input
without private material, L7 network profile, absence of
setuid/setgid/file capabilities, private filesystem modes, required
tmpfs/fd-mount/pidfd/mount namespace and cgroup-v2/`cgroup.kill` kernel support,
and absence of embedded secret/test keys. Test probes are copied into the
workspace through the existing bounded guest copy contract; they are not
installed in the production image and cannot manufacture proof.

## Prepared-Linux prerequisite gate

Before the selected E2E begins, a separate no-skip prerequisite test proves:

- Linux amd64, writable KVM, pinned Firecracker, writable TUN, and working
  vsock;
- the exact fresh digest-locked L8 distribution;
- L7 namespace, nftables, pasta, local topology, and active-inspection
  prerequisites;
- mount namespaces, normal tmpfs mount/unmount, boot-time cgroup-v2 delegation,
  race-free job placement, `cgroup.kill`, and `populated 0` inspection;
- sufficient `RLIMIT_MEMLOCK`, successful page locking, no active swap,
  disabled core dumps, and non-dumpable live helpers;
- an owned session-keyring entry readable only by the worker identity, direct
  keyctl access without a subprocess, and cleanup of the owned test key;
- local `ssh-agent`/`ssh-keygen` tooling for an owned disposable agent;
- owned local verified-TLS HTTP fixtures and resolver namespace with no internet route; and
- an owned controller signing key and credential value in private test
  keyrings, followed by revocation/removal proof.

```sh
go test -race -count=1 -timeout=5m \
  -tags='firecracker_live network_enforcement_live l7_linux_network_integration l8_production_credential_delivery_live' \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^TestL8PreparedLinuxCredentialDeliveryPrerequisites$'
```

Missing or inadequate prerequisites fail. They never call `t.Skip` after the
test is selected.

## Selected prepared-Linux E2E

List and run are separate gates so the build expression and exact test name
are auditable:

```sh
go test -list '^TestL8PreparedLinuxCredentialDeliveryE2E$' \
  -tags='firecracker_live network_enforcement_live l7_linux_network_integration l8_production_credential_delivery_live' \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  | grep -qx 'TestL8PreparedLinuxCredentialDeliveryE2E'

go test -race -count=1 -timeout=20m \
  -tags='firecracker_live network_enforcement_live l7_linux_network_integration l8_production_credential_delivery_live' \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^TestL8PreparedLinuxCredentialDeliveryE2E$'
```

The one selected test contains subtests for HTTP only, file only, SSH only,
all three together, and the required failure/recovery matrix. Every subtest
uses a fresh sandbox/runtime/job generation.

### HTTP fixture

The fixture is an owned local TLS upstream in an isolated namespace on a
locally assigned address that production classification treats as globally
unicast. A test-only trusted CA and sealed fixture service entry are injected
through test constructors; production destination checks are not weakened.
The upstream verifies the expected transformed canary and TLS server identity.
The exact production Pi binding generates the reserved base URL, sealed API
version, and ticket environment from a clean allowlist against the compatible
fixture entry without a billed call; inherited provider variables, direct Pi
`xai`, arbitrary base URLs, and `--api-key` are negative cases.

Negative cases cover wrong deployment/version/model, Pi ambient configuration
and missing hardening flags, pre-admission or serialized ticket injection,
malformed/expired/hard-expired/over-count/concurrent tickets, bad roots/server
identity, plaintext downgrade, redirect, authority mismatch, userinfo,
competing/duplicate authentication headers, unsupported method/path,
request/response/event/idle overflow, mixed unsafe DNS, NAT64 unsafe
translation, ticket replay in a second job/runtime, L7 loss before lookup, and
L7 loss between lookup and upstream write. A CONNECT echo fixture proves opaque
bytes and zero credential lookup/injection.

### Tmpfs fixture

The intended v2 job reads its file through a copied workspace probe. Same-UID
agent attacks are impossible because the workload has a distinct UID; forged
SCM credentials/PID/nonce, proc/ptrace/process-memory/pidfd-getfd access,
neighbor job, v1 exec, stale generation, traversal, symlink/hardlink, and
post-revoke reads fail. Live inspection proves the private mount namespace,
tmpfs type and flags, file mode/owner/link count, bounded contents, helper
privilege/root/fd/seccomp boundary, race-free cgroup membership, normal unmount,
keeper reap, zero population, and absence after cleanup. A copied child calls
`setsid`, retains a descriptor, and must still die through `cgroup.kill`; forced
cgroup-inspection failure must stop and reap the entire microVM.

### SSH fixture

Before mode subtests, an unauthorized host-side vsock peer, wrong CID fixture,
wrong signing key/generation, transcript replay, bad AEAD tag, and sequence gap
must all fail before guest mutation. An owned disposable host agent receives
one allowed and one forbidden generated test key. A copied guest workspace
probe lists only the allowed identity and signs only an allowed
challenge/algorithm through the job relay. Empty policy,
the forbidden key/flag, agent-peer replacement, neighbor job, stale capability,
v1 exec, and forbidden agent operations fail. Loss and cleanup prove host
connection/listener and guest socket absence. Private key bytes never enter the
guest or any scanned surface.

### Terminal and restart matrix

Each mode and the combined case cover success, nonzero exit, prepare failure,
partial prepare, renew failure, expiry, cancel, timeout, guest loss,
Firecracker exit, L7 loss, proxy/relay loss, state-write failure, daemon close,
daemon kill/restart, repeated recovery, and repeated revoke. No case may publish
success or begin artifacts while cleanup is incomplete.

After every case, scan durable state and inspect live resources. All owned
containers, Firecracker processes, helpers, listeners, connections,
namespaces, mounts, keepers, cgroups, sockets, rules, routes, locks, leases,
tickets, buffers, and sessions must be absent. Historical or unrelated
resources are observed but never removed without exact ownership proof.

## Broad and portability gates

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run gofmt verification over every tracked Go file. If `golangci-lint` is
installed, run it and distinguish pre-existing repository debt from changed
code; the Make target's missing-tool hint is not a pass.

Compile affected packages on Linux, Darwin, FreeBSD, and Windows. Linux-only
live constructors have explicit non-Linux fail-closed files. Cross-compilation
does not imply a non-Linux credential-delivery security claim.

## Review and evidence

At least one fresh Hal review child must finish on the exact phase head with no
valid issue and no tracked/untracked worktree mutation. A second independent
manual/security reviewer classifies every candidate with file/line evidence.
Generated patches are untrusted and never committed directly.

Issue evidence records the exact aggregate base, design/red/implementation/fix
commits, phase head, aggregate merge, reproducible artifact digests, commands
and exit states, selected subtest count and zero skips, reviews, rejected
findings, cleanup counts, remote SHA, PR checks, and L10 handoff. It omits
credentials, secret/ticket/key material, raw destinations, endpoints, sockets,
hostnames, paths, PIDs, inode/device IDs, rule bodies/handles, and host identity.

## Non-goals

L8 does not make env or legacy auth strict, accept arbitrary HTTP destinations,
MITM TLS, forward unrestricted SSH-agent operations, persist secrets, change
template trust, select the secure default, upgrade rootless isolation, call a
cloud provider, or contact the public internet.
