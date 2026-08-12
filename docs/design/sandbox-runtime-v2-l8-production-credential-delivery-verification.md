# Sandbox Runtime v2 L8 Production Credential Delivery Verification

## Scope

This note verifies issue #49 L8 against
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. L8
produces live, job-scoped HTTP, tmpfs-file, and SSH-agent activation evidence.
It does not select the strict default; L10 consumes the resulting proof.

Default tests are fake-only except for exact isolated local Unix-socket
protocol tests. Those deterministic framing tests are not live-tagged; they do
not open IP or external listeners, resolve or dial destinations, read host
agents, create mounts or namespaces, start a provider/runtime, access KVM, or
read raw configured secrets. All other live behavior is isolated behind
explicit build tags and prepared-host opt-in markers.

A selected live test that skips is a failure, not a pass.

## Design and source guards

The design gate locks package ownership, lifecycle states, separate
active/cleanup proof kinds, failure codes, strict worker and guest protocol v2,
no-downgrade behavior, the neutral L6 route seam, exact non-MITM HTTP protocol,
initial Pi service/consumer and numeric limits, Linux-keyring byte source,
anonymous locked memory, authenticated v2 vsock, dedicated guest identities,
fd-confined launch/controller/agent/monitor/shim cleanup, restricted SSH relay,
finalization/recovery ordering, and the L10 handoff. Its normative
`sandbox-runtime-v2-l8-helper-syscall-policy.md` and
`sandbox-runtime-v2-l8-guest-extension-seams.md` supplements freeze the exact
role/syscall boundary, extension APIs, live host-agent registry, composition
junction, and image-profile ownership:

```sh
go test -count=1 ./cmd \
  -run '^TestL8(CredentialDelivery(Architecture|Verification|DefaultGuards|SourceGuards.*)|D2(GuestHelper|CredentialClient).*)$'
```

Guards must prove:

- `internal/credentialdelivery` and `internal/sandbox/credential_proxy*.go`
  remain metadata-only;
- every current `cmd` production file, including all `sandboxd*.go`
  composition files, stays free of premature L8 live imports and constructors;
  D4 replaces the blanket only for exact guest-asset entrypoints needed to
  compose the native role bootstrap and guest agent/init/helper, with per-file import and constructor
  allowlists while root command and `sandboxd*.go` files remain forbidden; D6
  then permits one explicit root L8 composition file. Every transition retains
  default-disabled construction tests and rejects L8 imports or constructors in
  every non-allowlisted command file;
- command and factory paths cannot transport raw credential bytes, callbacks,
  endpoints, or tickets in worker requests;
- source-reference and admission-grant IDs remain non-authoritative safe
  identity; production v2 authorization uses a server-derived authenticated
  owner UID/GID principal plus immutable host-admin grant before source
  resolution, rejects missing/mismatched peers, and cannot be selected or
  weakened by repository-controlled fields; same-UID host processes with
  access to the owner-only worker socket are explicitly inside the trusted host
  control-plane boundary, not falsely claimed as isolated;
- D0 locks the complete `sandboxworker-v1`/`sandboxjob-v1` and guest-v1 Go
  field/type/JSON-tag schemas, underlying named scalar wire types, plus existing
  custom JSON methods, and rejects new JSON or text marshal/unmarshal methods,
  against hidden or renamed intent;
  the closure includes every nested root `sandboxruntime` DTO and custom method
  reachable through worker-v1 status, capability, target, security, and
  credential metadata; the first D1
  red/green checkpoint must make the worker decoder reject unknown,
  duplicate, and trailing JSON before any v2 dispatch is added, so v1 cannot
  accept or ignore production credential intent;
- v1 guest behavior and no-credential JSON remain compatible;
- helper and controller send construction deep-snapshot mutable safe result
  graphs, pins canonical length/digest, permits only a bounded full-capacity-
  wiped safe-metadata transmit scratch, keeps private stream/file payloads on
  the locked direct-copy path, and retries `EAGAIN` from the already-filled
  locked slot without re-encoding;
- handoff, simulation, env, and legacy activation cannot project L8 live
  proof;
- D0 fixture-name and test-import barriers remain intact; once the D1 catalog
  exists, its constructor tests and import guards must prove that fixture
  endpoints are defined only in `_test.go` and cannot enter production
  composition; and
- every file that declares either selected prepared-Linux test remains behind
  the exact L8 build tag even if the tag literal is otherwise absent, and all
  other live test markers remain behind their exact build tags.

## Focused fake-only gates

The exact package set grows as D1-D6 land. The authoritative wrapper first
runs `go test -list '^TestL8'` for every selector and fails if any selector
matches no named L8 test; only then does it run the focused, race, and repeated
commands below as JSON streams, waits for every child, and rejects every skip
event:

```sh
tools/microvm/l8/verify-focused.sh
```

The wrapper is the gate; running a skip-blind `go test -run` command by itself
does not satisfy the selector-presence requirement. The D1
`applicationroute` package participates in selector discovery, the focused
run, the race run, and the `-count=25` repeated run.

Required focused areas are:

- lifecycle transition tables, idempotence, correlation, replay, revision,
  expiry, loss, mutually exclusive active/cleanup proofs, and cleanup ordering;
- safe-reference-to-keyring registry admission, direct syscall read into locked
  memory, replacement/revocation/permission races, no
  string/environment/file/subprocess/factory ingress, page-lock
  success/failure, full-capacity overwrite, unlock/unmap, borrowed-view sink
  bounds, daemon-start dumpability, cancellation, and non-stringability;
- authenticated connection-principal derivation from the exact socket peer
  UID/GID, host-admin grant/source ACL intersection before lookup,
  missing/wrong-peer denial,
  principal/grant/source/plan/binding/template/workspace correlation,
  non-enumeration, revision/restart races, repository override rejection, and
  an explicit trusted same-UID host control-plane boundary;
- `sandboxjob-v1` compatibility, distinct `job_*_v2` operations, strict `sandboxjob-v2`,
  credential-aware idempotency/request keys,
  unknown/duplicate/trailing JSON rejection, exact legacy unsupported-operation
  envelope, one-request/one-response Unix connections framed by request-sender
  write-half-close/EOF, mandatory successful official-client half-close before
  response decoding, no dispatch before EOF, prompt missing-half-close cleanup
  on peer close or server cancellation, unsupported-v2 failure, no v1 retry, and
  client-loss recovery;
- guest-v1 compatibility, exact guest-v2 negotiation including only the bounded
  old-server error envelope, fixed ports 1024/1025/1026, the exact 512-byte JSON
  payload request-ID-free compatibility preface/response exception versus a
  4096-byte `HL8H` GuestHello, host peer-CID and
  local CID/port validation, the suite-1 signed X25519 transcript and full
  deterministic vector, HKDF-SHA-256 labels, AES-256-GCM 52-byte headers,
  Finished sequence zero, application sequence one, replay/gap/cap/tamper and
  unauthorized-host negatives, reconnect rejection, no fallback, strict frames,
  exact concrete control request/response/error unions, binding/exec schemas,
  `0x13` private `HL8B` records, and direction-constrained `0x14` binary `HL8S`
  stdin/stdout/stderr streaming, both root/source mode-dependent network
  validators, root/child/session digest conformance, canonical `sha256-`
  guest-image mapping, authenticated preflight-to-complete identity
  construction, private versioned seed/complete-identity persistence and clone
  rules, generated-only `HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy`
  values fixed to the proved L7 base, and cross-job negatives;
- neutral leaf-route registration and composed Registry definition/dispatch
  separation, collision/cleanup-retry ordering, live request and response
  non-serialization, safe metadata bounds, exact exported live target/header
  seam shape, static target formatting and marshal/unmarshal denial, canonical
  bounded ASCII target validation, typed-nil and unstable/panicking header
  rejection, defensive sorted name snapshots and stable positive counts, and
  no Registry-side header-value copy before the selected handler; exact
  deployment-prefixed reserved HTTP target/header-value seam and framing mapped to upstream
  `/openai/v1/responses`, fixed ticket
  encoding/lease/request/concurrency and body/response/SSE/idle limits,
  initial Pi Azure Responses clean-environment flags and sealed model, disabled
  extension/prompt-template/theme/session
  discovery, explicit text-only context/skill workspace policy,
  post-admission in-memory binding without RPC/job mutation, service catalog,
  HMAC digest, raw HTTP/1.1 mutable auth emission,
  destination/TLS policy, redirects, header control, L7 proof races, and generic
  CONNECT noninterference;
- dedicated agent/workload identities, non-dumpable/protected-proc agent,
  controller readiness before gated exact `syscall.ForkExec` service `clone`
  with `CLONE_PIDFD`, authenticated pidfd
  bootstrap after clone and before gate release, exact
  PID/UID/GID/pidfd/nonce/SCM helper IPC, fixed inherited descriptors and
  helper packet codec, exact launch-supervisor/agent-supervisor/monitor codecs,
  process-safe
  helper/client descriptor attestation, exact capability/securebits sets,
  fd-root/pivot/seccomp
  loss behavior, deny-by-default amd64/x32 and pinned Go 1.25.7 syscall-role
  decisions, pointer/provenance reinspection, exact 4 MiB tmpfs ceiling and
  namespace-type inspection, exact 72 KiB body/73,828-byte datagram bounds,
  PID1-owned `CLONE_INTO_CGROUP|CLONE_PIDFD` race-free shim placement,
  launch-bootstrap/launch-base filter ancestry, exact PID1 ambient inheritance,
  native-preopened fixed v1/control/relay VSOCK listeners and steady-agent-only
  acceptance, capability-empty agent bootstrap, pidfd-poll-only agent liveness,
  same-UID-only monitor signaling, cgroup-only UID-1000 workload termination,
  no protocol-FD read before each Go role's
  TSYNC steady/transition-filter commit, native stage-zero raw-syscall golden
  coverage, native-shim namespace entry before Go `CLONE_FS` threads, exact
  post-setns three-capability Go transition plus identity/capability read-back,
  child role-filter ownership, required `CAP_SYS_CHROOT`, monitor-owned tmpfs namespace/mount/
  openat2 behavior and exact proc namespace-handle exception,
  root-owned searchable/non-listable directory and UID-1000 file/socket
  ownership, linkage, path races, partial prepare, fixed resource limits,
  file-generation policy, `setsid` escape,
  `cgroup.kill`/zero-population proof, normal monitor unmount/reap, whole-VM
  fallback, exact numeric helper/job/FD/process/cleanup limits, atomic
  prepare-begin/file/commit correlation, domain-separated bootstrap/manifest/
  transaction digests, exact enum, typed response-union and ExecPlan codecs,
  nested relative-path encoding, opaque `0x17` exec-private transfer,
  rights-free exec requests, per-stream `HL8C`/`0x19 exec_credit` flow control
  over concurrently drained `0x18` exec streams,
  terminal input/output/transaction digests, host-resupplied comparison-only
  replay without a second launch, the pre-production count-trailer
  `stdinTranscriptSHA256` one-pass vector with one immediately wiped payload
  slot and no two-pass/leaf retention, no agent replay retention, local helper-loss
  termination, rollback, and restart cleanup;
- neutral SSH codec, authenticated relay subkey, SCM_RIGHTS handoff,
  backpressure, mandatory key and algorithm/flag allowlists, filtered
  enumeration, per-connection host-agent identity, exact relay limits, loss,
  and absence proof;
- immutable matching helper/client extension registries, typed-nil and
  duplicate-claim rejection, exact helper/client/core/transport/policy/host
  method sets, implementation-ready private-field Core request/result layouts,
  canonical relative-path and one-shot correlation capabilities, synchronous
  borrowed private-binding input, exact receive/send packet unions and
  body/right budget ownership, closed helper-policy operation/rejection and
  failure matrices, D4/D5 import independence, the D6-only process-local composition
  junction and PID1 descriptor attestation, the daemon-owned host-agent live registry with fresh peer proof per
  connection, and D7-only image source-lock/build/profile ownership;
- the helper-Service normative closure: exact Service/ServiceRuntime/result
  APIs, a runtime-owned 30-second cleanup budget without forced-return claims,
  CoreExecution event/body ownership over the full canonical output body,
  non-reassignable lifecycle correlation capabilities whose prepared echo remains
  non-authoritative through repeat Revoke/Inspect,
  context-aware ownership-on-entry for helper live body/right constructors and
  the helper CredentialSink send, exact core/extension capability domains,
  deterministic proof/event labels, reused prepare/exec transaction FSMs,
  fixed non-evicting exec/non-exec ledgers with reserved Revoke ledger capacity
  and the uncached terminal-overflow rule, opaque extension lifecycle with
  Service-only binding mint authority, repeatable absence passes before
  one-time finalization, three-pass cleanup and close correlation, and the
  response-disposition correction;
- the credential-client concrete closure: its one-way read-only `credentialclient -> v2control`
  authority edge with a reverse-import guard,
  D6-issued canonical process-descriptor snapshot,
  D4-owned helper bootstrap before Client construction with operational
  sequences 2/3 and no Client hello/body retention,
  bodyless request-root inspection with active-identity-gated unknown and
  safely correlated malformed-known responses
  and a complete-root versus schema/canonical-decode boundary,
  exact lexical root boundary with canonical key order, compact inspected
  scalars/punctuation, one bounded body value, and EOF,
  initial identity reconstruction and root-digest recheck,
  static formatting and JSON/text/binary denial, specifically marshal/unmarshal denial with seeded nonmutation for inspected and bodyless dispatch values, single-Serve lifecycle and
  racing idempotent drain under the fixed 30-second internal cleanup deadline,
  trusted-dependency deadline conformance plus D6 process/VM kill-reap
  escalation without an in-process forced-return or detached-goroutine claim,
  exact controller/HL8P typed unions with the constructor/dispatch authority split,
  conditional helper request-ID correlation for idle asynchronous event/SSH
  packets and drain-time zero-ID close-notify only, segmented exact-coverage send sinks with direct private-body
  offset writes, intrinsic-only SSH I/O results plus operation/bound validation,
  one-slot body and one-shot send ownership with retained-slot `EAGAIN` retry and
  no re-encoding, full-v2-to-helper manifest projection and ordered proof mapping,
  operation/result/stream/credit correlation, closed
  policy/error matrices with a policy-subset error allowlist, pure v2/helper conversion functions, and SSH connection-capability ownership before and
  after extension transfer;
- Firecracker process/vsock/network/credential generation composition;
- worker durable seed-before-preflight ordering, the exact preflight return and
  ownership matrix, immediate continuously latched loss watching, complete
  identity persistence before source resolution, proof-bearing idempotent
  abort, prepare-before-exec, heartbeat renewal, loss cancellation,
  revoke-before-terminal behavior, state-write failures, daemon close,
  seed-only crash stop/reap, complete-identity recovery, and restart
  reconciliation;
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

The final-image verifier proves the exact v2 guest agent/init/controller,
single-threaded native role-bootstrap, mount-monitor, and workload-shim binaries,
musl target Node 22.22.0, `@earendil-works/pi-coding-agent` 0.82.1 and its
locked dependency-tree digest, root-owned non-setuid `/usr/bin/node` and
`/usr/bin/pi`, and absence of npm cache/config/session material. It also proves
dedicated agent UID/GID 998 and workload UID/GID 1000, PID1 controller launch
before agent privilege drop, protected proc, exact launch-base/controller/
agent/monitor/shim capability and seccomp policies, native no-libc/no-loader/
no-thread bootstrap constraints, exact locked-off setuid fixups,
native fixed VSOCK listener table, native-shim pre-Go namespace entry, empty
controller/agent/workload capability sets, controller-public-key boot input
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
- the final-image Node/Pi files and provenance match the L8 source lock, and
  live guest execution reports the exact locked Node and Pi versions;
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
  keyrings, followed by revocation/removal proof; and
- hardware AES-GCM acceleration visible on the host and inside the exact guest
  used for the strict session.

```sh
tools/microvm/l8/verify-selected-live.sh prerequisites
```

The wrapper hardcodes build tags `firecracker_live`,
`network_enforcement_live`, `l7_linux_network_integration`, and
`l8_production_credential_delivery_live`, and selects exactly
`TestL8PreparedLinuxCredentialDeliveryPrerequisites` for this gate.
Missing or inadequate prerequisites fail. They never call `t.Skip` after the
test is selected. The wrapper captures `go test -json`, waits for the child,
rejects every skip event, and requires exactly one run and pass event for the
selected top-level test.

## Selected prepared-Linux E2E

Discovery and execution remain separate inside the authoritative wrapper so
the build expression and exact test name are auditable:

```sh
tools/microvm/l8/verify-selected-live.sh e2e
```

This mode selects exactly `TestL8PreparedLinuxCredentialDeliveryE2E` under the
same four build tags.
The one selected test contains subtests for HTTP only, file only, SSH only,
all three together, and the required failure/recovery matrix. Every subtest
uses a fresh sandbox/runtime/job generation. The wrapper rejects every JSON
skip event and requires the top-level test plus `http_only`, `file_tmpfs_only`,
`ssh_agent_only`, `all_modes`, and `failure_recovery_matrix` to pass exactly
once after the child process finishes.

### HTTP fixture

The fixture is an owned local TLS upstream in an isolated namespace on a
locally assigned address that production classification treats as globally
unicast. A test-only trusted CA and sealed fixture service entry are injected
through test constructors; production destination checks are not weakened.
The upstream verifies the expected transformed canary and TLS server identity.
The exact production Pi binding starts the locked `/usr/bin/pi` inside the
fresh guest and generates the reserved base URL, sealed API version, and ticket
environment from a clean allowlist against the compatible fixture entry
without a billed call. The fixture must observe the real Pi Azure Responses
request and return a bounded response that Pi consumes successfully. A host
Pi, adapter-only request generator, copied test double, inherited provider
variables, direct Pi `xai`, arbitrary base URLs, and `--api-key` are negative
cases.

The Pi 0.82.1 compatibility probe also locks the path split independently of
the fixture: Pi preserves Hal's runtime-local reserved base, which ends exactly
at `/deployments/<sealed-deployment>` with no trailing slash, `/responses`, or
query. The bundled Responses client appends `/responses`; the Azure client
appends the sealed `api-version` query; and its deployment endpoint set excludes
Responses, so it inserts no second deployment segment. Hal's reserved local
route is therefore deployment-prefixed and queried exactly once, while Hal's
proxy transforms it to upstream `POST /openai/v1/responses`.

Negative cases cover missing/wrong Node or Pi version/tree digest, wrong
deployment/version/model, Pi ambient configuration
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
tmpfs type and flags, file mode/owner/link count, bounded contents,
root-owned mode-0711 traversal directories and UID-1000 socket ownership/mode,
controller/supervisor/monitor/shim privilege/fd/seccomp boundaries, race-free
cgroup membership, normal monitor unmount/reap, zero population, and absence
after cleanup. A copied child calls
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
namespaces, mounts, monitors, cgroups, sockets, rules, routes, locks, leases,
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
