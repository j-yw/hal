# Selected minimal config and seed admission

## Status and exact boundary

DESIGN/compiling RED at base `14608af2a2e63e52e46a457ac41f5b71f2dcb89c`.
This implements no selected supervisor, store, controller, producer or launch.
The [accepted controller design](sandbox-runtime-v2-minimal-host-controller.md),
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.

The actual private `supervise` dispatcher imports its existing six roles first.
An additive private hook, supplied only by the Linux wrapper, may select the
eight-role admission. Its result prevents six/seven fallback on selected failure;
absent hooks and the child-gate paths preserve existing dispatch. The first RED
adapter invokes the existing selected decoder: it rejects the new discriminator
before extra imports. Positive tests therefore fail at the real admission gap,
not at an invented successful runtime. Every later validation negative first
requires a successful fresh admission; until that prerequisite passes, the
negative itself is explicitly NOT covered.

Allowed files are new `minimal_control_config*`, `minimal_control_seed_linux*`,
this note and the small hook in `l8_runtime_owner_executable{,_linux}.go`.
The ordinary production consumer always returns unavailable, even after GREEN
admits bytes. The observer in tests substitutes only that unavailable consumer.
It must never return a production supervisor success or issue readiness.

## Selected public schema

The discriminator is exactly `jailer-runtime-owner-minimal-control-config-v1`.
Reuse the existing job/policy/path/asset **data shapes**, with a distinct version
and exact eight-role list; do not convert the input to a seven-role config or
invoke its accepted decoder by relabeling. The extra `minimalControl` object has:

- exactly 25 public prelaunch pins, validated through the shared minimal boot
  renderer; neither late process nor vsock generation is supplied;
- canonical public key, key generation and boot nonce;
- the reservation's positive absolute preparation deadline, launch grant ID and
  canonical positive launch policy revision, distinct from credential intent;
- exact NIC/six-static-field public projection and nonzero, distinct user/network
  namespace device/inode tuples, to bind to actual transferred namespaces later.

The complete object is bounded by the existing 32 KiB config limit and must
equal its typed canonical JSON encoding. Missing/null/duplicate/unknown/aliased
fields, wrong types/order/trailing bytes and inconsistent redundant job/runtime/
image values are rejected. Root-daemon/nonroot-workload host policy stays fixed.
The private admission digest is SHA-256 of the **entire original canonical
eight-role config**, never a seven-role projection, serialized override, private
seed or key digest. No public boot map or key is added to cleanup records.

## FD ownership and seed lifetime

Roles remain FD 3 control socket, 4 owner directory, 5 supervisor config,
6 kernel, 7 rootfs, 8 stable owner root key, 9 final FC config, 10 controller
seed. The Linux wrapper owns and marks 9/10 CLOEXEC before any duplication that
could reuse these numbers. Select from the bounded sealed config only, never
from presence of FD 10. Reject absent/swapped/extra roles, aliases, wrong measured
asset identity/digest and malformed selected config without six/seven fallback.

The seed has exactly 32 nonzero bytes in a regular unlinked read-only FD with
the existing exact required seal set, CLOEXEC, trusted UID and mode 0400. The
dedicated loader allocates one 32-byte scratch array and makes exactly one Pread
at offset zero. Derive the Ed25519 key, compare its public key with sealed pins,
clear scratch on every path, and consume/close the seed before the observer.
Read/close errors must not expose a key. The callback-scoped private key is
cleared after either observer success or error. Close each partial import once;
do not close a successor that reuses the consumed seed FD number.

Tests use real ordinary Unix socketpairs, directories, files and sealed memfds.
Production passes fixed trusted seed UID 0; the test seam passes the real
unprivileged fixture UID to exercise actual kernel metadata without claiming root
admission. The serialized root-daemon policy is not rewritten for these tests.
No namespace transfer, mounted asset, privileged operation, execution or real
credential is involved; public deterministic seed bytes are test fixtures.
Retaining the scratch slice tests its actual zeroing, not physical memory erasure.

## Required coupled next slice, still unavailable

`jailerRecoveryStore`, `encode/decodeJailerRecoveryRecord` and the selected runtime
currently hardcode seven-config validation/digests. They cannot consume this
admission by simply changing its version or supplying a replacement digest.
A subsequent source-owner-reviewed private projection must let the same retained
store bind its current correlation field to this complete admitted config.
No generic store schema or record fields change in this first slice.

The same next slice must validate the sealed NIC/static expectation against
actual FC bytes without fabricating `l7network.LaunchDescriptor`, and match the
SCM_RIGHTS namespaces against the frozen tuple. Exact live L7 authority remains
with the original producer. This admission alone validates neither current L7
ownership nor guest boot. Preparation deadline expiry/cancellation must be checked
at the later allocation/release barriers, not inferred from the positive integer.
Producer/seed construction, actual ExtraFiles noninheritance to Jailer, original
channel lifetime, gate cancellation, full controller handshake and provider
readiness handoff remain explicit dependencies. No credentials, enforcement,
cleanup, readiness, VM or complete Sandbox v2 claim is made here.

## Focused RED verification

```sh
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControl(Config|Seed)'
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(L8RuntimeOwnerExecutable|L8RuntimeOwnerLinuxExecutable|JailerRecoverySelectedConfig)'
go vet -p 2 ./internal/sandboxruntime/microvm/firecrackerhost
git diff --check
```

The first command must compile and fail for absent actual admission/seed loading.
Legacy sentinel controls and existing exact ABI/decoder tests must pass. The
dedicated private seed-helper negatives separately require actual Pread/close
observations; an unconditional unavailable stub is not counted as their success.
After reviewed GREEN, retain all RED assertions and run affected race, source
guards and Darwin compilation before integration-owned broader gates.
