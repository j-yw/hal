# Selected minimal config and seed admission

## Status and exact boundary

Config/seed admission implemented after DESIGN/RED `46a23cdb`, from base
`14608af2a2e63e52e46a457ac41f5b71f2dcb89c`. This implements no selected
supervisor, store, controller, producer or launch.
The [accepted controller design](sandbox-runtime-v2-minimal-host-controller.md),
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.

The actual private `supervise` dispatcher imports its existing six roles first.
An additive private hook, supplied only by the Linux wrapper, may select the
eight-role admission. Its result prevents six/seven fallback on selected failure;
absent hooks and the child-gate paths preserve existing dispatch. The frozen RED
adapter invoked the existing decoder and rejected the new discriminator before
extra imports. GREEN now validates the distinct selected schema and seed at this
same boundary. Every later validation negative first requires successful fresh
admission; these prerequisites now pass and the actual negatives are reached.

Allowed files are new `minimal_control_config*`, `minimal_control_seed*`,
this note, the small hook in `l8_runtime_owner_executable{,_linux}.go`, and the
approved common validation extraction in `jailer_recovery_config.go`.
The ordinary production consumer always returns unavailable after admitting
bytes. The observer in tests substitutes only that unavailable consumer.
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
image values are rejected. A three-level delimiter bound precedes selected
schema decoding. The NIC/static fields are syntax-checked using the existing
guest parser, not correlated with a live descriptor or actual FC boot arguments.
Root-daemon/nonroot-workload host policy stays fixed; the seven-role validator
retains its exact original version/roles/root gate before the common body.
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
at offset zero. Recheck retained identity, seals/flags and private metadata after
that read: seals freeze content but do not freeze permissions. Derive the
Ed25519 key, compare its public key with sealed pins,
clear scratch on every path, and consume/close the seed before the observer.
Read/close errors must not expose a key. The callback-scoped private key is
cleared after observer success, error or panic. A selected observer panic becomes
the same sanitized unavailable error after lexical cleanup. Close each partial
import once;
do not close a successor that reuses the consumed seed FD number.
Every final selected close error, including any first-six import, forces failure
while still attempting the remaining closes. Historical six/seven/child-gate
close-error behavior is unchanged. No duplicate operation exists in admission.

Tests use real ordinary Unix socketpairs, directories, files and sealed memfds.
Production passes fixed trusted seed UID 0; the test seam passes the real
unprivileged fixture UID to exercise actual kernel metadata without claiming root
admission. The serialized root-daemon policy is not rewritten for these tests.
Approved fixture-only correction `07319d6b` explicitly chmods the test directory
0700: Go's numbered TempDir child was 0755 on this host. Existing directory privacy
validation remains enforced, with a real 0755 rejection case. No original RED
assertion changed. Root-key trust and root-supervisor authority remain runtime
dependencies, not facts issued by the ordinary-UID fixture.
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

## Focused verification

```sh
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControl(Config|Seed)'
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(L8RuntimeOwnerExecutable|L8RuntimeOwnerLinuxExecutable|JailerRecoverySelectedConfig)'
go vet -p 2 ./internal/sandboxruntime/microvm/firecrackerhost
git diff --check
```

At frozen RED the first command failed with 96 failing test/subtest events and
11 passing controls, zero skips. The selected-close follow-up additionally
reproduced six actual first-six close-error failures after successful admission,
with two passing FD9/10 controls, before correcting dispatch. GREEN requires all
these tests, the legacy sentinel/ABI tests and actual Pread/close observations to
pass. No unavailable stub is counted as validation coverage. Run affected race,
source guards and Darwin compilation before integration-owned broader gates.
