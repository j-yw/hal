# Minimal controller seed producer

## Authority and boundary

This leaf starts at `5a916ea4dff26596b0ac84bb244bc01f42ef6064`. The
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md), and
[host controller seed contract](sandbox-runtime-v2-minimal-host-controller.md)
govern. It creates the dedicated seed role only. It neither invokes the old
seven-role producer nor takes another lease from claimed assets.

No provider/default activation, L7 preparation, config assembly, executable
handoff, currentness receipt, readiness, credential, or terminal-success claim
is included. Existing entropy, seed receiver, asset copier and guards remain
unchanged. No durable/machine schema changes are needed.

## Private API and ownership

`newMinimalControllerSeed(ctx)` returns `(*minimalControllerSeedOwner, error)`.
The production wrapper fixes trusted UID to **0**, uses only
`minimalControlControllerEntropy`, and supplies actual local syscalls. UID is
never a job or provider option. Ordinary unprivileged tests exercise a private
helper below this boundary with the actual test UID; this is not root admission.

The non-copyable owner retains one `*os.File` and a public `[32]byte` value:

- `publicKey()` returns a copy, not a mutable alias;
- `borrowFile()` returns only its retained read-only descriptor for a future
  scoped handoff, without transferring closure authority: the borrower must
  neither close it nor create another owning wrapper around its FD;
- `close()` consumes its file exactly once and is idempotent, including a close
  error. Nil, zero and copied handles cannot access or close another owner's FD.

These are private package APIs. Calls on one owner are caller-serialized; no
background goroutine, finalization service, or concurrent borrow/close guarantee
is added. A future exec producer must close its owned parent copy after the
handoff; this leaf does not perform that transfer. The seed and derived private
key have no returned accessor, hash,
metadata, error detail, log, or durable representation. Public pins can remain
after closure; descriptor access cannot.

## Creation algorithm and failure ownership

Check a nonnil, live context and required dependencies before allocation. Draw
exactly once into an exact 32-byte scratch array through the existing bounded
entropy adapter; reject error, short/oversized counts and an all-zero seed. No
retry, blocking fallback, recovery-root-key derivation or generic asset copier
is allowed. Derive the actual Ed25519 private allocation once, copy only its
public half, and clear the private allocation and scratch on every reachable
success, error and panic path. This is explicit buffer hygiene, not physical
memory erasure of kernel pages or crypto implementation internals.

Create a genuine `MFD_CLOEXEC|MFD_ALLOW_SEALING` memfd. Own a returned nonnegative
FD immediately, even when a trusted callback also returns an error. Write exactly
32 bytes once; reject short/error writes. Apply exact mode `0400` and the existing
exact four required seals. Reopen that same object read-only with `O_CLOEXEC`;
retain a returned descriptor before checking its accompanying error. Validate
with the unchanged sealed-regular-FD validator and real `Fstat`: regular,
unlinked, exact size 32, exact mode, trusted UID, exact seals, read-only, CLOEXEC,
and the same device/inode as the writable original. Close the writable original
before publishing the owner. Context cancellation observed after any callback
or at final publication rejects and closes all owned descriptors.

Partial aliases are closed once, including a synthetic reopen returning the
already-owned FD. No caller-supplied or unrelated borrowed descriptor enters
this constructor. Close failure is a sanitized failure, not successful creation;
never retry a consumed descriptor number. Callback panic is contained to the
same fixed error after owned cleanup; never retain or format its value.

The lower private helper has narrowly typed entropy, memfd-create, write,
chmod, fcntl, reopen, close-file and derive-key callbacks to observe actual
allocations and inject failures. The production wrapper hardwires them; no
stored provider configuration or alternate validator is introduced. Callbacks
remain trusted, synchronous dependencies. If a callback allocates and panics
before returning ownership, its own unreturned allocation remains its duty.
There are no abandoned goroutines or forced syscall interruption claims.

## RED, GREEN and evidence boundary

First freeze a compiling unavailable-creation scaffold with new tests. A genuine
ordinary-UID memfd plus the unchanged seed loader must round-trip independently,
then actual creator acceptance must fail because no owner is created. Assert
returned public-key correspondence and all descriptor properties directly.

Forward fault tests must include positive reached counters: entropy count/error/
panic/zero, context cancellation, create/reopen FD-plus-error, partial aliases,
short write, chmod/seal/reopen failures, exact metadata drift, close error and
retained scratch/private-allocation wipe. They cannot be called covered when
the unavailable scaffold rejects before reaching the targeted stage. Original
seed-reader and entropy tests are controls, not proof of the new writer.

Stop at frozen compiling RED for independent reproduction. Only then implement
the smallest GREEN and run focused/race tests, original seed/entropy controls,
unchanged source guards, vet and Darwin compile. No privileged test, real VM,
network listener, process launch or external provider is selected.
