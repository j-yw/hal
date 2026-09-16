# Context-bounded minimal asset acquisition

Base: `74852f74dd7bcb847affe44de10de1675cecd514`. This implements the local
dependency in the accepted minimal-template association design, under the Linux
completion architecture and minimal L8 reset. It does not construct a provider,
equate OCI and raw-image digests, issue build evidence, or activate any runtime.

## API and ownership

Add `VerifyDistributionBundleContext(ctx, request)` and
`VerifyL8MinimalDistributionBundleContext(ctx, request)`. Existing entrypoints
delegate with `context.Background()` to the same algorithm. Nil context fails;
real cancellation/deadline errors retain `errors.Is` identity without exposing
paths or raw filesystem errors. Do not launch a goroutine around verification.
The supplied deadline is never replaced or extended. Synchronous deadline checks
cover the interval before a context timer has published its error.

Thread context through real parent inventory/JSON/checksum/asset hashing, private
L7 lease acquisition and source confirmation, parent evidence measurement,
minimal child pinning, authenticated metadata snapshots and final currentness.
Legacy helpers remain wrappers where their existing callers require them. One
bounded reader caps each underlying regular-file read at 32KiB and checks the
same context before and after it; it must not expose WriterTo/ReadFrom shortcuts.
Existing size/digest bounds and source identity checks remain authoritative.
Parent distribution hashing uses its initial regular-file size as a finite bound
and checks final size/identity; it never hashes a growing file to unbounded EOF.
Metadata remains capped. Parent inventory reads exactly the expected count plus
one, not ReadDir(-1); the existing minimal inventory already has this shape.

All opened partial handles close on cancellation and failure through their
existing owners, and close uncertainty remains an error. A failed minimal
acquisition returns no usable distribution. Successful results keep original
single-transfer semantics; caller cancellation cannot mint replacement authority.
No secret, caller path, or decoded candidate value becomes a trusted Expected.

Context checks bound algorithmic work and observe cancellation after lock waits.
They do not make mutex acquisition or an in-progress local filesystem syscall
interruptible. Regular local filesystem responsiveness remains a prerequisite.

## Authenticated snapshot guard

The old minimal verifier becomes a Background wrapper; its context counterpart
owns the same document loop and calls context-aware decode/checksum helpers.
Each old helper likewise forwards Background to its context counterpart. The
context helpers must obtain an owned, bounded, pin-authenticated byte snapshot
before JSON decoding or checksum scanning. Extend the existing source wiring
guard to require every wrapper edge and context edge, preserving its ban on the
mutable legacy decoder and all behavioral mutation negatives. No exemption.

## RED and verification

First add compiling entrypoints forwarding to the unchanged old verifier. Real
synthetic L7/minimal fixtures establish successful acquisition first; canceled,
expired and nil contexts must then reject with no returned ownership. These
are reachable missing context-admission failures, not yet mid-read evidence.
Commit/run this RED before implementation. Forward GREEN coverage then reaches
real bounded regular-file reads, cancellation within each major acquisition
stage, original deadline, oversized inventory, partial-handle cleanup and
unchanged retained identities. Context observers may only forward a real parent
and invoke its real cancellation at observed call frames; no fake bytes/errors,
mutable deadlines, production hook or abandoned read task.

Run focused and whole localresolver tests/races, authenticated-snapshot/import
guards, affected command guards, vet, Darwin compile, formatting and diff checks.
Evidence records the exact commit, test/pass/fail/skip counts and ownership.
Ordinary local-file tests do not prove native image or prepared-Linux acceptance.

## Implemented checkpoint

DESIGN `8428fcb9` and compiling RED `87f0050b` preceded GREEN. RED ran the
unchanged real acquisition controls under race times three: six control passes,
18 intended failing leaves (27 test/subtest failure events), zero skips. The
original RED file remains byte-identical; it establishes context admission only.

Both APIs now share their original algorithms with legacy Background wrappers.
Actual reads, parent lease/evidence, child pin/snapshot and final currentness
propagate the caller context. Inventory is bounded to expected count plus one;
parent hashing reads its initial finite size and verifies trailing EOF, size and
identity. Snapshot decoding still authenticates exact owned bytes against the
original pin. The source guard now checks all wrapper/context edges and rejects
both old and context-aware mutable legacy JSON decoder calls on this path.
The initially unchanged guard failed at the moved bodies as expected; no
behavioral mutation negative or guard exemption was removed.

Forward tests cancel a real parent after an actual data read in thirteen
acquisition stages, including the child pin after three completed parent pins.
The bounded Context observer logs no stacks and injects neither bytes nor
errors. A successful control establishes every target stage first. Cancellation
returns no usable result, repeated partial acquisitions keep descriptor counts
stable, and a new uncanceled acquisition still verifies the original source.
Other tests inspect the actual file offset after a 32KiB read and canceled next
read, reject excess inventory, and observe the exact measurement task blocked
on its retained parent mutex before the original fixed deadline expires.

Self-review found one new draft ownership error: cancellation in a pin's final
deferred check returned an open pin together with an error, before its caller
could retain it. The actual acquisition regression reproduced one leaked FD.
The corrected defer closes and clears that still-owned pin whenever its final
result becomes an error. The reached return-cancellation regression passes race
times three; it is separate from the earlier read-cancellation evidence.

Final exact Go/test bytes pass 238 whole-package tests and 714 whole-package
race passes across three repetitions, zero failures/skips. The affected command
guard selector below passes 222 tests/subtests; vet, Darwin arm64 compile,
formatting and diff checks pass. Darwin was compiled, not executed; lint is
unavailable. No whole-repository or prepared-host acceptance is claimed here.

```text
go test -p 2 ./internal/sandboxruntime/microvm/assets/localresolver -count=1 -json
go test -race -p 2 ./internal/sandboxruntime/microvm/assets/localresolver -count=3 -json
go test -p 2 ./cmd -run '^Test(Phase41|L8D2ImageProfileMintAuthorityStaysNarrow)' -count=1 -json
go vet -p 2 ./internal/sandboxruntime/microvm/assets/localresolver
GOOS=darwin GOARCH=arm64 go test -p 2 ./internal/sandboxruntime/microvm/assets/localresolver -c -o <external-test-binary>
```
