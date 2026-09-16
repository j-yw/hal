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
