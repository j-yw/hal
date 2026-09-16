# Minimal host workload transport

This implements the host portion of the accepted
[workload design](sandbox-runtime-v2-minimal-workload-control.md), based on
`8b8ccc77`. It does not activate a runtime, guest command, credential delivery,
or strict security claim.

The explicit private `withMinimalWorkloadController` constructor selects work
before the existing authentication task starts. The original constructor remains
readiness-only. Only the original current readiness object can obtain the
`guestagent.Transport`; copied, zero, stale and legacy readiness cannot.
The original controller owns the session, stream, sole reader and all writers.
One pending ordinal is installed before writing. Concurrent callers receive a
bounded busy error without retiring the current request. No queue or retry is
introduced. Invalid/pre-canceled calls have no effect on an active operation.

The selected reader starts at readiness and reads only bounded authenticated
responses. It rejects unsolicited, repeated or miscorrelated responses. It uses
the shared codec and the existing Client validates inner v1 responses. The
validator passed to session.OpenApplication performs only bounded decoding;
it never calls a session getter, backend, I/O or external callback.

The original hard lifetime is preserved. A caller deadline narrows the active
exchange; admitted cancellation retires the entire connection. Close interrupts
I/O outside controller locks, joins the reader and every admitted writer, then
revokes the session. A fully decoded correlated reply is retained across late
caller cancellation so the Client's existing published CopyIn semantics remain
effective. Missing replies remain ambiguous and are never resubmitted.

First RED: authenticate the real retained Unix bridge/shared guest bootstrap,
then require a selected transport from the original readiness. Legacy, copied,
zero and closed readiness controls remain independently exercised. Subsequent
joint tests must use the actual selected guest transport and Client for exec,
copy, cancellation, bounds, replay/correlation, concurrent calls and owner loss.
The existing host fixture uses fake process bookkeeping and caller-UID admission:
none of these tests is a Jailer/KVM, Linux backend or credential acceptance test.

Verification: focused host tests and race checks, existing controller/transport
regressions, joint guest/host tests, unchanged command guards, vet and Darwin
compilation. Source stays unintegrated until the original guest transport RED
and the host/guest exchanges pass without exclusions.

## Joint injected exchange checkpoint

The host adapter now consumes guest transport `4c62975f` in its isolated test
branch. The real Client, retained Unix bridge, cryptographic session, selected
guest transport and actual Server.Serve exchange 50 sequential execs and 512 KiB
copy-in/out. Exact command plans, output bytes, digest/publication responses,
one connection and a fresh injected inspection before each operation are checked.
Caller cancellation, either owner loss, host Close and a concurrent busy request
are exercised while an actual injected backend call is blocked. No test release
rescues that backend: cancellation must reach it and both owners must join.
Corrupted ciphertext/header and truncated responses retire the original session
without a result, reconnect or repeated backend execution.

An initial joint test incorrectly expected the outer scope to infer the last
operation failure despite its callback returning nil. The existing scope reports
authentication and callback success; the corrected consumer returns its actual
operation error. No production behavior or operation/cleanup assertion changed.
The standalone first RED and partial-reader panic regression remain unchanged.
Preparation/guest inspection and command execution remain injected, not live.
