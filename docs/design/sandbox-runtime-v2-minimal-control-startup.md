# Selected minimal control startup availability

## Status and boundary

DESIGN/compiling RED was committed as `65a1a882` at base `b6a440fe`. GREEN
implements the private startup method; it has no production selector/caller.
Existing single-attempt `minimalControlTransport.Open` delegates to a shared
private attempt core with its original one-shot/fail-closed behavior. Legacy
v1/v2, Jailer, worker, guest and L7 paths are unchanged. This slice returns only
a retained raw stream after CONNECT/ACK,
not authenticated readiness, credential/helper authority or cleanup proof.

Firecracker's host UDS can precede the guest listener. The pinned dependency is
v1.15.1 (`tools/microvm/l5/sources.lock.json`). Existing
`firecracker_vsock_transport.go` classifies an empty pre-ACK EOF/ECONNRESET as
guest-port unavailable; its ordinary-UDS bridge regression covers reset then
success. Minimal Open currently collapses that condition into generic failure.
No upstream Rust source or live Firecracker behavior was newly verified here.

## Private API and bounds

`(*minimalControlTransport).OpenWhenAvailable(ownerCtx, admissionDeadline)` is
one-shot, including failure, and returns the existing `minimalControlStream`.
It shares one-shot ownership with Open: neither method may run after the other.
The caller supplies a nonzero future absolute admission deadline. Cap it at
entry plus 15 seconds and the caller deadline; never extend a shorter deadline.
Retain the effective absolute admission deadline on the returned private stream
so a longer input cannot accidentally extend the next phase. The next
controller must keep that same effective absolute deadline through
bootstrap, both Finished messages and encrypted readiness, with at most one
authenticated attempt. Passing a short-lived admission context as ownerCtx is
incorrect: ownerCtx owns the returned stream's lifetime.

Capture the owner hard lifetime once at startup entry (at most 35 minutes,
capped by ownerCtx). Retry delays and connections do not reset it. Each CONNECT
attempt is additionally capped at five seconds and the remaining startup/hard
budget. Wait 100 ms between availability probes; allow at most 150 CONNECT
attempts. Reject elapsed absolute time even if a context timer is not scheduled
yet. A long caller deadline cannot enlarge any bound.
The private poll-interval test override can only shorten the 100 ms delay; it
does not enlarge the 150-attempt or absolute time bounds and is not a public
runtime option. It permits a deterministic real-UDS attempt-cap regression
without making every ordinary test wait 15 seconds.

## Authority and state sequence

1. Resolve one exact manager handle, process identity and active strict owner.
   Validate canonical runtime paths. Observe the original owner-pinned parent
   independently of the socket using nofollow Linux metadata and pathname
   rechecks. Existing socket observation returns ENOENT before its final parent
   checks, so ENOENT alone is insufficient authority to wait.
2. While no socket has ever been captured, only an absent leaf may wait; the
   original parent mode/owner/device/inode and retained process must remain
   current. Missing/changed/unsafe parent, process loss or cancellation fails.
3. Capture the first valid socket device/inode once. Every attempt uses that
   same process/owner/parent/socket tuple. A disappearance or replacement after
   capture is terminal, even if the replacement is independently well-formed.
   Refactor only the private raw admission core as needed to accept this pinned
   expectation; do not silently recapture between one-shot transports.
4. A successful whole `CONNECT 1025\n` write followed by zero ACK bytes and
   specifically EOF/ECONNRESET may return a private stage-specific unavailable
   classification. Recheck retained currentness and absolute deadlines before
   classifying, close/join that attempt, then recheck before another attempt.
   Cancellation/currentness failure always takes precedence over retryability.
5. Dial errors (including ECONNREFUSED), write errors, partial/malformed/extra
   ACK, timeout and identity errors are terminal. No string-based error matching
   or broad legacy transient classifier. Once any valid ACK is received, there
   is no retry, even if final currentness/publication fails.
6. Only fully admitted ACK success allocates a stream generation. Failed
   pre-ACK attempts return no stream/correlation; each connection and its watcher
   are closed/joined before the next attempt. A failed final publication retires
   its correlation. Return one stream, never a readiness or legacy session.

These are bounded host availability probes, not guest authentication retries.
The ordinary unbound-port case does not reach guest Accept; ambiguous transport
failure is not proof that the guest consumed zero attempts. Its independent
three-accepted-connection/15-second budget stays authoritative and unchanged.
This slice generates no signing keys and consumes no session entropy. The later
controller may retain its one key over the bounded wait, authenticate once after
ACK, and destroy it on consumption, failure, cancellation or exhaustion.

## RED and acceptance

New tests use actual disposable Unix sockets/CONNECT/ACK/payload bytes plus a
fake tracked strict process record. Caller-owned parent/socket metadata is real;
no privileged UID change, Jailer execution, AF_VSOCK, KVM or live VM is involved.
The root-UID fixture is skipped rather than pretending UID zero is a valid
strict runtime UID. Fixture watchdog cleanup is not product cleanup evidence.

The compiling RED stub failed eventual socket/ACK and lifetime regressions.
Negative tests must observe the relevant real transcript before accepting a
rejection; an unconditional unavailable stub is not credited for those cases.
Passing controls exercise existing single-attempt Open and its fail-closed
empty/partial/malformed ACK behavior. Tests also cover cancellation/deadline,
process/record/parent/socket loss between attempts, no early generation, original
hard lifetime, one-shot use, and no legacy publication.

```sh
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControlStartup'
go test -p 2 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalHostTransport'
go vet -p 2 ./internal/sandboxruntime/microvm/firecrackerhost
git diff --check
```

GREEN adds exact 150-attempt exhaustion and effective 15-second/input/hard/context
deadline checks, real reset-then-success, terminal dial/write causes, concurrent
one-shot use, pending dial/write cancellation, failed watcher joining before
retry and post-ACK final absolute deadline rejection. The original RED tests
remain byte-identical. Supervisor/controller selection and
the original-client readiness handoff remain separate work; no default is
enabled and no guest authentication or terminal cleanup claim is made here.
