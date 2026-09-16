# Legacy recovery client interrupted receive

## Scope and current checkpoint

This bounded slice follows the Linux completion architecture and L8 reset. An
external diagnostic at `3e07e173` reproduced actual `Recvmsg` EINTR during the
legacy client's third authentication. The shared receiver, reconnect, and
original test have identical bytes at accepted `b9354f8e`, `33248091`, and
`3e07e173`; this is an inherited failure path. The earlier broad-suite failure
did not record errno and remains unattributed, not dismissed as a flaky fixture.

The compiling RED checkpoint `a25c2fcc` is based on accepted `0b18f8f2` and was
independently reproduced before GREEN. Its production extraction moved the
legacy client's existing one-shot receive into
a private client-specific helper. Its syscall-shaped receive parameter is
hardwired to `unix.Recvmsg` by the real client exchange, never stored, exported,
configured, or supplied by request/runtime options. The original decoder remains
shared and unchanged. Every existing test stays byte-identical.

## Required behavior

After the one successful request send, retain one absolute monotonic receive
deadline established before the first receive, capped by the existing configured
socket budget and any earlier context deadline. Genuine EINTR may retry only
when it consumed no bytes, ancillary rights, stale ancillary-buffer contents,
or flags. Recheck caller cancellation and the same deadline before every retry
and before accepting the reply. Never resend the request or restart the budget.

Only the remaining receive budget may be installed per attempt. Preserve the
original socket receive and send budgets after the operation. Errors remain
sanitized; timeout, EOF, shutdown, malformed/partial/truncated packets, other
errors, and ambiguous ancillary observations never authorize retry or success.
Every actual descriptor received or rejected must retain its existing exact
close ownership. No global signal handler or new cancellation goroutine is
introduced; existing caller checks and owned shutdown/close remain in force.

The shared receiver is deliberately not changed. Its callers include selected
bootstrap with the original preparation deadline P, an untimed owner-loss
monitor, untimed controller loops, and distinct child/arming gates. Selected
finalization already owns an absolute deadline and interrupted-I/O handling;
that path, P, supervisor, gates, codecs, and credential/native behavior remain
untouched. There is no new capability, security, live registry, or VM claim.

## RED evidence and acceptance

Use real socketpairs, the actual client exchange, a genuine encoded reply, and a
one-request peer. A bounded SIGURG sender targets only a locked thread in its
own test process and joins before the thread unlocks. An additional observing
helper case delegates to actual `unix.Recvmsg`, records the raw EINTR tuple, and
returns it unchanged. Both must succeed after interruption without resending.

Deterministic syscall-boundary tests inject only recvmsg-shaped observations:
one interruption then valid bytes; repeated bounded interruptions exhausting one
configured/context-capped budget; restored socket options; cancellation; EOF and
shutdown; no retry of partial/malformed/timeout observations; and disposal of
real owned descriptors, including explicitly labeled impossible error-plus-
ancillary tuples. No fake clock or decoder substitutes for the actual signal
case. All helper goroutines, senders, peers, files, and test processes join.

Freeze the full compiling RED commit/tree for independent reproduction. Preserve
unchanged reconnect, selected finalization/P, shared transport, and command
guards; run scoped default/race checks, vet, and cross-compilation. These are
component gates, not full-repository or prepared-Linux acceptance.

## Implemented checkpoint

Independent RED reproduction observed raw EINTR with no bytes/rights/flags and
the intended lost-reply/budget failures. Both RED files and every old test remain
unchanged. The client-specific helper now captures monotonic start time on entry,
reads the configured receive option, rejects unset/overflowing budgets, and caps
one absolute deadline by the caller deadline. Production authentication installs
five seconds before its first exchange, and subsequent legacy cleanup exchanges
reuse that socket. No production caller relies on an unset receive budget.

Only no-consumption EINTR retries. Every attempt installs positive remaining
SO_RCVTIMEO, rechecks cancellation/deadline, and clears its buffers. Successful
syscall flags retain the unchanged decoder policy; flags must be zero for an
interruption retry, not for ordinary successful receives. The existing
complete-prefix ancillary disposal leaf is reused without changing selected
finalization. Final acceptance and exact original receive-option restoration
run before return; SO_SNDTIMEO is never changed.

Additional reached controls cover zero receive options, expired caller context,
late valid packets, restored options, and real successful syscall flags. No new
reader, cancellation goroutine, send retry, public option, shared transport
policy, selected P rebasing, or prompt legacy cancellation claim is introduced.
Full verification results are attached to the frozen submission handoff rather
than inferred from this implementation description.
