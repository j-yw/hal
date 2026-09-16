# Legacy recovery client interrupted receive

## Scope and current checkpoint

This bounded slice follows the Linux completion architecture and L8 reset. An
external diagnostic at `3e07e173` reproduced actual `Recvmsg` EINTR during the
legacy client's third authentication. The shared receiver, reconnect, and
original test have identical bytes at accepted `b9354f8e`, `33248091`, and
`3e07e173`; this is an inherited failure path. The earlier broad-suite failure
did not record errno and remains unattributed, not dismissed as a flaky fixture.

Current checkpoint is compiling RED only, based on accepted `0b18f8f2`. No retry
implementation is authorized until independent reproduction. The only permitted
production extraction moves the legacy client's existing one-shot receive into
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
