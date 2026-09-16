# Stable recovery-key loader buffer ownership

The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.
This correction starts at `62112a273e913ced98345b928f9c131581dc6bb5` and owns only
the local 32-byte buffer in `loadL8RuntimeOwnerStableKeyFD`. It is not the new
sealed controller seed, stable-key provisioning, or producer assembly.

## Confirmed defect and invariant

Main independently reproduced the unchanged loader at `8a20cb61`: an actual
retained Pread destination stays nonzero after short read, read error, second
stat error/mismatch, or a deferred Close error discards the result. The helper
returns nil and its two callers cannot wipe that hidden allocation. The owned
FD is consumed once; existing metadata/exact-read/replacement controls pass.

Successful transfer must return the same live buffer only after both current
metadata checks, exact read and successful Close. All unsuccessful exits must
clear the retained local allocation independently of the named result, which
may already have become nil. Do not clear a successfully returned key.

Register a buffer-cleanup defer BEFORE the existing Close defer, retaining the
local slice even when the result is discarded. Commit transfer only after Close
returns nil and the named result is valid. On read/stat/Close panic, preserve
the existing propagated panic and closure behavior; cleanup may wipe while the
stack unwinds, without adding recovery, callback retries or another FD close.

## Verification and non-goals

First freeze a behavioral RED equivalent to the accepted external diagnostic:
ordinary private input, actual Stat/Pread/Close, retained scratch aliases, five
reached returned-error cases, successful same-buffer/caller-wipe control and
invalid-first-stat control. Preserve all old test bytes and the new RED through
GREEN. Add reached read/stat/Close panic controls before claiming unwind wiping;
use fixed markers and never print bytes or dynamic panic payloads.

The implementation is limited to local slice/defer ownership in the existing
helper. Keep linked 0600/32-byte identity validation, one exact read, the second
stat equality, one Close invocation, current success transfer and sanitized
errors unchanged. No caller, metadata/schema, UID policy, secret infrastructure,
provider, seed writer, executable role or default activation changes.

Run focused and original-control race tests, unchanged relevant guards, whole
host race tests, vet and Darwin compilation at the frozen final version. Ordinary
FD tests and cross-compilation do not claim root admission, physical memory
erasure, VM boot, credential usability or complete Sandbox v2 acceptance.

## Implemented checkpoint

RED `05065691` preserves the original loader and old tests. Its returned-error
cases plus old controls reproduced 33 passes / 18 expected failures under race
x3; the additional panic cases reproduced 3 controls / 15 expected failures.
The latter retain the exact propagated marker and existing FD behavior: a Close
callback that panics before its syscall still leaves that FD to the test-owned
cleanup, while the helper itself makes no retry or second Close attempt.

The helper now retains its local slice and clears it unless the existing Close
defer finishes and commits a valid successful result. The only production change
is this local ownership bookkeeping; no recovery or new closure action is added.
All 23 focused test/subtest events, including old controls, now pass. Both new
RED files remain unchanged through GREEN. Broader frozen-version checks are
recorded separately in the exact review handoff.
