# Selected minimal guest command

## Scope and authority

This slice starts at `ad9286888ca8f718fa5a7fc79d557d82eb2b9a99` and composes the
accepted authenticated workload transport and Linux workload verifier at the
actual selected `hal-guest-agent` entry point. The Linux completion architecture,
L8 contract reset, and selected minimal workload-control design remain controlling.
It neither changes their protocol nor enables strict selection or credentials.

Only `cmd/hal-guest-agent` construction and its tests change. Shared transport,
server, verifier, image tooling, host CLI, and legacy entry behavior are unchanged.

## Inputs and construction

`runGuestAgentEntry` keeps its single bounded command-line read and passes the
same retained string to the selected route. That route validates both the
minimal pins and `guestnetwork.ParseBootCommandLine` on those bytes. L7 must be
present and valid. The existing configuration builder validates all four
inherited proxy variables, requiring their exact equality and a canonical URL;
its proxy URL must exactly match the retained L7 expectation. Missing, partial,
malformed, mismatched, or canceled input fails before backend or listener
construction. No second `/proc/cmdline` read or request environment supplies
boot authority.

The production route constructs the concrete L7 network verifier from that
BootConfig, then the concrete Linux workload verifier. No process boundary is
injected in production. It constructs `server.NewLinuxBackend` with the existing
fixed `/workspace` workspace and guest roots, `/usr/bin` and `/bin` executable
roots, and narrow base environment. It then acquires the fixed control listener,
constructs `minimalcontrol.NewWorkloadTransport`, and calls actual `server.New`
and `Server.Serve` with both process and network work-proof flags true.

Private construction dependencies permit fake-only command tests: environment
lookup, backend constructor, listener constructor, network verifier constructor,
and workload verifier constructor. They do not substitute a transport, server,
parser, handshake, operation dispatch, or cleanup algorithm. Production defaults
are explicit concrete constructors. No secret environment resolver is installed;
the existing rejecting default and request-environment rules remain authoritative.

## Lifecycle, failures, and ownership

The parent/signal context owns the selected lifetime. Check cancellation before
construction and between constructor boundaries. Constructors do not establish
readiness: actual `Server.Serve` starts the transport, which runs backend Ready
and fresh process/network inspection before authenticated minimal readiness.
Every valid later work admission receives the existing fresh proof check.

Before Serve ownership, the command closes every successfully returned owned
backend/listener on later failure, including canceled construction and sanitized
constructor panics. Backend cleanup uses a bounded independent context, never
an already-canceled work context. Once Serve begins, its accepted backend cleanup
and the transport's listener/stream ownership remain the sole cleanup owners.
Constructor error strings, panic payloads, boot bytes, proxy values, and request
contents do not cross the command error boundary; use existing fixed invalid or
unavailable errors while retaining standard cancellation identity where relevant.
Cleanup failure remains a failure, never a success or guest-process-absence claim.

No retry, alternate legacy fallback, background abandoned construction, durable
state, new machine JSON, new capability, or security upgrade is introduced.
Legacy absence keeps selecting the existing legacy constructor unchanged.

## RED-first acceptance

1. Commit this design, then a compiling behavior RED on the actual selected
   route. A narrow construction seam initially delegates the unchanged bootstrap
   behavior. Tests supply real public boot pins, complete matching L7 config,
   fake counted backend/verifier constructors, and in-memory duplex I/O. Actual
   authentication and the unchanged readiness golden precede the workload test.
   Assert exact exec/copy dispatch, fresh proof calls, and owned cleanup. Add
   config negatives proving no backend/listener construction. Freeze the RED
   commit for supervisor reproduction before implementing GREEN.
2. Compose the accepted production constructors minimally. Cover cancellation
   before and between constructors, nil/error/panic results, exact construction
   and cleanup counts, sanitized failure, actual authenticated work and copy,
   denied proof, backend errors/panics, request proxy override and secret sources.
   No test assigns server lifecycle or cached proof state.
3. Run whole command and affected guest packages, race repetitions, unchanged
   relevant source/compatibility guards, vet, formatting/diff checks, and Darwin
   cross-compilation. Record exact tested commits and any unrun broader/live gate.

Existing selected command tests currently inject only a listener because the
route is bootstrap-only. Their setup must evolve to supply valid L7 and fake
backend/proof construction while preserving v1 rejection, cancellation,
sanitization, and ownership assertions. The old listener-only production helper
must not remain orphaned solely to keep those fixtures compiling. Direct legacy
minimal readiness-only transport fixtures remain unchanged compatibility tests.
Any source-guard conflict requires supervisor review, not an assumed exemption.

## Deferred acceptance

Ordinary temp directories cannot prove the Linux workspace boundary: it requires
a distinct unaliased filesystem and exact mount ownership. Default tests do not
bind sockets, mount filesystems, probe real networks/raw sockets, launch programs,
change privileges, or boot VMs. Actual prepared-guest backend acceptance, exact
rebuilt release assets, live exec/copy/cancel/teardown, host runtime producer,
credential delivery/cleanup, and correlated L10/L11 proof remain separate gates.
The selected image has the reset same-UID topology, not workload privilege
separation or a guest seccomp claim.

## Initial compiling RED checkpoint

The new constructor-only seam is used by `runMinimalGuestAgent`, but deliberately
delegates unchanged bootstrap-only serving. The old listener-only helper remains
temporarily shared with existing tests; GREEN removes it while evolving only
their selected setup. No backend/proof constructor is called at this checkpoint.

The whole command package under `-race -count=3` produces 33 expected failing
test/subtest events, 201 passing events, and zero skips. Nine invalid L7/config
cases reach the listener incorrectly; pre-canceled entry still passes. The actual
entry route completes bootstrap, Finished, and the unchanged independent golden
readiness, then authenticated exec fails with EOF and zero backend/proof calls.
Construction/cleanup assertions independently expose the missing backend owner.
Copy request fixtures validate before authentication, but copy dispatch and fresh
proof assertions are not reached past the exec failure and are not claimed as
executed acceptance. Existing command/config/legacy tests pass unchanged. All
Serve/watchdog tasks join; no watchdog rescue or race report occurs.

## Selected command composition checkpoint

After independent reproduction of the first RED, a second committed construction
fault RED covers error, nil/typed-nil, panic, cancellation, and value-plus-error
returns at all four constructor boundaries. It produces 90 expected failing
test/subtest events and six passing controls under three race runs. The minimal
implementation now validates the retained L7/environment tuple first, builds the
actual concrete production dependencies, and selects the accepted workload
transport inside actual Server.Serve with both proof gates enabled.

The listener-only production helper has been removed. Six existing selected
fixture call sites now use one test-only setup helper adding complete L7 and
counted fake backend/proof constructors. Their original behavioral assertions,
including exact fixed error identities, remain unchanged; setup additionally
asserts unauthenticated traffic never calls Ready, proof inspection, or Exec,
and every constructed backend is closed. Legacy command production bytes and
direct readiness-only transport fixtures remain unchanged.

Actual authenticated tests now execute one bounded exec and copy-in/out through
the shared Server and Client, checking exact plans, output, digest, publication,
one preparation, and four fresh proof checks. Forward tests reject missing
process/network proof on preparation and later work, exercise backend Ready/Exec
errors and panics, and prove owner loss and EOF cancel blocked work before
cleanup without a test release. Cleanup error remains failed. Request proxy
names and every environment source reach the actual server: uppercase variables
and secret entries fail at its rejecting resolver; lowercase proxy names fail
the existing strict name validator before inspection. No request authority or
new secret resolver is installed. These are injected component results, not
actual process/network/workspace acceptance.

Pre-Serve cleanup is synchronous with a bounded independent context; it does not
abandon a blocked constructor or cleanup in a new goroutine. This bounds the
context provided to the trusted backend, not arbitrary implementations ignoring
it. After Serve, the accepted server retains its existing bounded-cleanup and
pending-ownership semantics. No new terminal resource-absence proof is implied.
