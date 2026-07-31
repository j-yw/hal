# Sandbox Runtime v2 L6 Production Policy Proxy Architecture

## Authority and scope

L6 implements the policy-proxy node in issue #49's locked Linux-completion
plan. The three locked issue comments (`5068151561`, `5068157402`, and
`5068162708`) and
`docs/design/sandbox-runtime-v2-linux-completion-architecture.md` are
authoritative.

L6 owns a real, explicitly constructed HTTP/1.1 forward proxy with CONNECT
tunnelling. It does not wire proxy environment variables into a sandbox,
create namespaces, install or inspect Linux rules, block direct egress, claim
strict networking, or depend on L5 Firecracker completion. Those are L7
topology/enforcement responsibilities.

## Package ownership

The existing `internal/sandboxruntime/networkenforcement` package remains the
data-only plan, decision, sanitized-log, lifecycle, and proof package. Its
import boundary continues to reject `net`, `net/http`, process, runtime, and
firewall dependencies.

The concrete listener lives in
`internal/sandboxruntime/networkenforcement/policyproxy`. This child package
may import the parent contracts plus standard-library networking packages. It
must not import `cmd`, factory, worker, execution, workspace, concrete runtime,
provider, Docker/Podman, Firecracker, firewall, process, or cloud packages.

The production constructor is explicit. No command, daemon, worker, runtime,
factory, or default execution path constructs it in L6.

## Inputs and live-only state

Construction requires:

- a `networkenforcement.PolicyProxyPolicyInput`, including validation-only
  allowlist values;
- bounded server, header, request-body, response-body, CONNECT-byte, timeout,
  and concurrency limits;
- an optional listen address, defaulting to an ephemeral loopback TCP port;
- an optional resolver and dialer for deterministic tests.

Raw destinations, resolved addresses, listener addresses, request URLs,
headers, bodies, credentials, and connection handles remain live-only. The
adapter exposes the selected endpoint only through a non-JSON live accessor
for L7 topology wiring and direct L6 tests. Existing lifecycle proof remains
limited to safe plan/session/adapter IDs, proxy-only mechanisms, statuses,
capability labels, and reason/warning codes.

Invalid or unbounded configuration fails before binding. Non-Linux builds
compile but construction fails closed as unsupported.

## Request decision and DNS-rebinding boundary

For ordinary HTTP:

1. accept only a valid absolute `http` request target;
2. reject userinfo, malformed/mismatched authority, unsupported schemes and
   upgrades;
3. evaluate the existing in-memory host/endpoint policy;
4. resolve the allowed hostname once through the configured resolver;
5. reject an empty, malformed, mixed-safe/unsafe, loopback, private,
   link-local, unspecified, multicast, or metadata-address result;
6. dial one of the validated addresses directly, never the hostname; and
7. forward through a transport with ambient proxy discovery disabled.

CONNECT follows the same authority evaluation, single resolution, address
validation, and direct-IP dial. This closes the check-then-resolve rebinding
gap and prevents a second resolver answer from changing the destination.
L6 does not provide a public-IP allowlist exception for local/private ranges;
contained tests map a policy-safe synthetic address to a disposable loopback
listener behind an injected dialer.

All resolved addresses must pass. A mixed answer fails closed.

## Bounds and protocol handling

- accepted connections, server header bytes, read-header time, idle time, and
  maximum concurrent requests are bounded before handler admission;
- aggregate limits conservatively account for parsed request, response, and
  trailer working sets, including the server's request-header read allowance,
  and upstream response headers are MIME-parsed only once;
- request and response bodies are buffered only up to configured maxima, with
  oversize input rejected before upstream publication;
- CONNECT tunnels have bounded lifetime and per-direction byte limits;
- CONNECT resolution, dialing, and tunnelling share one bounded CONNECT
  operation context;
- hop-by-hop and `Proxy-Authorization` headers are removed;
- outbound HTTP writes one contained origin-form request directly to the
  already validated numeric-address connection, so ambient proxy discovery and
  a second DNS lookup are impossible;
- cancellation closes upstream work and stop closes listeners, idle
  connections, active tunnels, and request contexts.

Public errors use fixed safe response text and status codes. They never include
the raw authority, URL, address, resolver/dialer error, header, body, or token.

## Decisions and lifecycle

Every handled request produces exactly one final sanitized
`PolicyProxyDecisionLogRecord` before its response or tunnel outcome. The
optional in-memory sink is synchronous and panic-isolated. The injected sink
contract requires a nonblocking callback; production persistence must place
its own bounded queue behind that callback. A panic cannot weaken a decision,
and L6 creates no background sink goroutine or lossy hidden queue. Durable
consumers receive only policy
snapshot/rule IDs, action, reason, safe destination category, and count.

Lifecycle is transactional:

- prepare validates configuration without binding;
- start binds and starts serving, or closes all partial state;
- start and stop serialize across full generation cleanup;
- active succeeds only while the exact owned listener and serve loop are live;
- stop is idempotent and uses an internal bounded cleanup context even if the
  caller is canceled;
- serve failure clears active proof and serializes cancellation and owned
  connection cleanup with start and stop for the same lifecycle generation.

The existing enforcement projection may report active proxy-only
`networkEnforcement=proxy`. L6 can never report firewall/runtime proof,
`proxy_firewall`, direct-egress denial, or strict deny-by-default enforcement.

## Verification contract

Default fake tests use injected resolver/dialer/listeners and prove:

- HTTP and CONNECT allow/deny paths;
- DNS-rebinding and unsafe/mixed resolution rejection;
- direct-IP dialing with no second DNS lookup;
- request, response, CONNECT, header, timeout, and concurrency bounds;
- proxy/auth/secret stripping and redaction-safe decisions/errors;
- cancellation, unexpected serve failure, idempotent stop, and cleanup;
- no ambient proxy use;
- proxy-only proof without enforcement overclaim;
- no default-path construction; and
- non-Linux fail-closed compilation behavior.

The selected tagged live test uses only disposable loopback HTTP/TCP fixtures,
the real listener/server/transport, and injected deterministic safe-address
mapping. It has no skip path and requires no cloud, KVM, Podman, firewall,
namespace, external DNS, or internet access.

## Non-goals and handoff

L6 does not implement sandbox endpoint reachability, proxy environment
injection, DNS interception, direct-egress denial, nftables/iptables rules,
network namespaces, Podman/Firecracker topology, credential injection, OCI
acquisition, or strict composition.

L7 consumes the explicit live endpoint and proxy-only lifecycle proof, makes
the endpoint reachable from each runtime, adds inspected Linux rule proof, and
proves direct/DNS/IPv4/IPv6/private/link-local/metadata bypass denial and stale
topology cleanup.
