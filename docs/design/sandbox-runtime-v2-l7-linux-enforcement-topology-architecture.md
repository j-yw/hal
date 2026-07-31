# Sandbox Runtime v2 L7 Linux Enforcement and Topology Architecture

## Authority and phase boundary

L7 implements the network-enforcement/topology node in issue #49's locked
Linux-completion plan. The locked issue comments `5068151561`, `5068157402`,
and `5068162708`, together with
`sandbox-runtime-v2-linux-completion-architecture.md`, remain authoritative.

The exact stacked base is
`880ee698c48df9d6e62a2a472414d8f4c7ce0bfb`. L6 supplies a real loopback
HTTP/CONNECT proxy and proxy-only lifecycle proof. L7 makes that proxy
reachable from rootless Podman and Firecracker, installs and inspects owned
Linux rules, correlates the live components, and cleans them transactionally.

L7 does not deliver credentials, select OCI templates, enable the strict
default, or compose the final cross-component claim. Rootless Podman remains
advisory even with active network enforcement. L10 alone may select strict
Firecracker after every required production proof exists.

## Prepared-host decision

The prepared user has no host-global `CAP_NET_ADMIN`, and host-global nftables
inspection fails as intended. The same user can create a fresh owned user and
network namespace and can apply/inspect nftables inside it. L7 therefore must
not require `sudo`, ambient host capabilities, host-global tables, shared
chains, or global sysctl changes.

Every L7 mutation is scoped to a sandbox-owned network namespace:

- rootless Podman uses its exact Podman-owned user/network namespace; and
- Firecracker uses a Hal-owned user/network namespace whose lifetime is held
  by a supervised helper.

`pasta` provides a runtime-specific, live-only mapping from a synthetic guest
address to the exact L6 loopback proxy port. Because `--map-host-loopback`
targets only the canonical family loopback, L7 accepts only `127.0.0.1` or
`::1` and requires the guest mapping address to use the same family. The
mapping is not enforcement proof. The owned nftables rules mediate IP traffic,
while an independently inspected runtime control removes raw-packet capability
before untrusted work can start. Both proofs are required: an `inet` output
hook cannot observe `AF_PACKET` link-layer sends, and a capability-only control
cannot replace the inspected default-drop IP policy.

## Package ownership

- `internal/sandboxruntime/networkenforcement` remains data-only. It owns safe
  lifecycle, correlation, inspection-proof, aggregation, redaction, and reason
  code contracts. Its existing import guard remains intact.
- `internal/sandboxruntime/networkenforcement/linuxrules` owns Linux nftables
  batch construction, namespace-FD execution, bounded JSON inspection,
  quarantine, exact-generation deletion, and non-Linux fail-closed stubs.
- `internal/sandboxruntime/networkenforcement/linuxtopology` owns supervised
  namespace handles, namespace identity inspection, pasta lifecycle and proxy
  mapping, and safe topology generation IDs. It does not import Podman or
  Firecracker.
- `internal/sandboxruntime/rootlesspodman` owns Podman create/start/exec/stop
  sequencing, explicit pasta arguments, container-label and namespace binding,
  proxy environment injection, inspected raw-packet capability removal, and
  its per-target topology session.
- `internal/sandboxruntime/rootlesspodman/l7network` is the explicit concrete
  composition package. It imports the concrete policy proxy and Linux rule
  adapters while the parent `rootlesspodman` package keeps its concrete-adapter
  import guard unchanged.
- `internal/sandboxruntime/microvm/firecrackerhost` owns the Firecracker
  topology session, TAP lifecycle, namespace-bound process launch, and the
  ordering between topology, Firecracker, guest readiness, and teardown.
- `internal/sandboxruntime/networkenforcement/policyproxy` may expose a typed
  live-only endpoint and generation-loss signal. Its default listener stays
  loopback-only; no wildcard or universal guest-facing bind is added.
- `tools/microvm/l7` owns a distinct reproducible network-enabled guest image
  profile. The L5 no-network profile and its evidence remain unchanged.
- `cmd` remains dependency wiring, gates, and sanitized projection. It never
  constructs rule bodies or executes Linux networking tools.

## Live inputs, private state, and safe output

Construction requires safe immutable identity for the sandbox, execution,
worker, runtime, plan, policy snapshot, proxy session, topology generation,
the exact retained proxy generation, and rule generation. Empty, unsafe,
duplicate, or mismatched identity fails before mutation.

Private live state includes namespace FDs and device/inode identity, helper
process handles, runtime PIDs/start identity, TAP/interface names and indices,
addresses, routes, proxy address/port, pasta arguments, nft names/handles/raw
JSON, and executed argv. It stays in memory or in a private `0700` runtime
directory with a `0600` lock-protected ownership journal. It never enters
public JSON, manifests, worker status, errors, logs, or issue evidence.

Safe public proof contains only validated correlation IDs, generation/proof
IDs, a canonical rule digest, inspection status/time, mechanisms, capability
labels, reason codes, and warning codes. Projection must require equality of
all supplied component identities; it must never choose the first non-empty
ID when sources disagree.

The safe lifecycle states are:

```text
planned -> proxy_started -> topology_prepared -> runtime_created
        -> rules_applied -> inspected -> active
        -> quarantining -> stopping -> cleaning -> stopped
                                               \-> cleanup_incomplete
```

Apply acknowledgement is not active proof. Only a fresh structural inspection
of the exact namespace, interface, proxy generation, and nft generation can
produce `inspected` and then `active`.

The `linuxtopology` package itself stops conservatively at `prepared`. Its safe
metadata distinguishes `structuralInspected` from `mappingReachable` and never
publishes `active`: a successful namespace-local probe cannot by itself prove
that the retained L6 proxy generation is still the listener reached. The
higher runtime composition must compare the same required proxy generation
before and after the probe, correlate the exact inspected rule generation, and
only then publish an aggregate active result.

Topology inspection disables ambient route copying and correlates every
accepted route with normalized address evidence from the exact interface.
Each family has one default route. IPv4 has one connected route for its
observed prefix; IPv6 has one link-local connected route and has a global
connected route only when its exact address evidence does not declare
`noprefixroute`. Extra gateway, connected, metadata, or duplicate route shapes
fail closed.

## Linux rule adapter

The adapter uses narrow injected boundaries equivalent to:

```go
type NFTExecutor interface {
	ApplyBatch(context.Context, NamespaceHandle, []byte) error
	ListTableJSON(context.Context, NamespaceHandle, TableQuery, int64) ([]byte, error)
}
```

Production execution passes one bounded batch to `nft -f -` over stdin. It
does not use a shell, put rule bodies on argv, invoke iptables, call `sudo`, or
flush a shared/global ruleset. Namespace entry uses an already-open FD through
a validated helper such as `/proc/self/fd/N`; process-global `setns` is not used
from multithreaded Go.

One uniquely owned `inet` table is committed atomically per generation. Base
chains are default-drop in the first committed transaction. Canonical rules:

- allow only required established return traffic;
- allow the exact TCP proxy mapping for the current proxy generation;
- allow only the minimal IPv6 neighbour-discovery traffic required by the
  configured link;
- deny direct TCP/UDP/ICMP, TCP/UDP DNS, proxy bypass, private/ULA, loopback,
  link-local, metadata, multicast, unspecified, and NAT64-translated bypasses;
- reject unexpected accept, jump, goto, NAT, masquerade, extra interface, or
  extra default-route behavior.

The rule adapter must fail closed unless its caller supplies a same-generation
runtime proof that the workload cannot create raw packet sockets. A requested
capability drop, static image property, or plan label is not proof. Podman must
inspect the created container's effective configuration; Firecracker must
confirm the running guest-agent process has no effective, permitted,
inheritable, ambient, or recoverable raw-packet capability. The L7 image must
also contain no setuid/setgid or file-capability path that can reacquire it.

Inspection consumes bounded `nft --json list table` output and compares the
normalized family, table ownership token, chain hooks/priorities/policies,
rule order, expressions, verdicts, interface identity, generation comments,
and canonical digest. Adapter-supplied labels or plan-derived capabilities are
not inspection proof.

Any apply, inspection, correlation, or topology drift replaces the owned
generation with an all-drop quarantine when ownership is still provable.
Cleanup deletes only an exact owned generation and then inspects absence. A
stale generation cannot delete a newer generation.

## Rootless Podman topology

The default Podman constructor remains unchanged. An explicit injected L7
topology factory performs this transaction:

1. validate safe identity, local prerequisites, and the typed L6 loopback
   endpoint;
2. start and retain one exact L6 proxy generation;
3. create the stopped container with explicit rootless pasta mapping, no host
   network, no ambient/default network, no port auto-forwarding, no Docker
   socket, no privilege, no-new-privileges, and no workload `CAP_NET_ADMIN` or
   `CAP_NET_RAW`;
4. start only the inert container command; user work remains blocked;
5. inspect exact container ID/labels, user/network namespace identity, and the
   effective absence of all raw-packet/admin capability paths;
6. enter that owned namespace through the daemon helper and atomically install
   the output-chain rules;
7. structurally inspect the rules and probe the exact proxy mapping;
8. publish active advisory network proof and permit job execution.

The topology sub-step in item 7 produces only prepared structural and mapping
evidence. Item 8 belongs to the higher composition after it has revalidated
the exact retained L6 proxy generation and rule proof.

The concrete `l7network.Factory` is disabled unless explicitly injected. It
retains an opaque typed `policyproxy.LiveEndpoint` generation, resolves the
exact full-ID Podman init user/network namespace with before/after label and
start-identity inspection, builds `linuxrules.RuleProfileWorkloadOutput` with a
target-bound `PodmanRawPacketIsolationVerifier`, and checks the same listener
generation immediately before and after rule application/inspection. Its
ordinary `Inspect` path repeats listener, structural rule, and raw-packet
inspection without applying rules again.

The execution adapter injects `HTTP_PROXY`, `HTTPS_PROXY`, and lowercase
equivalents from typed live state, clears uncontrolled proxy bypass variables,
and never persists the endpoint. Removing those variables cannot restore
direct egress because nftables remains default-drop.

On stop, cancel or proxy loss, proof is revoked first. The runtime is stopped
or frozen before rules are removed. Releasing the proxy port while an active
mapping could reach a future listener is forbidden.

## Firecracker topology and guest profile

L5 deliberately produced a no-network guest. L7 adds a separate reproducible
profile enabling IPv4, IPv6, network devices, virtio-net, and the minimal
packet/socket support. PID 1 configures one statically described interface,
addresses, routes, and proxy bootstrap before dropping to UID/GID 1000. DHCP
and guest DNS remain disabled. Required BusyBox networking/probe applets are
locked by the build. The L5 image, digest, and no-network tests are not edited
into a networking claim.

Before Firecracker work is admitted, PID 1 must irreversibly remove effective,
permitted, inheritable, ambient, and bounding capability paths while changing
to UID/GID 1000 under `no_new_privs`. The built filesystem must be inspected to
contain no setuid/setgid executable or file capability that can reacquire raw
packet access. Guest readiness must report only a sanitized pass/fail result
for that live process state; the static image manifest is not runtime proof.

The Firecracker transaction is:

1. create and retain the Hal-owned user/network namespace helper;
2. attach an explicitly configured pasta mapping to the host-loopback L6
   proxy; disable ambient port forwarding;
3. create one owned TAP, configure the namespace side, and enable forwarding
   only inside the owned namespace;
4. install default-drop input/forward rules before guest execution;
5. inspect namespace, pasta, TAP, routes, proxy generation, and rules;
6. render exactly one Firecracker network interface with validated live-only
   TAP name/MAC and bounded static guest boot parameters;
7. start Firecracker inside the owned namespace using a namespace-FD process
   wrapper, then require API acceptance and the L5 vsock readiness handshake;
8. inspect guest link/address/route and proxy reachability, then re-inspect all
   host-side components before publishing active proof.

Guest work receives the proxy bootstrap from validated L7 boot state. The
guest-agent command entrypoint may project those generated non-secret proxy
values into its fixed base environment; the guest-agent protocol does not gain
arbitrary raw environment transport.

Direct guest packets arrive from the owned TAP. Only the exact mapped proxy
tuple may be forwarded toward pasta; every other IPv4/IPv6/DNS/private/link-
local/metadata/raw protocol path is dropped. The host namespace and host-global
rules are untouched.

## Failure, restart, and cleanup semantics

All setup is serialized per sandbox by an in-memory mutex plus private
cross-process lock. Every operation uses generation compare-and-swap. No user
work starts before fresh active proof.

Failures use sanitized codes only:

`capability_missing`, `identity_mismatch`, `topology_collision`,
`proxy_unavailable`, `topology_prepare_failed`, `rule_apply_failed`,
`rule_inspection_failed`, `runtime_start_failed`, `proof_mismatch`,
`quarantine_failed`, `cleanup_incomplete`, and `stale_topology_unverified`.

Cleanup uses an independent bounded context even when the caller is canceled.
It revokes proof, quarantines, stops/reaps the workload or VM, stops mapping
and proxy helpers, deletes only exact owned rules/topology, inspects absence,
and finally removes the journal. Cleanup uncertainty remains
`cleanup_incomplete`; it must not be projected as stopped or successful.

After daemon restart every durable active claim is stale. Reconciliation opens
only a contained private journal, re-inspects exact ownership, quarantines
first, and cleans a terminal generation. It never reconstructs active proof
from labels, names, plans, or old JSON and never deletes a mismatched resource.
Topology setup holds a private per-sandbox cross-process lock for the whole
session, uses a `0600` atomic ownership journal under an owned `0700` state
directory, and retains incomplete rollback state. Helper reconciliation uses
recorded process start identity plus namespace identity and a stable process
handle; identity mismatch blocks replacement without signalling or deletion.
Retired topology-generation tombstones prevent generation reuse across daemon
restart.

Rootless-Podman restart cleanup enters through `l7network.Reconciler`. It pins
the first exact target ID/name/runtime tuple across retries, reconstructs no
active proxy or enforcement proof, reopens only label-correlated Podman
namespace descriptors, quarantines the exact owned table, requires exact
container stop, proves rule absence, closes the retained descriptors, and only
then deletes that exact container. Quarantine, stop, rule cleanup, descriptor
close, and delete failures retain ordered state for retry. A real daemon
process exit closes its process-owned L6 listener; same-process listener loss
is handled by the retained session before it can be treated as restart.

Before mapper launch the journal records a private `mappingArmed` marker plus
the exact daemon PID/start identity, keeper, and namespace identity. The
long-running helper is created and reaped by one goroutine locked to its OS
thread for the full child lifetime, so `Pdeathsig` remains tied to a retained
creator thread. The namespace keeper is a direct `unshare` exec without a
forking wrapper, so the one tracked PID owns the retained namespaces and Hal
waits for and reaps that exact process during cleanup.

Any restart that sees `mappingArmed` without a fully recorded mapper fails
closed as `stale_topology_unverified`, regardless of whether the recorded
creator still appears live. Creator death and `Pdeathsig` delivery are useful
containment but are not proof that the mapper has exited. Reconciliation does
not signal the keeper, retire or delete the journal, or permit replacement;
explicit recovery is required. A same-daemon retained `Session` can still
clean up or retry its own start failure. A fully recorded mapper is reconciled
by exact pidfd/start identity. No old journal is converted into prepared or
active proof.

## Red-first and live acceptance

Before production implementation, failing tests must cover:

- inspected-proof schema/redaction and aggregation rejecting plan-only,
  apply-only, stale, warning-bearing, and mismatched identities;
- atomic batch execution, bounded JSON inspection, extra/missing/reordered/
  wrong-verdict rule rejection, quarantine, generation-safe cleanup, and
  concurrency;
- explicit Podman pasta mapping, no privilege/capability/socket/host-network
  regression, no execution before proof, endpoint non-persistence, proxy-loss
  quarantine, restart reconciliation, and advisory-only projection;
- raw-packet socket attempts failing in both runtime lanes before user work,
  with capability state re-inspected after readiness and after restart;
- one Firecracker NIC, network-enabled L7 image validation, topology-before-
  boot ordering, namespace-bound process start, proxy loss, process failure,
  reverse rollback, and zero-resource teardown;
- non-Linux fail-closed behavior plus default constructors that perform no
  namespace, pasta, nftables, Podman-network, TAP, or Firecracker-network work.

Selected prepared-Linux tests use local fixtures and locally available images
and assets only. Once explicitly selected, a missing required prerequisite is
a failure/blocker, not a skip. They must prove allowed HTTP and CONNECT plus
denial of proxy policy violations, cleared-proxy direct egress, TCP/UDP DNS,
IPv4/IPv6 direct traffic, private/ULA, loopback, link-local, metadata, NAT64,
UDP, and ICMP. They also prove proof revocation, restart, partial failure, and
absence of owned containers, helpers, Firecracker processes, listeners,
namespaces, TAPs, routes, nft tables, sockets, mounts, locks, and leases.

No selected L7 test contacts the internet or a cloud provider.

## Non-goals and L8 handoff

L7 carries no credential values and does not implement credential proxying,
tmpfs secret files, SSH-agent delivery, OCI acquisition, template selection,
strict default selection, or final secure-default composition.

L8 consumes the same proven proxy/topology session for credential HTTP proxy
activation, then adds tmpfs-file and SSH-agent delivery with secret lifetime
cleanup. L8 cannot infer delivery proof from L7 network proof.
