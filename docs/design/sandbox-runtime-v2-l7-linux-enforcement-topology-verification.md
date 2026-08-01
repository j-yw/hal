# Sandbox Runtime v2 L7 Linux Enforcement and Topology Verification

## Default focused gates

Default tests are fake-only and must not start proxy helpers, create
containers/VMs/namespaces/TAPs, or mutate nftables:

```sh
go test -count=1 -timeout=180s \
  ./internal/sandboxruntime/networkenforcement \
  ./internal/sandboxruntime/networkenforcement/linuxrules \
  ./internal/sandboxruntime/networkenforcement/linuxtopology \
  ./internal/sandboxruntime/rootlesspodman \
  ./internal/sandboxruntime/rootlesspodman/l7network \
  ./internal/sandboxruntime/microvm/firecracker \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./internal/sandboxruntime/microvm/firecrackerhost/l7network \
  ./cmd -run 'TestL7|TestLinuxRules|TestLinuxTopology|TestFirecrackerHostTopology|TestLinuxTAP|TestProductionProxy'

go test -race -count=1 -timeout=300s \
  ./internal/sandboxruntime/networkenforcement/linuxrules \
  ./internal/sandboxruntime/networkenforcement/linuxtopology \
  ./internal/sandboxruntime/rootlesspodman \
  ./internal/sandboxruntime/rootlesspodman/l7network \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./internal/sandboxruntime/microvm/firecrackerhost/l7network
```

The fake-only Firecracker profile gate includes bounded `HAL_L7_JOBS`
validation in both host/container scripts, L5 boot-critical source/effective
configuration preservation, final-rootfs privilege assertions, strict `/30`
and `/126` point-to-point boot configuration, verified L7 descriptor
correlation, and request-environment rejection of lowercase proxy names.

The focused Firecracker guest process proof lane is:

```sh
go test -count=1 -timeout=180s \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server \
  ./internal/sandboxruntime/microvm/guestnetwork \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./cmd/hal-guest-agent

go test -race -count=1 -timeout=240s \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server \
  ./internal/sandboxruntime/microvm/guestnetwork \
  ./internal/sandboxruntime/microvm/firecrackerhost

go test -count=25 -timeout=300s \
  ./internal/sandboxruntime/microvm/guestagent/server \
  ./internal/sandboxruntime/microvm/guestnetwork \
  ./internal/sandboxruntime/microvm/firecrackerhost
```

These gates lock old/new JSON compatibility, strict unknown/duplicate/size
handling, request and runtime-generation correlation, partial/stale proof
rejection, every capability/identity/no-new-privileges/group failure, exact
raw-packet denial errno semantics, injected-boundary ordering, error redaction,
pre-proof work rejection, and concurrency/repetition. Non-Linux construction
fails closed. Default L5 and non-L7 readiness omits the optional fields and
retains its previous behavior.

The proof reports network status as unavailable unless the explicit L7 command
composition injects the production guest-network verifier. That verifier
reuses only the validated immutable kernel boot expectation, verifies the exact
single-interface/static-route shape and disabled resolver state, then probes the
exact proxy tuple with bounded cancellation. The generic guest process lane
does not infer those values and therefore does not overclaim network proof.

The explicit prepared-host semantic check for the locked keep-caps-off
sequence is:

```sh
go test -count=1 -tags=l7_setpriv_semantics ./tools/microvm/l7 \
  -run '^TestL7SetprivLockedKeepCapsSemantics$'
```

It derives the exact ordered option vector from the production init, queries the
configured subordinate-ID provider through `getsubids`, and maps the current
identity to namespace ID 0 plus exactly one subordinate UID and GID to namespace
ID 1000 in a disposable user namespace. It then executes the real UID/GID 1000
and group-clear transition. Provider queries use an absolute operation deadline,
hard-bounded stdout, discarded stderr, an owned Linux process group, and a small
fixed cleanup allowance. A terminal leader is observed with Linux `waitid`
`WNOWAIT` and remains unreaped while non-leader process-group membership is
eliminated; the leader is then reaped exactly once, with no later group signal.
If terminal observation does not complete after group termination, one owned
`Wait` is still arranged after the final group operation and joined only for the
fixed cleanup allowance; timeout remains a sanitized failure and cannot cause a
second wait or a later process-group signal.
Timeout, cancellation, overflow, nonzero exit, descendant retention, or
malformed output fails closed after exact process-group termination and bounded
pipe drain. A provider descendant that explicitly leaves the owned group is
outside the process-group containment boundary, but an inherited output pipe
cannot retain the query: the owned read end is closed after the fixed drain
allowance, the copier is joined, and the query fails closed. It requires all five
capability sets to be zero, supplementary groups to be empty, `NoNewPrivs` to be
active, and keep-caps to remain locked off. It does not start Firecracker, modify
an image, or run guest work. The final-image verifier is run read-only against
the fresh digest-locked L7 rootfs before the selected Firecracker lane.

The selected local live-process proof runs the real guest-agent verifier after
the production UID/GID 1000, group-clear, capability-clear, and
no-new-privileges transition in a disposable user namespace. Listing and
running the exact test are separate gates; once selected, missing tools,
subordinate-ID mappings, or namespace support is a failure rather than a skip:

```sh
go test -list '^TestL7GuestAgentLiveProcessIsolationSemantics$' \
  -tags=l7_guest_isolation_semantics \
  ./internal/sandboxruntime/microvm/guestagent/server

go test -count=1 -timeout=180s \
  -tags=l7_guest_isolation_semantics \
  ./internal/sandboxruntime/microvm/guestagent/server \
  -run '^TestL7GuestAgentLiveProcessIsolationSemantics$'
```

This selected test starts no Firecracker process and performs no host
namespace, TAP, nftables, proxy, or internet operation. It must execute exactly
one test with zero skips.

## Selected prepared-Linux gates

The owned-namespace topology lane proves exact proxy reachability plus direct
keeper PID/namespace ownership, prompt reap, and process/namespace/descriptor
absence after cleanup:

```sh
go test -count=1 -timeout=90s \
  -tags='l7_linux_network_integration' \
  ./internal/sandboxruntime/networkenforcement/linuxtopology \
  -run '^TestL7PreparedLinuxOwnedNamespacePastaTopology$'
```

The rootless lane requires the global proxy/firewall markers, an L7 Podman
marker, and a named already-local image. It performs no pull:

```sh
go test -count=1 -timeout=5m \
  -tags='network_enforcement_live podman_integration l7_linux_network_integration' \
  ./internal/sandboxruntime/rootlesspodman \
  -run '^TestL7PreparedLinuxRootlessPodmanNetworkTopology$'
```

The Firecracker lane requires the global proxy/firewall markers, Firecracker
live markers, an L7 Firecracker-network marker, a pinned executable, and the
digest-locked L7 distribution:

```sh
go test -race -count=1 -timeout=15m \
  -tags='firecracker_live network_enforcement_live l7_linux_network_integration' \
  ./internal/sandboxruntime/microvm/assets/localresolver \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^TestL7PreparedLinux(NetworkImagePrerequisites|FirecrackerNetworkTopologyE2E)$'
```

Exact marker values and all local paths remain outside documentation and issue
evidence. Once a selected gate begins, missing Linux amd64, writable KVM,
user/network namespace nft capability, pasta, Podman/local image, `/dev/net/tun`,
Firecracker, or locked L7 assets fails rather than skips.

Both live lanes must attempt a raw packet socket after readiness and require a
permission failure. The Podman lane must also inspect the created container's
effective capability/no-new-privileges configuration. The Firecracker lane
must inspect the live guest-agent capability sets and the locked filesystem's
absence of setuid/setgid or file-capability reacquisition paths. These runtime
proofs must correlate to the same topology generation as the inspected rules;
requested drops and image-manifest labels do not count.

## Broad and portability gates

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Verify changed Go files with `gofmt`. Compile affected packages on Linux,
Darwin, FreeBSD, and Windows. Run `golangci-lint` only when installed, and
record unavailability rather than treating the Make target hint as a pass.

```sh
for os in linux darwin freebsd windows; do
  GOOS="$os" GOARCH=amd64 go test -exec=true -count=1 -run '^$' \
    ./internal/sandboxruntime/microvm/guestagent \
    ./internal/sandboxruntime/microvm/guestagent/server \
    ./internal/sandboxruntime/microvm/guestnetwork \
    ./internal/sandboxruntime/microvm/firecrackerhost \
    ./cmd/hal-guest-agent
done
```

## Required evidence

Record the exact stacked base, red-test commits and failures, implementation
and accepted-fix commits, phase head, aggregate merge, focused/race/broad/live
commands and results, zero-skip selected gates, independent reviews, rejected
findings, cleanup inspection, remote SHA, PR state, and L8 handoff. Evidence
must omit raw endpoints, addresses, ports, namespace/socket paths, hostnames,
rule bodies/handles, process IDs, credentials, and identifying host paths.
