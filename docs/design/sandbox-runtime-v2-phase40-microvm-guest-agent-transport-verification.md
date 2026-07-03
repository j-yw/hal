# Sandbox Runtime v2 Phase 40 MicroVM Guest Agent Transport Verification

Phase 40 adds a conservative guest-agent transport foundation for Firecracker
microVM readiness, exec, copy-in, and copy-out. It defines protocol and adapter
boundaries without changing the default lifecycle-only microVM posture.

## Implemented Scope

`internal/sandboxruntime/microvm/guestagent` owns the versioned guest-agent
protocol contract. The stable protocol version is `guest-agent-v1`, with
operation identifiers for `readiness`, `exec`, `copy_in`, and `copy_out`.
Request and response DTOs carry bounded command arguments, environment names
and safe sources, guest paths, stream metadata, payload metadata, base64 stream
or copy payload content, and timeout or deadline metadata. Environment values,
credential values, host paths, URLs, headers, request bodies, and Docker socket
details are not protocol fields.

The guest-agent client dispatches readiness, exec, copy-in, and copy-out only
through an injected `guestagent.Transport`. The client enforces encoded request
and response limits, preserves context cancellation and deadlines, rejects
malformed or mismatched responses, and returns redaction-safe public errors.
It does not call Firecracker APIs, use SSH, shell out, open the host Docker
socket, or start guest processes.

`internal/sandboxruntime/microvm/firecrackerhost` owns the Phase 40 host-side
adapters. `GuestAgentTransport` satisfies the existing
`firecracker.GuestTransport` interface and translates Firecracker guest exec and
copy requests into guest-agent protocol requests. Exec stdin, copy-in, and
copy-out payloads are bounded and base64 encoded on the JSON wire. Copy-in
sends only the guest destination path plus bounded payload content. Copy-out
sends only the guest source path and receives bounded payload content.
Host-local copy paths and raw environment values do not cross the protocol
boundary.

`GuestAgentReadinessProbe` adapts guest-agent readiness responses onto the
existing Firecracker guest readiness probe boundary. Guest readiness remains a
separate stage from host Firecracker process and API socket acceptance.

`hal sandboxd` exposes optional guest-agent wiring through
`--firecracker-guest-agent-endpoint`. The configured endpoint must be a local
Unix socket endpoint. When the endpoint is configured and validated,
`NewGuestAgentEndpointAdapters` builds both a guest transport and a guest
readiness probe backed by the same guest-agent protocol client.

Default microVM support remains lifecycle-only unless a tested guest transport
is configured. Default `hal sandboxd` registers only `rootless_podman`, and an
explicit microVM sandboxd driver without `--firecracker-guest-agent-endpoint`
continues to advertise only create, start, stop, delete, and inspect. Exec,
copy-in, and copy-out are advertised for microVM only when the guest-agent
endpoint is explicitly configured.

## Honest Capability Posture

Phase 40 adds a protocol and adapter foundation, not a production guest-agent
implementation. Default command, factory, sandboxexec, scheduler, worker, and
sandboxd paths must not infer microVM exec or copy support from Firecracker
capability, host process acceptance, guest readiness metadata, cached runtime
metadata, or the presence of microVM lifecycle support.

Configured guest-agent transport means a validated local Unix socket endpoint
has been provided and the default fake-backed Phase 40 tests cover the adapter
and protocol paths. It does not mean a production guest agent has been
installed in the guest image, that vsock is implemented, or that live E2E guest
exec and copy have been verified by default.

Host Docker socket access is not part of Phase 40. Guest transport code paths
must not mount, open, dial, or advertise `/var/run/docker.sock`,
`/run/docker.sock`, `docker.sock`, Docker APIs, or `DOCKER_HOST`.

## Verification Commands

Run guest-agent protocol and client coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/guestagent
```

Run focused microVM, Firecracker backend, and Firecracker host adapter coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run command-level Phase 40 documentation, sandboxd, default capability, guest
transport, and guest readiness guard coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase4[0].*MicroVM|Phase4[0].*Firecracker|Sandboxd.*MicroVM|GuestTransport|GuestReadiness'
```

Run worker capability and microVM operation rejection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxworker
```

Run the full repository verification stack:

```sh
go test -count=1 -timeout=420s ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

Passing this matrix satisfies the Phase 40 tests and typecheck gates.

## Fake-Safe Default Scope

Default Phase 40 verification is fake-safe and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images, a live guest, a guest
agent, vsock, SSH, or a running `hal sandboxd`.

Default Phase 40 tests use pure protocol DTOs, injected fake guest-agent
transports, fake guest readiness probes, fake command dependencies, parsed
imports, source guards, JSON redaction assertions, temporary state directories,
and optional endpoint validation only.

Default Phase 40 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
Firecracker process, access KVM, require root, bind network sockets, start
worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs,
invoke Firecracker SDKs, or depend on live providers or runtime adapters.

## Non-Goals

Phase 40 does not implement a production guest agent, concrete vsock transport,
SSH transport, Docker or Podman guest engine, Firecracker SDK integration,
machine configuration API calls, image/rootfs/kernel provisioning, workspace
sync, credential broker/proxy delivery, network proxy/firewall enforcement,
deny-by-default guest networking, jailer/root setup, cgroups, default command
enablement, default worker routing, default scheduler selection, or default
live E2E guest exec and copy verification.

Phase 40 does not make default microVM support more than lifecycle-only. It
does not advertise exec, copy-in, or copy-out for default microVM workers or
for sandboxd microVM drivers without a configured guest-agent endpoint.

## Future Handoff Areas

Future phases are responsible for a real guest-agent implementation, a concrete
vsock or other guest transport, guest image packaging, Firecracker API machine
configuration, secure credential delivery, network policy enforcement, worker
and scheduler registration policy, production endpoint lifecycle management,
live E2E guest readiness, live E2E guest exec and copy, and operator
documentation for preparing guest images.

## Review Notes

Keep Phase 40 protocol contracts isolated from command, factory, worker,
Firecracker backend, and Firecracker host adapter dependencies. Keep the
sandboxd guest-agent endpoint path explicit and optional. When test names,
focused selectors, capability rules, or optional endpoint behavior change,
update this document and `cmd/phase40_microvm_guest_agent_transport_docs_test.go`
together so documented verification commands remain executable, fake-safe by
default, and clear that guest exec and copy require configured guest transport
rather than default microVM lifecycle support.
