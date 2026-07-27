# Sandbox Runtime v2 L5 Firecracker Guest Image and Vsock Verification

This document is the issue #49 L5 verification boundary. The locked issue
comments, Linux completion architecture, L4 architecture, and L5 architecture
remain authoritative.

## Scope

L5 delivers reproducible digest-described kernel/rootfs assets containing the
guest agent, production Firecracker virtio-vsock transport and readiness
composition, proof-gated exec/copy capability, and actual prepared-Linux KVM
guest execution and teardown.

API socket availability, a configured UDS, a downloaded demo image, a skipped
test, or synthetic readiness metadata is not an L5 pass.

## Default red-first matrix

Default tests are deterministic and fake-safe. They lock asset/provenance
schemas and digest checks, machine vsock payload rendering, host CONNECT
framing and bounds, guest listener dispatch and cleanup, readiness correlation,
capability honesty, redaction, cancellation, and lifecycle cleanup. They make
no downloads, mounts, KVM calls, Firecracker launches, cloud calls, or network
connections.

The matrix includes canonical unsigned 32-bit assigned-host-port checks,
including zero, overflow, sign, leading-zero, and reserved
`VMADDR_PORT_ANY` rejection; partial and
pre-acknowledgement data, wrong/stale socket rejection, state/UDS
type-owner-mode and runtime/process/inode correlation, symlink/socket
substitution, Linux `SO_PEERCRED` PID/generation binding, boot/readiness races,
and post-cleanup reconnect failure. The full
config must contain the fixed boot arguments, read-only root drive, guest CID,
and target-owned UDS before process start.

Authorization negatives construct caller-carried ready metadata and
cross-runtime/stale targets and prove they cannot exec or copy without the
backend-owned live-session proof. The matrix invalidates proof on stop, delete,
process exit, restart, bridge loss, and readiness failure. Daemon-wide worker
descriptors remain lifecycle-only, and synthetic isolation labels never become
strict evidence.

Cleanup tests lock an independent cleanup timeout, TERM deadline, KILL
escalation, wait/reap, ownership-proven state deletion, and fail-closed
cleanup uncertainty that cannot become stopped/ready/success.

The docs and source guards require the dedicated guest identity, fixed protocol
CID/port, exact one-request-per-connection framing, no AF_INET fallback, no raw
path/endpoint evidence, and no cross-phase network/credential/OCI behavior.

## Prepared-Linux acceptance

`TestL5PreparedLinuxFirecrackerVsockE2E` is selected only by
`l5_firecracker_vsock_integration`. Once selected it must not skip. It consumes
only the pinned Firecracker binary and assets produced by the checked-in
pipeline, uses a scratch rootfs, and proves real readiness, exec exit/output,
copy integrity, timeout, cancellation, guest-agent failure, escaped-process
containment by VM teardown, and zero owned processes/sockets/state afterward.
The same tag first selects `TestL5PreparedLinuxImagePrerequisites`, with
`HAL_L5_DISTRIBUTION_DIR` naming the caller-installed distribution. That test
must fail, not skip, when the host, architecture, manifest, or installed asset
locks do not satisfy the L5 image contract. It also correlates provenance,
requires the exact `SHA256SUMS` output set and verified bytes, rejects
symlinked/non-directory roots and symlinked/non-regular files, and uses
read-only rootfs inspection to require `/usr/bin/hal-guest-agent`.

Missing prerequisites or a zero-match selector is a failure. Retained evidence
contains versions, digests, safe IDs, pass/fail codes, and cleanup counts only;
it contains no host paths, endpoints, machine identity, credentials, or raw
process arguments.

The asset gate verifies Buildroot `2026.05.1` tag/commit/signed-release
identity, Linux `6.1.178`, BusyBox `1.38.0`, e2fsprogs `1.47.4`, Go `1.25.7`,
Firecracker `v1.15.1`, the full pinned `linux/amd64` Buildroot build-image
digest, every exact offline dependency filename and digest, clean source/tree
identity, deterministic Go/kernel/ext4 controls, `CONFIG_MODULES=n`,
`CONFIG_HW_RANDOM_VIRTIO=y`, and `e2fsck -fn`. It rejects missing and extra
downloads under a real no-network boundary with `BR2_PRIMARY_SITE_ONLY`,
`BR2_DOWNLOAD_FORCE_CHECK_HASHES`, and no ccache.
The build preflights the exact local container image and disables daemon
pulls, so a missing image cannot be satisfied during the offline step.
Canonical cache/output roots require private mode-`0700` ownership; cache
verification includes hidden entries and repeats inside the root-run
container against the expected host UID. Guest Go compilation uses the exact
cached module artifacts with `GOPROXY=off` and `-mod=readonly`.

The e2fsprogs source evidence is specifically the Buildroot-selected
`e2fsprogs-1.47.4.tar.xz` archive. The upstream signed checksum record maps
that filename to
`fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b`;
the lock rejects a suffix/digest pairing from any alternate compression.

The two reproducibility runs use independent clean namespaces/containers but
the same canonical internal Buildroot source and `O=` paths, with fresh
host/staging/target/download state. They export to distinct caller
directories and byte-compare the kernel, rootfs, path-free distribution
manifest, provenance, and checksums. No distribution artifact may contain
either caller path; runtime-materialized launch descriptors are tested
separately and are not reproducibility outputs.

## Focused and broad commands

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/assets/build ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
go test -count=1 -timeout=180s ./cmd -run '^TestL5'
GOOS=darwin GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecrackerhost
GOOS=windows GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecrackerhost
test "$(go env GOOS)" = linux
go test -count=1 -timeout=60s -tags=l5_firecracker_vsock_integration ./internal/sandboxruntime/microvm/assets/localresolver -run '^TestL5PreparedLinuxImagePrerequisites$'
go test -list '^TestL5PreparedLinuxFirecrackerVsockE2E$' -tags=l5_firecracker_vsock_integration ./internal/sandboxruntime/microvm/firecrackerhost | grep -qx 'TestL5PreparedLinuxFirecrackerVsockE2E'
go test -race -count=1 -timeout=900s -tags=l5_firecracker_vsock_integration ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL5PreparedLinuxFirecrackerVsockE2E$'
go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run changed-file gofmt verification. Because `golangci-lint` is installed on
the prepared host, run:

```sh
golangci-lint run --new-from-rev 762ee1a61d2efc5bb9241a6e87409ca20d68f976 ./...
```

## Boundaries

L5 makes no proxy, firewall, topology, credential, OCI, cloud, default-runtime,
or strict-composition change. Those remain L6-L10 work.
