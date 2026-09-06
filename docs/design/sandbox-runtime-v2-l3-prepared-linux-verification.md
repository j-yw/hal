# Sandbox Runtime v2 L3 Prepared-Linux Verification

This is the phase L3 verification and prepared-Linux acceptance boundary. It
proves that the daemon-owned rootless Podman job and the sandbox-centric
operator commands converge on one durable execution after the initiating
client process is forcibly lost. It does not replace the L3 recovery
architecture or weaken its fail-closed rules.

## Test isolation and prerequisites

The default verification matrix is fake-only. The live acceptance test is in
`cmd/l3_prepared_linux_e2e_test.go` behind Linux, the existing
`podman_integration` tag, and the distinct `l3_recovery_e2e` build tag. Ordinary
`go test ./...` does not compile or invoke it.

The prepared host must provide:

- Linux and a working same-user rootless Podman service;
- `HAL_PODMAN_TEST_IMAGE`, naming an existing local rootless Podman image;
- an image with `sh`, `setsid --wait`, `ps`, `awk`, `git`, `tar`, and `grep`;
  and
- enough local capacity for one short-lived rootless container and private
  worker/job/execution stores.

The test verifies the image with `podman image exists` and never pulls an
image. Missing prerequisites fail the explicitly invoked test; they never
skip. A skipped required live test is a blocker, not a pass. Prerequisite
failures may name only the prerequisite category and sanitized command
failure; evidence must not publish the image value, socket path, runtime ID,
host path, endpoint, process ID, or credential.

Set the image to a value already present on the prepared host, then run:

```sh
export HAL_PODMAN_TEST_IMAGE='existing-local-image-reference'
go test -count=1 -tags='podman_integration,l3_recovery_e2e' ./cmd -run '^TestL3PreparedLinuxRecoveryE2E$'
```

The live test starts no cloud resource and makes no image pull or other network
request.

## Live acceptance proof

The tagged scenario uses the production rootless Podman command runner, worker
service, private Unix socket server/client, durable worker job store, sandbox
and host registries, execution store, lease store, L3 selection/status/log
functions, runtime-backed collectors, and finalizer. Final-command admission
goes through the production `runSandboxWorkerJob` adoption path used by explicit
worker-backed run/auto execution. The proof includes repeated recovery and
sync-out against the same durable execution.

It proves:

1. A child submitter enters `runSandboxWorkerJob`, using the exact execution ID
   as its caller-stable submission identity. Its production persistence hook
   durably writes the accepted worker-job reference and pending finalization
   before emitting the observer timing signal. The parent reloads and proves
   that manifest state before the initiating client process is killed while
   the job is running. A read-only submission lookup by execution ID finds the
   same job and the worker reports one active sandbox.
2. The durable manifest is rediscovered by sandbox name and run ID. Live
   `sandbox-status-v1` identifies that exact active execution.
3. The operator log path performs bounded log follow and terminal drain through
   `sandboxjob-v1` cursors without canceling or resubmitting work.
4. Repeated recovery and sync-out calls use the same execution lock and
   checkpoints. They deduplicate artifact identities, leave exactly one
   durable lease in `released` state, publish one completed finalization, and
   never invoke host apply.
5. Core state, a recovery patch, reports archive, uncommitted diff, untracked
   file list, and untracked output artifacts are recovered through the real
   worker/runtime copy boundary. Verified store handles are used to inspect the
   output artifacts.
6. Worker and operator active sandbox count projections converge from one to
   zero after the job becomes terminal.
7. After daemon restart, the same job is either proven terminal as `succeeded`,
   `failed`, or `canceled`, or conservatively reported as `unknown` or
   `interrupted`, without rerunning the admitted command. A persistent
   single-run marker proves no second execution occurred.

The successful prepared-host path is expected to retain the already durable
`succeeded` proof across restart. The conservative states remain accepted only
for restart windows where terminal proof cannot be reconstructed; they are
never rendered as active or successful and do not authorize finalization.

## Focused checks

Run the default documentation/tag guard first:

```sh
go test -count=1 ./cmd -run '^TestL3PreparedLinuxVerification'
```

Run the live command separately on the prepared Linux host:

```sh
go test -count=1 -tags='podman_integration,l3_recovery_e2e' ./cmd -run '^TestL3PreparedLinuxRecoveryE2E$'
```

Run the default L3 implementation packages and race gate without live tags:

```sh
go test ./cmd ./internal/sandboxworker ./internal/sandboxexecution
go test -race ./internal/sandboxworker ./internal/sandboxexecution ./cmd
```

## Broad checks

```sh
go test ./...
go test -count=1 -run '^$' ./...
GOOS=linux GOARCH=amd64 go test -count=1 -run '^$' ./...
go vet ./...
make docs-cli
make docs-check
make build
test -z "$(gofmt -l cmd internal)"
git diff --check
```

Run `golangci-lint` only when `command -v golangci-lint` succeeds. When it is
installed, run `golangci-lint run ./...` and distinguish pre-existing
repository findings from changed-code findings. Do not report `make lint` as a
pass merely because the executable was absent.

## Cleanup

The test owns one uniquely named rootless container, one private Unix socket
directory, one private worker job store, one isolated Hal config root, one
execution store, and one submitter child process. Cleanup stops both daemon
instances, kills a still-live child helper, deletes the exact owned container,
and removes the temporary directories. Container deletion failures fail the
test cleanup and must be resolved before acceptance evidence is recorded.

After the test, verify that the unique test container is absent and that no
test helper process or worker socket remains. Do not delete unrelated
containers, images, stores, sockets, processes, leases, or executions.

## Non-goals

No cloud or billed provider calls are authorized. This test does not cover
Firecracker guests, KVM, guest-agent transport, proxy or firewall enforcement,
credential activation, OCI acquisition or trust, strict secure-default
composition, retention pruning, implicit host apply, SSH-machine execution, or
factory execution. It does not promote rootless Podman beyond the documented
local/dev lower-isolation advisory posture.
