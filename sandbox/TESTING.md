# Sandbox Testing

This document covers how to run sandbox smoke tests and integration tests, both locally and in CI.

## Smoke Tests (Docker)

Smoke tests verify that all tools are installed correctly inside the sandbox Docker image.

### Run locally

```bash
# Build image and run smoke tests
make sandbox-test

# Or manually:
docker build -f sandbox/Dockerfile -t hal-sandbox .
docker run --rm hal-sandbox /test.sh
```

### CI behavior

The `sandbox-build` and `sandbox-test` jobs in `.github/workflows/ci.yml` build the Docker image and run `/test.sh` on every push and PR to `main`, `develop`, `sandbox*`, and `compound/sandbox*` branches. The `sandbox-test` job uses path filtering — it only runs the smoke tests when files under `sandbox/` or the `Makefile` change.

## Contained Podman lab

Use `sandbox/podman-lab.sh` for local rootless Podman and `sandboxd` testing. The
script owns an isolated home directory, Hal config root, XDG config/data/cache
roots, temp root, local Hal binary, disposable repository clones, daemon socket,
image, and named Podman machine. It does not install the feature binary or write
runtime state to the normal user configuration. `seed-auth` explicitly copies
supported Codex, Pi, and Claude auth files into the isolated home when live agent
execution is required. A custom `HAL_SANDBOX_LAB_ROOT` must be absolute and use
a `hal-sandbox-*` leaf directory so teardown cannot target a broad filesystem
path.

When host TUN/DNS routing cannot reach registries directly, set separate proxy
URLs instead of disabling TLS. `HAL_SANDBOX_LAB_HOST_PROXY` is used only while
the host downloads the Podman machine image. `HAL_SANDBOX_LAB_GUEST_PROXY` is
used only for image build traffic inside the Podman VM. Neither value is stored
in the lab manifest.

On Linux hosts where `podman machine info` reports the QEMU provider, install
the host QEMU image tool and architecture-specific system emulator before
preparing the lab. The prepare command checks these prerequisites before it
downloads a machine image. On Arch Linux, install the complete headless set with:

```sh
sudo pacman -S --needed qemu-base
```

```sh
export HAL_SANDBOX_LAB_HOST_PROXY=http://127.0.0.1:PORT
export HAL_SANDBOX_LAB_GUEST_PROXY=http://host.containers.internal:PORT
make sandbox-lab-prepare
make sandbox-lab-start
./sandbox/podman-lab.sh seed-auth
./sandbox/podman-lab.sh clone /path/to/browser-game browser-game
./sandbox/podman-lab.sh run -- hal sandbox host status hal-lab-worker --live
./sandbox/podman-lab.sh run -- hal factory run --sandbox --base main \
  --sandbox-host hal-lab-worker --sandbox-runtime rootless_podman
make sandbox-lab-destroy
```

Run `make sandbox-lab-destroy` after testing. It deletes registered lab
sandboxes through Hal while the daemon is available, stops the daemon, removes
remaining Hal-labeled containers, deletes the named Podman machine, and removes
the lab root.

## Runtime Integration Tests

Runtime integration tests are opt-in and use provider-independent local
resources. The default `go test ./...` suite remains deterministic and does not
require cloud credentials, Podman, Firecracker, or KVM.

### Rootless Podman

Set `HAL_PODMAN_TEST_IMAGE` to a locally available image, then run:

```bash
HAL_PODMAN_TEST_IMAGE=hal-sandbox:latest \
  go test -tags=podman_integration -v -timeout 5m \
  ./internal/sandboxruntime/rootlesspodman
```

The test exercises create, start, inspect, exec, copy, stop, and delete. It
skips when the image is not configured or Podman is unavailable.

### Firecracker

The Firecracker live test requires a Linux KVM host plus explicit executable,
kernel, and root filesystem paths. Run:

```bash
HAL_FIRECRACKER_LIVE_FIRECRACKER=/path/to/firecracker \
HAL_FIRECRACKER_LIVE_KERNEL=/path/to/vmlinux \
HAL_FIRECRACKER_LIVE_ROOTFS=/path/to/rootfs.ext4 \
  go test -tags=firecracker_live -v -timeout 5m \
  ./internal/sandboxruntime/microvm/firecracker
```

The test validates a real boot/start/stop/delete lifecycle and skips with a
clear prerequisite message when the host cannot run it.

### CI behavior

The `integration-test` job compiles and runs the opt-in runtime test packages.
On ordinary GitHub-hosted runners, live cases skip because their explicit local
prerequisites are absent. No cloud-provider secrets are read by the workflow.
