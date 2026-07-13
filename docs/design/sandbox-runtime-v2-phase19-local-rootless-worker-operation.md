# Sandbox Runtime v2 Phase 19 Local Rootless Worker Operation

Phase 19 documents local rootless worker operation for developers who want to
exercise worker-backed `rootless_podman` sandbox execution on one machine.

Rootless worker execution is explicit opt-in. Default `hal run --sandbox`,
`hal auto --sandbox`, and `hal factory run --sandbox` continue to use the
legacy SSH-machine-compatible path unless a worker target is selected with
`--sandbox-host` or `--sandbox-runtime`.

This mode is local/dev lower-isolation only. It is useful for development and
verification of the worker protocol, command routing, and rootless Podman
adapter behavior on a trusted local machine.

## Prerequisites

- Hal is built or installed from this repository.
- Podman is installed and available to the user running `hal sandboxd`.
- The selected rootless Podman image is already available locally; this guide
  does not require or perform image pulls.
- The worker daemon listens on a local Unix socket such as
  `/tmp/hal-sandboxd.sock`.
- The project has a PRD or report suitable for the command being run.

## Start The Local Worker

Run the worker daemon in a separate terminal:

```sh
hal sandboxd --socket /tmp/hal-sandboxd.sock --worker-id local-worker --driver rootless_podman
```

For machine-readable startup output:

```sh
hal sandboxd --socket /tmp/hal-sandboxd.sock --worker-id local-worker --driver rootless_podman --json
```

If Podman is not available, `hal sandboxd` reports `runtime_unavailable` and
does not register the `rootless_podman` worker driver.

## Register The Worker Host

Register the local daemon in the durable host registry:

```sh
hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live
```

The command stores the worker host record and refreshes safe runtime metadata
from the daemon. Human and JSON output summarize the endpoint as
`local Unix socket`; raw socket paths are not printed in normal host output.

## Run Selected Sandbox Commands

Select the worker/rootless target explicitly for `hal run`:

```sh
hal run --sandbox --sandbox-host local-worker --sandbox-runtime rootless_podman
```

Select the worker/rootless target explicitly for `hal auto`:

```sh
hal auto --sandbox --sandbox-host local-worker --sandbox-runtime rootless_podman
```

To create or reuse an exact sandbox identity on that worker, add
`--sandbox-name`. A missing name is created through the selected worker runtime;
an existing name is validated against the requested host and runtime before it
is reused:

```sh
hal auto --sandbox --sandbox-name local-worker-check --sandbox-host local-worker --sandbox-runtime rootless_podman
```

Select the worker/rootless target explicitly for `hal factory run`:

```sh
hal factory run .hal/prd-feature.md --sandbox --base <base-branch> --sandbox-host local-worker --sandbox-runtime rootless_podman
```

`--sandbox-host local-worker` selects the durable worker host. The runtime
constraint keeps the command on the `rootless_podman` worker-backed route
instead of an SSH-machine-compatible target.

## Limitations

Local rootless worker operation does not provide microVM isolation. It also
does not provide scheduler behavior, does not enforce network policy, does not
provide proxy or firewall enforcement, and does not provide secret broker
support.

The enforced security posture for the local rootless worker is container
isolation with best-effort network policy metadata and no network enforcement.
Treat the daemon, socket, and containers as local developer resources.

## Cleanup

Remove the durable worker host record when it is no longer needed:

```sh
hal sandbox host delete local-worker
```

Stop the `hal sandboxd` process in the terminal where it is running. If the
daemon exits unexpectedly and leaves a stale socket behind, remove
`/tmp/hal-sandboxd.sock` before starting a new daemon on the same path.

Rootless Podman containers created by failed manual experiments should be
inspected and removed with Podman using the container names reported by the
failing command or integration test.

## Optional Integration Check

Real worker/rootless integration coverage is opt-in and build-tagged:

```sh
go test -timeout=120s -tags=worker_integration ./cmd -run TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver -count=1 -v
```

The test skips unless all required variables are set:

- `HAL_WORKER_INTEGRATION_ENDPOINT`
- `HAL_WORKER_INTEGRATION_HOST_NAME`
- `HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=rootless_podman`
- `HAL_WORKER_INTEGRATION_IMAGE`

Example environment for a local daemon:

```sh
export HAL_WORKER_INTEGRATION_ENDPOINT=unix:///tmp/hal-sandboxd.sock
export HAL_WORKER_INTEGRATION_HOST_NAME=local-worker
export HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=rootless_podman
export HAL_WORKER_INTEGRATION_IMAGE=localhost/hal-worker-test:latest
```

Run the integration check only when the daemon is already running and the image
exists locally. Default test runs must remain free of Podman, worker daemons,
network access, provider credentials, and untagged worker integration behavior.
