## hal sandboxd

Start the local sandbox worker daemon

### Synopsis

Start the local sandbox worker daemon.

The daemon serves the sandboxworker-v1 protocol over a local Unix socket. The
command only parses flags, wires worker service/server dependencies, registers
selected runtime drivers, and reports startup or serve errors. Existing
hal sandbox subcommands continue to manage durable sandbox records separately.

Custom rootless Podman images do not accept daemon-owned jobs unless the operator
passes --image-job-execution-supported to attest the image has the required shell
and process-supervision utilities. This is not image verification and does not
upgrade container isolation, network enforcement, or credential protection.

RUNTIME_DIR below is a documentation placeholder, not a literal path. On
supported Unix platforms, it is selected at runtime from a validated private
XDG_RUNTIME_DIR/hal-sd location, or a private per-user directory under the system
temporary directory. Other platforms do not support the private runtime directory.

```
hal sandboxd [flags]
```

### Examples

```
  hal sandboxd
  hal sandboxd --socket /tmp/hal-sandboxd.sock
  hal sandboxd --driver rootless_podman --json
  hal sandboxd --driver rootless_podman --image localhost/hal-agent:custom --image-job-execution-supported
```

### Options

```
      --driver strings                  runtime driver to register with the worker daemon (default [rootless_podman])
  -h, --help                            help for sandboxd
      --image string                    container image for the rootless_podman driver (default "ghcr.io/jywlabs/hal-agent:latest")
      --image-job-execution-supported   operator attestation that the rootless_podman image supports daemon-owned jobs; does not verify the image or strengthen security
      --job-state-dir string            private state directory for durable worker jobs (default "RUNTIME_DIR/jobs")
      --json                            Output machine-readable daemon startup status
      --max-concurrent int              maximum concurrent sandboxes reported by daemon capacity (default 1)
      --podman string                   podman executable for the rootless_podman driver (default "podman")
      --socket string                   Unix socket path for the sandbox worker daemon (default "RUNTIME_DIR/hal-sandboxd.sock")
      --worker-id string                worker identifier to report in daemon status
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
