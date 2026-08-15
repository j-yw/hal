## hal sandboxd

Start the local sandbox worker daemon

### Synopsis

Start the local sandbox worker daemon.

The daemon serves the sandboxworker-v1 protocol over a local Unix socket. The
command only parses flags, wires worker service/server dependencies, registers
selected runtime drivers, and reports startup or serve errors. Existing
hal sandbox subcommands continue to manage durable sandbox records separately.

```
hal sandboxd [flags]
```

### Examples

```
  hal sandboxd
  hal sandboxd --socket /tmp/hal-sandboxd.sock
  hal sandboxd --driver rootless_podman --json
```

### Options

```
      --driver strings                            runtime driver to register with the worker daemon (default [rootless_podman])
      --firecracker-boot-poll-interval duration   host-side Firecracker boot acceptance poll interval; 0 uses the live driver default
      --firecracker-boot-timeout duration         host-side Firecracker boot acceptance timeout; 0 uses the live driver default
      --firecracker-executable string             Firecracker executable path for the microvm driver
      --firecracker-guest-agent-endpoint string   optional local Unix socket endpoint for Firecracker guest-agent readiness, exec, and copy transport
      --firecracker-initrd string                 optional initrd image path for the microvm driver
      --firecracker-jailer string                 optional Firecracker jailer executable path for the microvm driver
      --firecracker-kernel string                 kernel image path for the microvm driver
      --firecracker-rootfs string                 rootfs image path for the microvm driver
      --firecracker-state-dir string              state directory for the microvm driver
  -h, --help                                      help for sandboxd
      --image string                              container image for the rootless_podman driver (default "ghcr.io/jywlabs/hal-agent:latest")
      --job-state-dir string                      private state directory for durable worker jobs (default "/run/user/1000/hal-sd/jobs")
      --json                                      Output machine-readable daemon startup status
      --max-concurrent int                        maximum concurrent sandboxes reported by daemon capacity (default 1)
      --microvm-cpu-count int                     CPU count for the microvm driver (default 2)
      --microvm-disk-mib int                      disk size in MiB for the microvm driver (default 10240)
      --microvm-guest-workdir string              guest workdir for the microvm driver (default "/workspace")
      --microvm-memory-mib int                    memory size in MiB for the microvm driver (default 2048)
      --podman string                             podman executable for the rootless_podman driver (default "podman")
      --socket string                             Unix socket path for the sandbox worker daemon (default "/run/user/1000/hal-sd/hal-sandboxd.sock")
      --worker-id string                          worker identifier to report in daemon status
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
