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
      --driver strings       runtime driver to register with the worker daemon (default [rootless_podman])
  -h, --help                 help for sandboxd
      --json                 Output machine-readable daemon startup status
      --max-concurrent int   maximum concurrent sandboxes reported by daemon capacity (default 1)
      --podman string        podman executable for the rootless_podman driver (default "podman")
      --socket string        Unix socket path for the sandbox worker daemon (default "/tmp/hal-sandboxd.sock")
      --worker-id string     worker identifier to report in daemon status
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
