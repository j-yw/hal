## hal sandbox ssh

Open an interactive shell or run a remote command

### Synopsis

Open an interactive SSH session to a sandbox, or run a remote command.

With just a name, opens an interactive shell that replaces the current process
for provider-backed sandboxes. Worker-backed sandboxes require a command after
-- because the sandboxd transport does not provide an interactive PTY.
With arguments after --, runs the command in the sandbox. Provider SSH streams
output; worker-backed commands return bounded stdout and stderr after completion
and may be truncated at worker protocol limits.

When no name is provided, the command auto-resolves:
  - If exactly one sandbox exists, it is selected automatically.
  - If zero sandboxes exist, an error is returned.
  - If multiple exist, an error lists the available choices.

The sandbox host determines whether Hal uses provider SSH or sandboxd runtime exec.

Hal redacts addresses from its own connection messages and noninteractive
command output by default. Once an interactive shell starts, remote programs
can still print raw network addresses.

```
hal sandbox ssh [NAME] [-- command args...] [flags]
```

### Examples

```
  hal sandbox ssh my-sandbox
  hal sandbox ssh my-sandbox -- ls -la
  hal sandbox ssh local-worker-check -- sh -lc 'echo ready'
  hal sandbox ssh my-sandbox -- bash -c 'echo hello'
  hal sandbox ssh
```

### Options

```
  -h, --help   help for ssh
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
