## hal sandbox ssh

Open an interactive shell or run a remote command

### Synopsis

Open an interactive SSH session to a sandbox, or run a remote command.

With just a name, opens an interactive shell that replaces the current process.
With arguments after --, runs the command in the sandbox and streams output.

When no name is provided, the command auto-resolves:
  - If exactly one sandbox exists, it is selected automatically.
  - If zero sandboxes exist, an error is returned.
  - If multiple exist, an error lists the available choices.

The provider determines the SSH transport.

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

