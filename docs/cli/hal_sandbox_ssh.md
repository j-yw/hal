## hal sandbox ssh

Open an interactive shell or run a remote command

### Synopsis

Open an interactive SSH session to the active sandbox, or run a remote command.

With no arguments, opens an interactive shell that replaces the current process.
With arguments after --, runs the command in the sandbox and streams output.

The provider (Daytona or Hetzner) determines the SSH transport.

```
hal sandbox ssh [-- command args...] [flags]
```

### Examples

```
  hal sandbox ssh
  hal sandbox ssh -- ls -la
  hal sandbox ssh -- bash -c 'echo hello'
```

### Options

```
  -h, --help   help for ssh
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

