## hal factory open

Open handoff guidance for a factory run

### Synopsis

Open handoff guidance for one stored factory run from the global factory
store.

By default this command prints the best inspection, takeover, or resume command
without executing it. Failed sandbox runs point to the sandbox SSH command.
Failed local runs show repository context and resume guidance when saved auto
state permits continuation. Pass --exec to execute only the generated safe Hal
command. Pass --json to emit the factory-open-v1 contract without executing
handoff commands.

```
hal factory open <run-id> [flags]
```

### Examples

```
  hal factory open run-20260620-001
  hal factory open run-20260620-001 --exec
  hal factory open run-20260620-001 --json
```

### Options

```
      --exec   Execute the suggested inspection or resume command
  -h, --help   help for open
      --json   Output machine-readable JSON (factory-open-v1 contract)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
