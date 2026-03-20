## hal sandbox stop

Stop a running sandbox

### Synopsis

Stop a running sandbox.

Reads the sandbox name and provider from .hal/sandbox.json.
The provider is used to determine how to stop the sandbox (daytona CLI, hcloud CLI, or doctl CLI).

```
hal sandbox stop [flags]
```

### Examples

```
  hal sandbox stop
```

### Options

```
  -h, --help   help for stop
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

