## hal sandbox migrate

Migrate legacy sandbox state to global config

### Synopsis

Migrate legacy project sandbox configuration from .hal/config.yaml to the
global sandbox config location (~/.config/hal/sandbox-config.yaml), and migrate
legacy .hal/sandbox.json state into the global sandbox registry.

This command is non-interactive and safe to run repeatedly — if migration has
already completed or there is nothing to migrate, it reports that and exits.

Migration copies sandbox and daytona configuration sections from the local
project config to the global path. The local .hal/config.yaml is preserved
unchanged. When a legacy .hal/sandbox.json exists, the command verifies the
global registry entry was written successfully and then removes the local state
file.

```
hal sandbox migrate [flags]
```

### Examples

```
  hal sandbox migrate
```

### Options

```
  -h, --help   help for migrate
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

