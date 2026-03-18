## hal config

Show current configuration

### Synopsis

Show the current Hal configuration.

Displays settings from .hal/config.yaml if present,
otherwise shows default values.

With --json, outputs the configuration as JSON.

```
hal config [flags]
```

### Examples

```
  hal config
  hal config --json
  hal config add-rule testing
```

### Options

```
  -h, --help   help for config
      --json   Output configuration as JSON
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

