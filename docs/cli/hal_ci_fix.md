## hal ci fix

Auto-fix failing CI checks using an engine

### Synopsis

Apply focused CI fixes for failing checks using the configured engine.

The command retries up to --max-attempts. Each attempt uses the shared
single-attempt CI fix core operation and waits for fresh CI status before
continuing. Use --json for machine-readable output.

```
hal ci fix [flags]
```

### Examples

```
  hal ci fix
  hal ci fix --max-attempts 3
  hal ci fix -e claude
  hal ci fix --json
```

### Options

```
  -e, --engine string      Engine to use (claude, codex, pi) (default "codex")
  -h, --help               help for fix
      --json               Output machine-readable JSON result
      --max-attempts int   Max fix attempts before stopping (default 3)
```

### SEE ALSO

* [hal ci](hal_ci.md)	 - Run CI workflow commands

