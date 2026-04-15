## hal ci status

Show aggregated CI status for the current branch

### Synopsis

Show aggregated CI status for the current branch.

By default, this command returns the latest aggregated status immediately.
Use --wait to poll until checks complete, timeout, or no checks are detected.
Use --json for machine-readable output.

```
hal ci status [flags]
```

### Examples

```
  hal ci status
  hal ci status --wait
  hal ci status --wait --json
```

### Options

```
  -h, --help                       help for status
      --json                       Output machine-readable JSON result
      --no-checks-grace duration   No-checks grace override before returning no_checks_detected
      --poll-interval duration     Polling interval override while waiting (default: internal ci poll interval)
      --timeout duration           Wait timeout override (default: internal ci wait timeout)
      --wait                       Wait for checks to complete, timeout, or no-check detection
```

### SEE ALSO

* [hal ci](hal_ci.md)	 - Run CI workflow commands

