## hal verify

Run configured verification checks

### Synopsis

Run configured project verification checks from .hal/config.yaml.

Verification checks are defined under verify.checks and currently use shell
commands. Required checks fail the verification gate when they fail, time out,
or are missing. Optional checks produce warnings without failing the gate.

With --json, emits the verify-v1 machine-readable contract on stdout. The
command exits 0 for pass and warn results, and exits non-zero for fail results.

Examples:
  hal verify          # Human-readable verification summary
  hal verify --json   # Machine-readable verify-v1 JSON output

```
hal verify [flags]
```

### Examples

```
  hal verify
  hal verify --json
```

### Options

```
  -h, --help   help for verify
      --json   Output machine-readable verify-v1 JSON
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

