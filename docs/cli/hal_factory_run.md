## hal factory run

Run a factory executor

### Synopsis

Run the local factory executor by wrapping the existing hal auto compound
pipeline, or pass --sandbox to run the factory executor in a managed sandbox.

Provide at most one positional PRD markdown path to start from an existing
spec, or use --report <path> to start from an analysis report. The positional
path and --report are mutually exclusive. Use --base <branch> to pass a target
base branch to the executor, --sandbox for remote sandbox-backed execution, and
--json for machine-readable factory-run-v1 output.

```
hal factory run [prd-path] [flags]
```

### Examples

```
  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md
  hal factory run .hal/prd-feature.md --base main --json
  hal factory run .hal/prd-feature.md --sandbox
```

### Options

```
      --base string     Target base branch for follow-up review or CI
  -h, --help            help for run
      --json            Output machine-readable JSON (factory-run-v1 contract)
      --report string   Start from an analysis report path
      --sandbox         Run the factory executor in a managed sandbox
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows

