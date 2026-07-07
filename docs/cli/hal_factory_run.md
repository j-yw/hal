## hal factory run

Run a factory executor

### Synopsis

Run the local factory executor by wrapping the existing hal auto compound
pipeline, or pass --sandbox to run the factory executor in a managed sandbox.

Provide at most one positional PRD markdown path to start from an existing
spec, or use --report <path> to start from an analysis report. The positional
path and --report are mutually exclusive. Use --base <branch> to pass a target
base branch to the executor. Sandbox mode requires --base so the remote
workspace can be checked out deterministically. Use --secret-env to declare
required environment variables that should be resolved only for this run. Use
--sandbox for remote sandbox-backed execution, and --json for machine-readable
factory-run-v1 output.

```
hal factory run [prd-path] [flags]
```

### Examples

```
  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md
  hal factory run .hal/prd-feature.md --secret-env GITHUB_TOKEN
  hal factory run .hal/prd-feature.md --base main --json
  hal factory run .hal/prd-feature.md --sandbox --base main
  hal factory run .hal/prd-feature.md --sandbox --base main --sandbox-host worker-1 --sandbox-runtime rootless_podman
```

### Options

```
      --base string              Target base branch for follow-up review or CI
      --ci-policy string         CI policy for factory runs (required, skip-if-unavailable, disabled)
  -h, --help                     help for run
      --json                     Output machine-readable JSON (factory-run-v1 contract)
      --no-ci                    Alias for --ci-policy disabled
      --publish string           Host publish policy after factory execution (none, push, pr)
      --report string            Start from an analysis report path
      --sandbox                  Run the factory executor in a managed sandbox
      --sandbox-host string      Cached sandbox host ID for target selection
      --sandbox-name string      Sandbox name for --sandbox execution
      --sandbox-runtime string   Cached runtime constraint for target selection (ssh_machine, rootless_podman, microvm)
      --secret-env stringArray   Required environment variable secret for the run (repeatable)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
