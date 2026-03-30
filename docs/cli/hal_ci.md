## hal ci

Run CI workflow commands

### Synopsis

Run CI-aware workflow commands.

Use subcommands to push branches, inspect CI status, apply fixes, and merge safely.

Examples:
  hal ci push
  hal ci status --wait
  hal ci fix --max-attempts 2
  hal ci merge --strategy squash

### Examples

```
  hal ci push
  hal ci status --wait
  hal ci fix --max-attempts 2
  hal ci merge --strategy squash
```

### Options

```
  -h, --help   help for ci
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal ci fix](hal_ci_fix.md)	 - Auto-fix failing CI checks using an engine
* [hal ci merge](hal_ci_merge.md)	 - Merge the open pull request for the current branch
* [hal ci push](hal_ci_push.md)	 - Push current branch and create or reuse a pull request
* [hal ci status](hal_ci_status.md)	 - Show aggregated CI status for the current branch

