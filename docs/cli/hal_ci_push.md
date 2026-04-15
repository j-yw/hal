## hal ci push

Push current branch and create or reuse a pull request

### Synopsis

Push the current branch to origin and create or reuse an open pull request.

By default, this command delegates to the shared CI core operation.
Use --dry-run to preview behavior with no remote side effects.
Use --json for machine-readable output.

```
hal ci push [flags]
```

### Examples

```
  hal ci push
  hal ci push --dry-run
  hal ci push --json
```

### Options

```
      --dry-run   Preview push/PR behavior without remote side effects
  -h, --help      help for push
      --json      Output machine-readable JSON result
```

### SEE ALSO

* [hal ci](hal_ci.md)	 - Run CI workflow commands

