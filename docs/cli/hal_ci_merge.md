## hal ci merge

Merge the open pull request for the current branch

### Synopsis

Merge the open pull request for the current branch with CI safety guards.

By default this command uses the squash strategy and requires passing CI
status. Use --allow-no-checks only when you intentionally want to override
no-check safety guards. Use --dry-run to preview behavior without merge or
remote branch deletion side effects. Use --json for machine-readable output.

```
hal ci merge [flags]
```

### Examples

```
  hal ci merge
  hal ci merge --strategy rebase
  hal ci merge --delete-branch
  hal ci merge --dry-run --json
```

### Options

```
      --allow-no-checks   Allow merge when no CI checks are discovered
      --delete-branch     Delete remote branch after successful merge
      --dry-run           Preview merge behavior without merge or remote branch deletion side effects
  -h, --help              help for merge
      --json              Output machine-readable JSON result
      --strategy string   Merge strategy (squash, merge, rebase) (default "squash")
```

### SEE ALSO

* [hal ci](hal_ci.md)	 - Run CI workflow commands

