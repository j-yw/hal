## hal sandbox auth

Manage sandbox agent auth profiles

### Synopsis

Manage local agent authentication copied into running sandboxes.

The auth sync flow copies only the small subscription-login profile files needed
by CLIs such as Codex and pi. It avoids caches, logs, sessions, and GitHub CLI
credentials. GitHub authentication is managed separately through sandbox token
setup and gh's credential helper.

### Examples

```
  hal sandbox auth sync my-sandbox
  hal sandbox auth sync --include-claude my-sandbox
```

### Options

```
  -h, --help   help for auth
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
* [hal sandbox auth sync](hal_sandbox_auth_sync.md)	 - Sync Codex and pi auth into a sandbox
