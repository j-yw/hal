## hal sandbox auth sync

Sync Codex and pi auth into a sandbox

### Synopsis

Sync local Codex and pi subscription-login auth files into a running sandbox.

By default this copies selected files from ~/.codex and ~/.pi into /root using
tar over the existing sandbox SSH transport. The command does not copy GitHub
CLI credentials, caches, logs, sessions, or entire auth directories.

Use --include-claude to also copy known Claude Code auth/settings files when
they exist locally.

```
hal sandbox auth sync [NAME] [flags]
```

### Examples

```
  hal sandbox auth sync my-sandbox
  hal sandbox auth sync --include-claude my-sandbox
  hal sandbox auth sync
```

### Options

```
  -h, --help             help for sync
      --include-claude   also sync known Claude Code auth/settings files
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox auth](hal_sandbox_auth.md)	 - Manage sandbox agent auth profiles

