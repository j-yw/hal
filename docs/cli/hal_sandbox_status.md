## hal sandbox status

Show sandbox status

### Synopsis

Show detailed status of a named sandbox, or list all sandboxes.

When a NAME is provided, queries its provider or worker runtime for live status and displays
identity, networking access state, lifecycle, config, runtime metadata, and
labels. When selected-template runtime metadata is present, the human view shows
sanitized trust, provenance, digest, and blocked readiness reason-code status.

Human output redacts public cloud and Tailscale addresses by default. Use
--show-addresses only when you intentionally need raw network addresses.

When no NAME is provided, delegates to 'hal sandbox list' to show all
sandboxes in the global registry.

```
hal sandbox status [NAME] [flags]
```

### Examples

```
  hal sandbox status my-sandbox
  hal sandbox status
  hal sandbox status NAME --live --json
```

### Options

```
  -h, --help   help for status
      --json   Output machine-readable JSON (sandbox-status-v1 contract)
      --live   Refresh the selected durable worker execution
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
