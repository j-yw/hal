## hal sandbox runtime status

Show sandbox runtime status

### Synopsis

Show sandbox runtime status for one runtime on a registered host.

Cached mode is the default and reads only durable host metadata. Use --live to
request a supported local worker capability refresh for this response. Use
--json for machine-readable output following the sandbox-runtime-status-v1
contract.

```
hal sandbox runtime status HOST_ID RUNTIME_ID [flags]
```

### Examples

```
  hal sandbox runtime status local-worker rootless_podman
  hal sandbox runtime status local-worker rootless_podman --json
  hal sandbox runtime status local-worker rootless_podman --live
  hal sandbox runtime status local-worker rootless_podman --live --json
```

### Options

```
  -h, --help   help for status
      --json   Output machine-readable JSON (sandbox-runtime-status-v1 contract)
      --live   Refresh runtime metadata from a supported local worker
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox runtime](hal_sandbox_runtime.md)	 - Inspect sandbox runtime metadata
