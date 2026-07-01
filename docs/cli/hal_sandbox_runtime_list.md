## hal sandbox runtime list

List sandbox runtimes for a host

### Synopsis

List sandbox runtimes for a registered sandbox host.

Cached mode is the default and reads only durable host metadata. Use --live to
request a supported local worker capability refresh for this response. Use --json
for machine-readable output following the sandbox-runtime-list-v1 contract.

```
hal sandbox runtime list HOST_ID [flags]
```

### Examples

```
  hal sandbox runtime list local-worker
  hal sandbox runtime list local-worker --json
  hal sandbox runtime list local-worker --live
  hal sandbox runtime list local-worker --live --json
```

### Options

```
  -h, --help   help for list
      --json   Output machine-readable JSON (sandbox-runtime-list-v1 contract)
      --live   Refresh runtime metadata from a supported local worker
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox runtime](hal_sandbox_runtime.md)	 - Inspect sandbox runtime metadata
