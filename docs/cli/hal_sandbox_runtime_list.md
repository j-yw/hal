## hal sandbox runtime list

List sandbox runtimes for a host

### Synopsis

List sandbox runtimes for a registered sandbox host.

Cached mode is the default and reads only durable host metadata. Use --live to
request a supported local worker capability refresh for this response. Use --json
for machine-readable output following the sandbox-runtime-list-v1 contract.

Secure-default readiness is reported truthfully. Strict secure-default readiness
uses security.securityReadinessGate to show whether strict mode reports blocked
decisions when required proof is missing, and compatibility mode reports advisory
diagnostics without claiming live protection, and proof-complete allowed states
include reason-code counts.

Each runtime entry includes selectedTemplate status with sanitized template
identity, trust decision, provenance status, locked digest, and blocked readiness
reason codes. Runtime listing does not acquire templates or contact live
template sources; acquisition remains fake/local unless an explicit lower-level
template acquisition path is invoked.

```
hal sandbox runtime list HOST_ID [flags]
```

### Examples

```
  # Cached compatibility advisory metadata.
  hal sandbox runtime list local-worker
  hal sandbox runtime list local-worker --json

  # Optional live refresh for the response; live validation remains explicit.
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
