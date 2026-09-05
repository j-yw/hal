## hal sandbox runtime status

Show sandbox runtime status

### Synopsis

Show sandbox runtime status for one runtime on a registered host.

Cached mode is the default and reads only durable host metadata. Use --live to
request a supported local worker capability refresh for this response. Use
--json for machine-readable output following the sandbox-runtime-status-v1
contract.

Secure-default readiness is reported truthfully. Strict secure-default readiness
uses security.securityReadinessGate to show whether strict mode reports blocked
decisions when required proof is missing, and compatibility mode reports advisory
diagnostics without claiming live protection, and proof-complete allowed states
include reason-code counts.

The selectedTemplate field summarizes sanitized template identity, trust
decision, provenance status, locked digest, and blocked readiness reason codes
for the requested runtime. Runtime status formats existing metadata only; it
does not parse template references or perform template acquisition.

```
hal sandbox runtime status HOST_ID RUNTIME_ID [flags]
```

### Examples

```
  # Human output shows compatibility advisory or strict allowed/blocked status.
  hal sandbox runtime status local-worker rootless_podman
  hal sandbox runtime status local-worker rootless_podman --json

  # Optional live refresh for the response; live validation remains explicit.
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
