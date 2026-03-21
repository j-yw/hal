## hal sandbox list

List all sandboxes

### Synopsis

List all sandbox instances from the global registry.

Displays a table with columns: NAME, PROVIDER, STATUS, TAILSCALE, AGE, AUTO-OFF, EST.COST.

Estimated cost is based on embedded hourly rates and time since creation.
Stopped sandboxes still accrue cost (cloud providers charge for allocated resources).
A dash (—) is shown when rate data is unavailable (e.g., Daytona provider).

The default path reads local registry data only and does not call provider APIs.
Use --live to fetch fresh status from each provider before rendering.
Use --json for machine-readable output following the sandbox-list-v1 contract.

```
hal sandbox list [flags]
```

### Examples

```
  hal sandbox list
  hal sandbox list --live
  hal sandbox list --json
```

### Options

```
  -h, --help   help for list
      --json   Output machine-readable JSON (sandbox-list-v1 contract)
      --live   Fetch fresh status from each provider before rendering
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

