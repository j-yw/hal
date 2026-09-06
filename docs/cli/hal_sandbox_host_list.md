## hal sandbox host list

List sandbox host records

### Synopsis

List durable sandbox host records.

The command renders host registry metadata in stable human-readable output. It
sorts records by host name, then id, and does not contact worker daemons or
runtime providers. Use --json for machine-readable output following the
sandbox-host-list-v1 contract.

```
hal sandbox host list [flags]
```

### Examples

```
  hal sandbox host list
  hal sandbox host list --json
```

### Options

```
  -h, --help   help for list
      --json   Output machine-readable JSON (sandbox-host-list-v1 contract)
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox host](hal_sandbox_host.md)	 - Manage sandbox host records
