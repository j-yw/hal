## hal sandbox host status

Show sandbox host status

### Synopsis

Show cached durable sandbox host status.

The command renders cached host registry metadata. It does not contact worker
daemons unless live refresh is explicitly requested by a supported flag. Use
--json for machine-readable output following the sandbox-host-status-v1
contract.

```
hal sandbox host status ID [flags]
```

### Examples

```
  hal sandbox host status local-worker
  hal sandbox host status local-worker --json
  hal sandbox host status local-worker --live
  hal sandbox host status local-worker --live --json
```

### Options

```
  -h, --help   help for status
      --json   Output machine-readable JSON (sandbox-host-status-v1 contract)
      --live   Refresh cached worker metadata from the local worker socket
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox host](hal_sandbox_host.md)	 - Manage sandbox host records
