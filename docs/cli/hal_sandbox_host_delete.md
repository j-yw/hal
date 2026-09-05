## hal sandbox host delete

Delete a sandbox host record

### Synopsis

Delete a durable sandbox host record.

The command removes only host registry metadata. It does not stop worker
daemons or mutate runtime targets.

```
hal sandbox host delete ID [flags]
```

### Examples

```
  hal sandbox host delete local-worker
```

### Options

```
  -h, --help   help for delete
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox host](hal_sandbox_host.md)	 - Manage sandbox host records
