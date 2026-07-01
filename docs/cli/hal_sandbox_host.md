## hal sandbox host

Manage sandbox host records

### Synopsis

Manage durable sandbox host records.

Worker host records describe local sandbox worker daemon endpoints and cached
capability metadata. These commands operate on the durable host registry only;
they do not provision, start, stop, or delete runtime targets.

```
hal sandbox host [flags]
```

### Examples

```
  hal sandbox host list
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live
  hal sandbox host status local-worker
  hal sandbox host delete local-worker
```

### Options

```
  -h, --help   help for host
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
* [hal sandbox host delete](hal_sandbox_host_delete.md)	 - Delete a sandbox host record
* [hal sandbox host list](hal_sandbox_host_list.md)	 - List sandbox host records
* [hal sandbox host register](hal_sandbox_host_register.md)	 - Register a sandbox host
* [hal sandbox host status](hal_sandbox_host_status.md)	 - Show sandbox host status
