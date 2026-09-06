## hal sandbox host register

Register a sandbox host

### Synopsis

Register a sandbox host in the durable host registry.

Registration stores host metadata for later listing and status inspection. The
worker subcommand registers local sandbox worker daemon endpoints without
changing sandbox runtime selection defaults.

```
hal sandbox host register [flags]
```

### Examples

```
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live
```

### Options

```
  -h, --help   help for register
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox host](hal_sandbox_host.md)	 - Manage sandbox host records
* [hal sandbox host register worker](hal_sandbox_host_register_worker.md)	 - Register a sandbox worker host
