## hal sandbox host register worker

Register a sandbox worker host

### Synopsis

Register a sandbox worker host in the durable host registry.

The command accepts a worker identity and local socket endpoint. Worker host
records describe sandbox daemon endpoints without changing sandbox runtime
selection defaults.

```
hal sandbox host register worker ID [flags]
```

### Examples

```
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live
```

### Options

```
  -h, --help            help for worker
      --live            Query the worker daemon once and persist live metadata
      --socket string   Local Unix socket path for the sandbox worker
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox host register](hal_sandbox_host_register.md)	 - Register a sandbox host
