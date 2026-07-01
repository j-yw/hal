## hal sandbox runtime

Inspect sandbox runtime metadata

### Synopsis

Inspect sandbox runtime metadata for registered sandbox hosts.

Runtime inspection is read-only. These commands report cached durable metadata by
default and only attempt live worker inspection when a supported --live flag is
explicitly requested. Output avoids raw socket paths, hostnames, credentials,
URL query strings, temp paths, and sensitive endpoint details.

```
hal sandbox runtime [flags]
```

### Examples

```
  hal sandbox runtime list local-worker
  hal sandbox runtime list local-worker --json
  hal sandbox runtime list local-worker --live
  hal sandbox runtime status local-worker rootless_podman
  hal sandbox runtime status local-worker rootless_podman --json
```

### Options

```
  -h, --help   help for runtime
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
* [hal sandbox runtime list](hal_sandbox_runtime_list.md)	 - List sandbox runtimes for a host
* [hal sandbox runtime status](hal_sandbox_runtime_status.md)	 - Show sandbox runtime status
