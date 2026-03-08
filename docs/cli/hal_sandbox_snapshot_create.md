## hal sandbox snapshot create

Create or reuse the template snapshot

### Synopsis

Ensure the template snapshot used by 'hal sandbox start' exists.

The template snapshot name is fixed to "hal" and is built from sandbox/Dockerfile (context ".").
If an active "hal" snapshot already exists, the command reuses it.

```
hal sandbox snapshot create [flags]
```

### Examples

```
  hal sandbox snapshot create
```

### Options

```
  -h, --help   help for create
```

### SEE ALSO

* [hal sandbox snapshot](hal_sandbox_snapshot.md)	 - Manage sandbox snapshots

