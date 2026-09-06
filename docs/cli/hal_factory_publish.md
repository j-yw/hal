## hal factory publish

Publish a stored factory run

### Synopsis

Publish the branch associated with a stored factory run. Succeeded runs can
be published directly. Failed or incomplete runs require --allow-unverified so
the operator explicitly acknowledges the unverified result.

```
hal factory publish <run-id> [flags]
```

### Examples

```
  hal factory publish run-20260620-001 --policy push
  hal factory publish run-20260620-001 --allow-unverified --policy pr --json
```

### Options

```
      --allow-unverified         Allow publishing a failed or incomplete stored run
  -h, --help                     help for publish
      --json                     Output machine-readable JSON (factory-publish-v1 contract)
      --policy string            Publish policy for stored run (push, pr)
      --publish-from string      Publish runner for stored run (host, sandbox, auto) (default "host")
      --secret-env stringArray   Required environment variable secret for sandbox publish (repeatable)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
