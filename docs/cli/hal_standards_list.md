## hal standards list

List configured standards

### Synopsis

Show all standards currently configured for this project.

Reads .hal/standards/index.yml and displays the catalog of standards
organized by domain. If no index exists, lists the .md files found.

With --json, outputs standards count and index as JSON.

```
hal standards list [flags]
```

### Examples

```
  hal standards list
  hal standards list --json
```

### Options

```
  -h, --help   help for list
      --json   Output as JSON
```

### SEE ALSO

* [hal standards](hal_standards.md)	 - Manage project standards

