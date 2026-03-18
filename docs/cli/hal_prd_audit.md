## hal prd audit

Audit PRD health and detect drift

### Synopsis

Audit PRD files for health issues and drift.

Checks:
  - Whether prd.json exists and is valid JSON
  - Whether markdown PRD files exist
  - Whether prd.json has stories/userStories
  - Story completion status
  - Whether both markdown and JSON exist (potential drift)

Use --json for machine-readable output.

```
hal prd audit [flags]
```

### Examples

```
  hal prd audit
  hal prd audit --json
```

### Options

```
  -h, --help   help for audit
      --json   Output machine-readable JSON result
```

### SEE ALSO

* [hal prd](hal_prd.md)	 - Manage PRD files

