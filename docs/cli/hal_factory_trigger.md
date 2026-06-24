## hal factory trigger

Create queued factory runs from trigger payloads

### Synopsis

Create a queued factory run from external trigger context without starting
an always-on server.

Pass exactly one source payload: --prd <path>, --report <path>, or
--discover-report. Use --repo <path> to target a repository explicitly from
cron jobs or GitHub Actions workflows. The command creates a pending factory
run record, enqueues it in the durable factory queue, and exits. A separate
worker can later process the entry with hal factory queue work.

```
hal factory trigger [flags]
```

### Examples

```
  hal factory trigger --repo . --prd .hal/prd-feature.md
  hal factory trigger --repo /work/hal --report .hal/reports/analysis.md --json
  hal factory trigger --repo /work/hal --discover-report --json
```

### Options

```
      --base string          Target base branch for follow-up review or CI
      --discover-report      Discover the latest report from the repository reports directory
      --executor string      Factory executor mode for the queued run (default "local")
  -h, --help                 help for trigger
      --json                 Output machine-readable JSON (factory-trigger-v1 contract)
      --prd string           Markdown PRD path for the queued run
      --repo string          Repository path for the queued run (default ".")
      --report string        Analysis report path for the queued run
      --reports-dir string   Reports directory override for --discover-report
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
