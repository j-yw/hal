## hal analyze

Analyze a report to identify the highest priority item

### Synopsis

Analyze a product/engineering report to identify the highest priority item.

By default, looks for the most recently modified file in .hal/reports/.
You can specify a report file path directly as an argument.

The analysis returns:
  - Priority item title
  - Description of what needs to be built
  - Rationale for prioritization
  - Estimated number of tasks
  - Suggested branch name

Examples:
  hal analyze                           # Analyze latest report
  hal analyze report.md                 # Analyze specific file
  hal analyze --reports-dir ./reports   # Use custom reports directory
  hal analyze --format json             # Output as JSON
  hal analyze --output json             # Deprecated alias for --format

```
hal analyze [report-path] [flags]
```

### Examples

```
  hal analyze
  hal analyze .hal/reports/report.md
  hal analyze --reports-dir ./reports
  hal analyze --format json --engine codex
```

### Options

```
  -e, --engine string        Engine to use (claude, codex, pi) (default "codex")
  -f, --format string        Output format: text (default) or json (default "text")
  -h, --help                 help for analyze
  -o, --output string        [deprecated] Alias for --format
      --reports-dir string   Directory containing reports (overrides config)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

