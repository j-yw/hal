## hal convert

Convert markdown PRD to JSON

### Synopsis

Convert a markdown PRD file to prd.json format using the hal skill.

Source selection:
- With no argument, scans .hal/prd-*.md and picks newest by modified time.
- If modified times tie, picks lexicographically ascending filename.
- With an explicit argument, uses that exact path.
- Prints "Using source: <path>" once the source is resolved.

Safety controls:
- Default convert does NOT archive existing state.
- --archive archives existing feature state before writing canonical .hal/prd.json.
- --archive is only supported when output is canonical .hal/prd.json.
- Canonical writes are protected from branchName switches; use --archive or --force to override.

Examples:
  hal convert                                # Auto-discover source (no archive)
  hal convert .hal/prd-auth.md              # Explicit source path
  hal convert --archive                      # Archive before writing .hal/prd.json
  hal convert .hal/prd.md --force           # Override branch mismatch guard
  hal convert .hal/prd.md -o custom.json    # Custom output path (no archive)
  hal convert .hal/prd.md --validate        # Also validate after conversion
  hal convert .hal/prd.md -e claude         # Use Claude engine

```
hal convert [markdown-prd] [flags]
```

### Examples

```
  hal convert
  hal convert --archive
  hal convert .hal/prd-auth.md --validate
  hal convert .hal/prd-auth.md --force
  hal convert .hal/prd-auth.md --engine codex
```

### Options

```
      --archive         Archive existing feature state before writing canonical .hal/prd.json
  -e, --engine string   Engine to use (claude, codex, pi) (default "codex")
      --force           Allow canonical overwrite without archive when branch mismatch protection would block
  -h, --help            help for convert
  -o, --output string   Output path (default: .hal/prd.json)
      --validate        Validate PRD after conversion
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

