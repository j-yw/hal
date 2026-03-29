## hal explode

Deprecated shim for 'hal convert --granular'

### Synopsis

Deprecated: use 'hal convert --granular'.

This command is a one-release compatibility shim.
It delegates conversion to:
  hal convert --granular --output .hal/prd.json

Behavior:
- Prints a deprecation warning to stderr.
- Preserves the explode --json output contract.
- Passes through --branch and --engine.

Examples:
  hal explode .hal/prd-feature.md                    # Deprecated shim to convert --granular
  hal explode .hal/prd-feature.md --branch feature   # Pin branchName in generated prd.json
  hal explode .hal/prd-feature.md --engine claude    # Use specific engine
  hal explode .hal/prd-feature.md --json             # Machine-readable explode contract

```
hal explode [prd-path] [flags]
```

### Examples

```
  hal explode .hal/prd-checkout.md
  hal explode .hal/prd-checkout.md --branch checkout
  hal explode .hal/prd-checkout.md --engine codex
  hal explode .hal/prd-checkout.md --json
```

### Options

```
      --branch string   Branch name to pin in generated prd.json
  -e, --engine string   Engine to use (claude, codex, pi) (default "codex")
  -h, --help            help for explode
      --json            Output machine-readable JSON result
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

