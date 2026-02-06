# Template Constants

All `.hal/` paths are defined in `internal/template/template.go`. Never hardcode them.

## Constants

```go
const HalDir = ".hal"

const (
    PRDFile       = "prd.json"
    AutoPRDFile   = "auto-prd.json"
    PromptFile    = "prompt.md"
    ProgressFile  = "progress.txt"
    AutoStateFile = "auto-state.json"
    ConfigFile    = "config.yaml"
)
```

## Usage

```go
// Correct
configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

// Wrong — hardcoded strings
configPath := filepath.Join(dir, ".hal", "config.yaml")
```

## Embedded Defaults

Template files (`prompt.md`, `progress.txt`, `config.yaml`) are embedded via `//go:embed` and exposed as `DefaultPrompt`, `DefaultProgress`, `DefaultConfig`. `DefaultFiles()` returns the map for `hal init`.

## Adding New State Files

1. Add the constant to `template.go`
2. If it needs a default, embed it and add to `DefaultFiles()`
3. If it should be archived, add to `featureStateFiles` in `internal/archive/archive.go`
