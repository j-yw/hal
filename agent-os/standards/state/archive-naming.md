# Archive Naming & Protected Paths

## Archive Directory Naming

Format: `YYYY-MM-DD-feature-name`

- Date prefix from `time.Now().Format("2006-01-02")`
- Feature name from `FeatureFromBranch()` — strips `hal/` prefix, sanitizes slashes to hyphens
- On collision, appends `-2`, `-3`, etc.
- List parsing expects date in `name[:10]`

## What Gets Archived

`featureStateFiles` in `internal/archive/archive.go` defines the files:

```go
var featureStateFiles = []string{
    template.PRDFile,       // prd.json
    template.AutoPRDFile,   // auto-prd.json
    template.ProgressFile,  // progress.txt
    template.AutoStateFile, // auto-state.json
}
```

Plus: `prd-*.md` (glob) and `reports/*` (excluding hidden files).

Update `featureStateFiles` when adding new state files.

## Protected Paths (Never Archived)

```go
var protectedPaths = map[string]bool{
    "config.yaml": true,
    "prompt.md":   true,
    "skills":      true,
    "archive":     true,
    "rules":       true,
}
```

These are project-level configuration, not feature-level state. Archiving them could break the tool entirely.

## Branch Name Parsing

`FeatureFromBranch()` is the canonical parser. All packages delegate to it — never parse branch names independently.
