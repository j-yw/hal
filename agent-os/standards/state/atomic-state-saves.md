# Atomic State Saves

Pipeline state is written atomically: temp file → rename.

## Why

If the process is killed mid-write without this pattern:
- **Corrupt JSON**: Partial write leaves a truncated file — pipeline can't resume, user loses progress
- **Inconsistent state**: Pipeline may partially advance and get stuck on resume

## Pattern

```go
func (p *Pipeline) saveState(state *PipelineState) error {
    data, _ := json.MarshalIndent(state, "", "  ")
    tmpPath := statePath + ".tmp"
    os.WriteFile(tmpPath, data, 0644)
    return os.Rename(tmpPath, statePath)  // atomic on most filesystems
}
```

## Rules

- Save state **after each successful step** — enables resume from any point
- Save state **before returning errors** — preserves progress even on failure
- Clear state file on completion or cancellation
- State file location: `.hal/auto-state.json`

## Pipeline Steps

```
analyze → branch → prd → explode → loop → pr → done
```

Each step saves state before advancing. On resume, the pipeline reads the state file and continues from the stored step.
