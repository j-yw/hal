# Engine Adapter Structure

Each engine lives in its own sub-package under `internal/engine/<name>/`.

## Required Files

| File | Purpose |
|---|---|
| `<name>.go` | Engine struct, `New()`, `Name()`, `CLICommand()`, `BuildArgs()`, and the three prompt methods |
| `parser.go` | `ParseLine([]byte) *Event` — normalizes CLI-specific JSONL into shared `Event` types |
| `sysproc_unix.go` | `newSysProcAttr()` + `setupProcessCleanup(cmd)` (build tag `!windows`) |
| `sysproc_windows.go` | Windows equivalent (build tag `windows`) |

**Parser and sysproc files are required only if the underlying CLI supports streaming JSON output.** A minimal engine that doesn't stream could omit the parser.

## Self-Registration via init()

Engines register themselves in `init()` — no central switch or manual wiring:

```go
func init() {
    engine.RegisterEngine("myengine", func(cfg *engine.EngineConfig) engine.Engine {
        return New(cfg)
    })
}
```

- Adding/removing an engine only touches its own package
- The engine becomes available by import side-effect (e.g., `_ "github.com/jywlabs/hal/internal/engine/myengine"`)
- `engine.Available()` and `engine.New()` discover registered engines automatically
