# Three Prompt Modes

Every engine implements three methods. Each serves different callers and output needs.

## Methods

| Method | Returns | Streaming | Used By |
|---|---|---|---|
| `Execute(ctx, prompt, display) Result` | `Result` struct (Success, Complete, Output, Duration) | Yes — JSONL parsed via display | Loop (`internal/loop`) for story execution |
| `Prompt(ctx, prompt) (string, error)` | Raw text | No | PRD generation, validation, simple single-shot calls |
| `StreamPrompt(ctx, prompt, display) (string, error)` | Collected text | Yes — display shows progress | Conversion, review, any call needing both UI feedback and text output |

## Timeout & Error Pattern

All three modes follow the same pattern:

```go
ctx, cancel := context.WithTimeout(ctx, timeout)
defer cancel()

// ... run command ...

if err != nil {
    if ctx.Err() == context.DeadlineExceeded {
        return ..., fmt.Errorf("... timed out after %s", timeout)
    }
    return ..., fmt.Errorf("... failed: %w (stderr: %s)", err, stderr.String())
}
```

This is currently duplicated per method per engine. Could be extracted into a shared helper eventually, but keeping it explicit is acceptable for now.

## Completion Detection

`Execute` checks for `<promise>COMPLETE</promise>` in output to set `Result.Complete`. This signals the loop that all tasks are done.

## Prompt Delivery

- **Claude**: Prompt passed as CLI argument (last arg)
- **Codex/Pi**: Prompt piped via stdin (`strings.NewReader(prompt)`) to avoid OS arg length limits
