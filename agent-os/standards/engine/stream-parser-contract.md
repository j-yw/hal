# Stream Parser Contract

Each engine's `parser.go` implements `ParseLine([]byte) *Event` to normalize CLI-specific JSONL into shared event types.

## Event Types to Emit

| EventType | When | Required fields |
|---|---|---|
| `EventInit` | Session/thread start | `Data.Model` (if available) |
| `EventTool` | Tool invocation | `Tool` (lowercase), `Detail` (truncated path/command) |
| `EventText` | Text response chunk | `Detail` (truncated) |
| `EventResult` | Execution complete | `Data.Success`, `Data.Tokens`, `Data.DurationMs` |
| `EventError` | Error occurred | `Data.Message` |

## Common Pitfalls

- **Must emit `EventResult`** — The loop and `parseSuccess()` rely on it to detect completion. Missing this breaks retry logic.
- **Must support text collection** — `StreamPrompt` uses a `textCollectingStreamHandler` that extracts assistant text from raw JSON. Each engine's text extraction differs (Claude: `assistant.message.content[].text`, Codex: `item.completed` with `agent_message`, Pi: `text_end` in `assistantMessageEvent`).

## Stateful vs Stateless

Parser statefulness depends on the CLI's output format:
- **Claude**: Stateless — each line is self-contained
- **Codex**: Tracks `commandFailed`/`turnFailed` flags across lines
- **Pi**: Accumulates `totalTokens`, `hasFailure`, collected `text`

Use whatever the CLI requires. No blanket preference.

## Helper Convention

Each parser re-declares `trimSpace`, `isSpace`, `shortPath`, `truncate` locally (package-scoped). These are intentionally duplicated per engine package to avoid cross-package coupling.
