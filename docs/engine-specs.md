# AI Engine Specifications

Detailed specifications for each supported AI coding engine.

---

## Claude Code

### Basic Info

| Property | Value |
|----------|-------|
| Name | Claude Code |
| CLI Command | `claude` |
| Default Model | claude-sonnet-4-20250514 |
| Output Format | stream-json |

### Invocation

```bash
claude --dangerously-skip-permissions --verbose --output-format stream-json -p "<prompt>"
```

With model override:
```bash
claude --dangerously-skip-permissions --verbose --output-format stream-json --model sonnet -p "<prompt>"
```

### Windows Handling

On Windows, pass prompt via stdin to avoid cmd.exe argument parsing issues:
```bash
echo "<prompt>" | claude --dangerously-skip-permissions --verbose --output-format stream-json -p
```

### Output Parsing

Stream-json format emits newline-delimited JSON:

```json
{"type":"assistant","message":{"content":"Working on the task..."}}
{"type":"tool","tool":"Read","file_path":"src/index.ts"}
{"type":"result","result":"Task completed successfully","usage":{"input_tokens":1234,"output_tokens":567}}
```

Parse the `result` event for:
- `result`: Final response text
- `usage.input_tokens`: Input token count
- `usage.output_tokens`: Output token count

### Error Detection

Check for error events:
```json
{"type":"error","error":{"message":"Rate limit exceeded"}}
```

### Success Criteria

- Exit code: 0
- No error events in output
- Result event present

---

## OpenCode

### Basic Info

| Property | Value |
|----------|-------|
| Name | OpenCode |
| CLI Command | `opencode` |
| Output Format | JSON |

### Invocation

```bash
OPENCODE_PERMISSION='{"*":"allow"}' opencode run --format json "<prompt>"
```

With model override:
```bash
OPENCODE_PERMISSION='{"*":"allow"}' opencode run --format json --model gpt-4 "<prompt>"
```

### Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `OPENCODE_PERMISSION` | `{"*":"allow"}` | Auto-approve all tool uses |

### Output Parsing

JSON format emits events:

```json
{"type":"text","part":{"text":"Implementing feature..."}}
{"type":"step_finish","part":{"tokens":{"input":500,"output":200},"cost":0.015}}
```

Parse `step_finish` for token counts and cost.
Concatenate all `text` events for the response.

### Success Criteria

- Exit code: 0
- No error events

---

## Cursor Agent

### Basic Info

| Property | Value |
|----------|-------|
| Name | Cursor Agent |
| CLI Command | `cursor` |
| Output Format | text |

### Invocation

```bash
cursor --prompt "<prompt>"
```

### Output Parsing

Plain text output. Success determined by exit code.

### Token Counting

Not available from CLI output. Set to 0.

---

## Codex

### Basic Info

| Property | Value |
|----------|-------|
| Name | Codex |
| CLI Command | `codex` |
| Output Format | JSONL |

### Invocation

```bash
codex exec --dangerously-bypass-approvals-and-sandbox --json -
```

Prompt is passed via stdin (the `-` reads from stdin):
```bash
echo "<prompt>" | codex exec --dangerously-bypass-approvals-and-sandbox --json -
```

### Output Parsing

JSONL format emits newline-delimited JSON events:

```json
{"type":"message.start"}
{"type":"message.delta","delta":{"text":"Working on..."}}
{"type":"tool_use","tool":{"name":"read_file","input":{"path":"src/index.ts"}}}
{"type":"message.done","usage":{"input_tokens":1234,"output_tokens":567}}
```

Parse the `message.done` event for token counts.
Handle `turn.failed` and error events for failure detection.

### Success Criteria

- Exit code: 0
- No error or failed events
- Message done event present

---

## Qwen-Code

### Basic Info

| Property | Value |
|----------|-------|
| Name | Qwen-Code |
| CLI Command | `qwen` |
| Output Format | stream-json |

### Invocation

```bash
qwen --output-format stream-json -p "<prompt>"
```

### Output Parsing

Same stream-json format as Claude. Parse `result` events.

---

## Factory Droid

### Basic Info

| Property | Value |
|----------|-------|
| Name | Factory Droid |
| CLI Command | `droid` |
| Output Format | text |

### Invocation

```bash
droid run "<prompt>"
```

### Output Parsing

Plain text output. Success determined by exit code.

---

## GitHub Copilot

### Basic Info

| Property | Value |
|----------|-------|
| Name | GitHub Copilot |
| CLI Command | `github-copilot-cli` |
| Output Format | text |

### Invocation

```bash
github-copilot-cli "<prompt>"
```

### Output Parsing

Plain text output. Success determined by exit code.

---

## Availability Check

Check if an engine is available:

```go
func CommandExists(command string) bool {
    var checkCmd string
    if runtime.GOOS == "windows" {
        checkCmd = "where"
    } else {
        checkCmd = "which"
    }

    cmd := exec.Command(checkCmd, command)
    return cmd.Run() == nil
}
```

---

## Step Detection (for Progress Spinner)

Parse JSON output to detect current step:

| Pattern | Step Name |
|---------|-----------|
| `tool="Read"` or `tool="Glob"` or `tool="Grep"` | "Reading code" |
| `tool="Write"` or `tool="Edit"` (non-test file) | "Implementing" |
| `tool="Write"` or `tool="Edit"` (test file) | "Writing tests" |
| `command` contains `git commit` | "Committing" |
| `command` contains `git add` | "Staging" |
| `command` contains `lint`, `eslint`, `biome`, `prettier` | "Linting" |
| `command` contains `test`, `jest`, `vitest`, `pytest` | "Testing" |

Test file detection:
```go
func IsTestFile(path string) bool {
    lower := strings.ToLower(path)
    return strings.Contains(lower, ".test.") ||
           strings.Contains(lower, ".spec.") ||
           strings.Contains(lower, "__tests__") ||
           strings.Contains(lower, "_test.go")
}
```

---

## Error Formatting

When engine fails with non-zero exit code:

```go
func FormatCommandError(exitCode int, output string) string {
    trimmed := strings.TrimSpace(output)
    if trimmed == "" {
        return fmt.Sprintf("Command failed with exit code %d", exitCode)
    }

    lines := strings.Split(trimmed, "\n")
    // Show last 12 lines for context
    if len(lines) > 12 {
        lines = lines[len(lines)-12:]
    }

    return fmt.Sprintf("Command failed with exit code %d. Output:\n%s",
        exitCode, strings.Join(lines, "\n"))
}
```
