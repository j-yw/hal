# Factory Logs Contract v1

**Command:** `hal factory logs <run-id> --json`
**Contract Version:** `factory-logs-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory logs <run-id> --json` reads stored stdout, stderr, or summarized
log chunks from the global factory store after a factory run process exits.
Log text is sanitized before display.

This contract does not change the existing `.hal/prd.json`,
`.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-logs-v1"` for this contract |
| `runId` | string | Stable factory run identifier |
| `chunks` | array | Stored log chunks in append order |

## Log Chunk

Each `chunks` entry contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sequence` | integer | yes | Monotonic per-run log sequence |
| `runId` | string | yes | Stable factory run identifier |
| `stream` | string | no | Log stream: `stdout`, `stderr`, or `summary` |
| `source` | string | no | Log source: `local_factory`, `remote_sandbox`, or `engine` |
| `text` | string | no | Sanitized log text |
| `summary` | string | no | Sanitized summary text when raw text is unavailable |
| `createdAt` | string | no | RFC 3339 timestamp when the chunk was captured |

Sanitization replaces secret-looking values with `[redacted]`.

## Error Behavior

If `<run-id>` does not exist, the command returns a non-zero error with the
message:

```text
factory run "<run-id>" not found
```

If the run exists but has no stored logs, the command succeeds. Table output
prints an empty-state message, and JSON output returns the normal response with
an empty `chunks` array.

Store resolution, directory read, parse, or load failures return a non-zero
command error. On failures, consumers should treat stdout as undefined and rely
on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-logs-v1.json`
