# Factory Timeline Event Surface

**Surface:** `timeline` array in `hal factory status <run-id> --json`
**Parent Contract:** `factory-status-v1`
**Stability:** Stable as part of `factory-status-v1`. New optional fields may be added with `omitempty`; existing fields and event type values will not be removed or renamed.

Factory timeline events are durable append-only records for one factory run. They are currently exposed through the `timeline` field in `factory-status-v1`.

This surface does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Event Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `sequence` | integer | Monotonic event sequence assigned by the producer |
| `runId` | string | Factory run identifier the event belongs to |
| `eventType` | string | Event type value; see event types below |
| `timestamp` | string | RFC 3339 timestamp of the event |

## Event Optional Fields

These fields use `omitempty` and are only present when the value is non-zero.

| Field | Type | Description |
|-------|------|-------------|
| `message` | string | Human-readable event message |
| `summary` | string | Short event summary suitable for display |
| `metadata` | object | Event-specific structured data |

`metadata` is an open JSON object. Consumers should ignore unknown metadata keys and should use `eventType` to decide whether a metadata key is meaningful.

## Event Types

| Event Type | Meaning |
|------------|---------|
| `run_created` | A factory run record was created |
| `step_started` | A factory step began |
| `step_ended` | A factory step completed, failed, or was skipped |
| `command_output_summary` | A command produced summarized output |
| `verification_result` | A quality or browser verification result was recorded |
| `ci_state` | CI state changed or was observed |
| `artifact_sync` | An artifact was written, copied, uploaded, or linked |
| `failure_classification` | A failure was classified for retry, fix, or handoff |

## Ordering Rules

Events are returned in durable append order as stored in the run timeline file. The `sequence` field is a producer-supplied monotonic value, but the status command does not sort by it before rendering JSON.

Missing timelines are empty state and render as:

```json
"timeline": []
```

Only committed `*.json` timeline files are considered. Temporary and backup artifacts such as `*.tmp` and `*.bak` are ignored.

## Error Behavior

Timeline load or parse failures make the parent `factory-status-v1` command return a non-zero error. On failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-status-v1.json`
