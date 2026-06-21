# Factory Run Contract v1

**Command:** `hal factory run --json`
**Contract Version:** `factory-run-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory run --json` emits the final local factory run result for a run
that wraps the existing auto pipeline. The result is compact and intended for
supervisor integrations; use `hal factory status <run-id> --json` to inspect
the full durable run record and timeline.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-run-v1"` for this contract |
| `version` | string | Hal CLI version that produced the result |
| `runId` | string | Stable factory run identifier |
| `status` | string | Final or current run lifecycle status; see status values below |
| `nextAction` | object or null | Recommended follow-up action |
| `artifacts` | array | Artifact references captured for this run |
| `eventSummary` | object | Summary of timeline events recorded for this run |
| `failure` | object or null | Failure details when the run failed |

`artifacts` is always present. Empty artifact state is represented as an empty
array. `eventSummary` is always present.

Sandbox-backed runs do not duplicate full sandbox metadata in this compact
result surface. Consumers that need the sandbox name, provider, lifecycle
status, safe connection display fields, SSH command, cleanup command, or
diagnostic handoff should follow `nextAction.command` and read the durable
`factory-status-v1` run record.

## Next Action

When `nextAction` is not null:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable action identifier |
| `command` | string | Suggested command |
| `description` | string | Human-readable guidance |

## Artifact Reference

Each `artifacts` entry may contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | no | Stable artifact identifier |
| `name` | string | yes | Stable artifact label |
| `type` | string | yes | Artifact category, such as `json`, `markdown`, `text`, or `url` |
| `sourcePath` | string | no | Sanitized source path used when collecting a local artifact |
| `path` | string | no | Local path for file artifacts |
| `storedPath` | string | no | Store-relative path for persisted artifact payloads |
| `url` | string | no | URL for remote artifacts |
| `sizeBytes` | integer | no | Size of the persisted payload in bytes |
| `createdAt` | string | no | Artifact payload timestamp in RFC3339 format |
| `summary` | object | no | Sanitized artifact-specific metadata |
| `warnings` | array | no | Sanitized warnings about artifact collection |
| `partial` | boolean | no | True when the artifact record is incomplete |

## Event Summary

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Count of timeline events recorded for the run |
| `byType` | object | Event count map keyed by event type |
| `lastEventType` | string | Event type of the last recorded event, omitted when no events exist |
| `lastSummary` | string | Summary of the last recorded event, omitted when unavailable |

Known event type values currently include:

- `run_created`
- `step_started`
- `step_ended`
- `command_output_summary`
- `verification_result`
- `ci_state`
- `artifact_sync`
- `failure_classification`

## Failure Details

When `failure` is not null:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `classification` | string | yes | Deterministic failure classification |
| `errorMessage` | string | yes | Human-readable error message |
| `suggestedCommand` | string | no | Suggested inspection, retry, or resume command when safely available |

Failure classification values are:

- `setup`
- `engine`
- `PRD`
- `run`
- `review`
- `verification`
- `CI`
- `sandbox`
- `queue`
- `unknown`

## Status Values

| Status | Meaning |
|--------|---------|
| `pending` | Run record exists but execution has not started |
| `running` | Run is actively progressing |
| `succeeded` | Run completed successfully |
| `failed` | Run reached a terminal failure |
| `canceled` | Run was stopped before completion |

## Error Behavior

Argument validation errors may return a non-zero command error before a run
record exists. Once a run record exists, failed local execution still emits a
`factory-run-v1` JSON result with `status` set to `failed` and `failure`
populated. Store or rendering failures return non-zero command errors. On
non-contract command errors, consumers should treat stdout as undefined and
rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-run-v1.json`
