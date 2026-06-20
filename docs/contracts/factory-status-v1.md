# Factory Status Contract v1

**Command:** `hal factory status <run-id> --json`
**Contract Version:** `factory-status-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory status <run-id> --json` reads one run from the global factory store and emits the complete run record plus timeline events. This is the detail surface for artifacts, failures, and event history.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-status-v1"` for this contract |
| `run` | object | Full factory run record |
| `timeline` | array | Timeline event records in append order |

`timeline` is always present. A run with no stored events emits an empty array.

## Run Record Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `runId` | string | Stable factory run identifier |
| `status` | string | Run lifecycle status; see status values below |
| `source` | object | Input source metadata for the run |
| `repoPath` | string | Repository path recorded for the run |
| `repoRemote` | string | Repository remote recorded for the run |
| `branchName` | string | Feature branch associated with the run |
| `baseBranch` | string | Base branch used for the run |
| `currentStep` | string | Current or terminal factory step |
| `createdAt` | string | RFC 3339 timestamp of run creation |
| `updatedAt` | string | RFC 3339 timestamp of the last run update |

## Run Record Optional Fields

These fields use `omitempty` and are only present when the value is non-zero.

| Field | Type | Description |
|-------|------|-------------|
| `sandboxName` | string | Sandbox name used for the run |
| `executorMode` | string | Factory executor mode that produced the run record |
| `finishedAt` | string | RFC 3339 timestamp of terminal completion |
| `artifacts` | array | Full artifact references associated with the run |
| `verification` | object | Verification summary and artifact references recorded from `hal verify --json` |
| `failure` | object | Terminal failure summary when the run failed or stopped on a recoverable error |

## Source Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | string | yes | Source kind, such as `auto_discovery`, `markdown`, `report`, or `prd` |
| `path` | string | no | Source file path when the run started from a local file |
| `reportPath` | string | no | Report path when the run started from an analysis report |
| `title` | string | no | Human-readable source title |

## Artifact Reference

When `artifacts` is present, each entry may contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Stable artifact label |
| `type` | string | yes | Artifact category, such as `json`, `markdown`, `text`, or `url` |
| `path` | string | no | Local path for file artifacts |
| `url` | string | no | URL for remote artifacts |

## Verification Record

When `verification` is present, it contains metadata copied from the `verify-v1` result:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `summary` | object | yes | Aggregate verification counts |
| `artifacts` | array | no | Verification artifact references emitted by `hal verify --json` |

The `summary` object uses the `verify-v1` summary field names:

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total verification checks |
| `passed` | integer | Checks with `pass` status |
| `failed` | integer | Checks with `fail` status |
| `timedOut` | integer | Checks with `timeout` status |
| `missing` | integer | Checks with `missing` status |
| `skipped` | integer | Checks with `skipped` status |
| `warnings` | integer | Warning-producing optional checks |

Each verification artifact reference uses the `verify-v1` artifact shape:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `checkId` | string | yes | Verification check identifier |
| `kind` | string | yes | Artifact kind, such as `stdout` or `stderr` |
| `path` | string | yes | Local path emitted by `hal verify --json` |

## Failure Summary

When `failure` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `step` | string | yes | Step that failed |
| `category` | string | no | Failure category, such as `validation`, `pipeline`, `engine`, `git`, `ci`, or `unknown` |
| `message` | string | yes | Human-readable failure summary |
| `recoverable` | boolean | yes | Whether an automated retry or fix can continue the run |
| `suggestedCommand` | string | no | Suggested inspection, retry, or resume command when safely available |
| `exitCode` | integer | no | Process exit code when available and non-zero |

## Status Values

| Status | Meaning |
|--------|---------|
| `pending` | Run record exists but execution has not started |
| `running` | Run is actively progressing |
| `succeeded` | Run completed successfully |
| `failed` | Run reached a terminal failure |
| `canceled` | Run was stopped before completion |

## Executor Mode Values

| Mode | Meaning |
|------|---------|
| `local` | Run was executed by the local factory executor wrapping the local auto pipeline |

## Timeline

The `timeline` array uses the factory timeline event surface documented in `docs/contracts/factory-timeline-v1.md`.

Timeline events are returned in stored append order. Consumers must not assume the array is sorted by `sequence`, because records preserve durable append order for auditability.

## Error Behavior

If `<run-id>` does not exist, the command returns a non-zero error with the message:

```text
factory run "<run-id>" not found
```

No JSON payload is written for missing run IDs. Store resolution, run parse, or timeline load failures also return non-zero command errors. On failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-status-v1.json`
