# Factory List Contract v1

**Command:** `hal factory list --json`
**Contract Version:** `factory-list-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory list --json` reads the global factory store and emits compact run summaries. It intentionally omits full artifact records and timeline events; use `hal factory status <run-id> --json` for one-run detail.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-list-v1"` for this contract |
| `runs` | array | Run summary objects, newest first |

`runs` is always present. Empty state is represented as an empty array.

## Run Summary Required Fields

These fields are always present on every entry in the `runs` array.

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
| `artifactCount` | integer | Count of full artifact records stored on the run |

## Run Summary Optional Fields

These fields use `omitempty` and are only present when the value is non-zero.

| Field | Type | Description |
|-------|------|-------------|
| `sandboxName` | string | Sandbox name used for the run |
| `finishedAt` | string | RFC 3339 timestamp of terminal completion |
| `failure` | object | Terminal failure summary when the run failed or stopped on a recoverable error |

## Source Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | string | yes | Source kind, such as `markdown`, `report`, or `prd` |
| `path` | string | no | Source file path when the run started from a local file |
| `reportPath` | string | no | Report path when the run started from an analysis report |
| `title` | string | no | Human-readable source title |

## Failure Summary

When `failure` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `step` | string | yes | Step that failed |
| `category` | string | no | Failure category, such as `test`, `review`, or `ci` |
| `message` | string | yes | Human-readable failure summary |
| `recoverable` | boolean | yes | Whether an automated retry or fix can continue the run |
| `exitCode` | integer | no | Process exit code when available and non-zero |

## Status Values

| Status | Meaning |
|--------|---------|
| `pending` | Run record exists but execution has not started |
| `running` | Run is actively progressing |
| `succeeded` | Run completed successfully |
| `failed` | Run reached a terminal failure |
| `canceled` | Run was stopped before completion |

## Ordering Rules

Run summaries are ordered newest-first by the later of `createdAt` and `updatedAt`. When two runs have the same ordering timestamp, `runId` ascending is the stable tie-breaker.

Only committed `*.json` run files are considered. Temporary and backup artifacts such as `*.tmp` and `*.bak` are ignored.

## Error Behavior

Missing factory store directories are treated as empty state and return:

```json
{
  "contractVersion": "factory-list-v1",
  "runs": []
}
```

Store resolution, directory read, parse, or load failures return a non-zero command error. On those failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-list-v1.json`
