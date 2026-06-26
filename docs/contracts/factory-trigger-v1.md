# Factory Trigger Contract v1

**Command:** `hal factory trigger --json`
**Contract Version:** `factory-trigger-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory trigger --json` creates a pending factory run from a trigger payload, enqueues it in the durable factory queue, and emits both the created run ID and queue entry. It is intended for cron jobs, GitHub Actions workflows, and other one-shot automation that should not run an always-on webhook server.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-trigger-v1"` for this contract |
| `runId` | string | Created factory run ID |
| `run` | object | Created durable factory run record |
| `entry` | object | Created queue entry using `factory-queue-entry-v1`; omitted for JSON failures that occur after run creation but before enqueue |
| `summary` | string | Short human-readable summary of the trigger enqueue result |

`run` and `entry` are always present on successful JSON output.

## Run Record

The `run` object uses the same durable factory run record shape returned by `factory-status-v1`.

Important fields for trigger consumers:

| Field | Type | Description |
|-------|------|-------------|
| `runId` | string | Created factory run ID; matches the top-level `runId` |
| `status` | string | Initially `pending` |
| `executorMode` | string | Executor mode for the queued worker, currently `local` |
| `engine` | string | Engine snapshot resolved at enqueue time |
| `source` | object | Trigger source metadata |
| `repoPath` | string | Repository path captured from `--repo` |
| `repoRemote` | string | Optional `origin` remote for the repository |
| `branchName` | string | Current branch at enqueue time |
| `baseBranch` | string | Optional target base branch passed with `--base` |
| `currentStep` | string | Initially `queued` after enqueue succeeds |
| `createdAt` | string | RFC3339 timestamp when the run record was created |
| `updatedAt` | string | RFC3339 timestamp when the run was queued |

Supported source kinds are `markdown` for `--prd`, `report` for `--report`, and `report` for scheduled `--discover-report` after discovery selects the latest report. The run-created timeline metadata may record trigger kind `report_discovery` for scheduled discovery runs.

## Queue Entry

The `entry` object uses the reusable queue entry contract documented in `docs/contracts/factory-queue-entry-v1.md`.

Newly created trigger entries have `status` set to `queued`, `attemptCount` set to `0`, and omit `claimedAt`, `completedAt`, `claim`, and `lastError`.

Important queue fields for trigger consumers include `queueId`, `runId`, `executorMode`, `status`, `createdAt`, and `attemptCount`.

## Error Behavior

Missing trigger payloads, conflicting payloads, inaccessible repository paths, missing PRD/report files, empty report discovery results, unsupported executor modes, queue load errors, and queue persistence errors return non-zero command errors. On failures before a run record exists, consumers should treat stdout as undefined and rely on the command exit status.

If `--json` is set and a run record is created but policy or snapshot validation fails before enqueue, stdout uses this `factory-trigger-v1` contract with `run.status` set to `failed` and `entry` omitted. The command still exits non-zero.

## Example Artifact

- `docs/contracts/examples/factory-trigger-v1.json`
