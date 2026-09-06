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
| `executorMode` | string | Effective executor used for the run: `local` or `sandbox` |
| `baseBranch` | string | Effective base branch passed to the executor |
| `runner` | object | Optional execution runner summary, including the actual host or sandbox runner used for post-run publish work |
| `publishFrom` | string | Optional normalized publish source request: `host`, `sandbox`, or `auto` |
| `nextAction` | object or null | Recommended follow-up action |
| `artifacts` | array | Artifact references captured for this run |
| `telemetry` | object | Optional compact observability summary including durations, engine, sandbox, outcomes, artifact count, cost estimate, and failure classification |
| `eventSummary` | object | Summary of timeline events recorded for this run |
| `failure` | object or null | Failure details when the run failed |
| `postRun` | object | Optional post-run outcomes such as recovery and publish results |

`executorMode`, `baseBranch`, `artifacts`, and `eventSummary` are always present.
An unavailable executor or unresolved base is represented as an empty string,
and empty artifact state is represented as an empty array. `telemetry` uses
`omitempty` and is present only when run telemetry can be read or derived.

Sandbox-backed runs do not duplicate full sandbox metadata in this compact
result surface. `telemetry.sandbox` may include provider and size for summary
purposes, but consumers that need the sandbox name, lifecycle status, safe
connection display fields, SSH command, cleanup command, or diagnostic handoff
should follow `nextAction.command` and read the durable `factory-status-v1` run
record.

## Effective Executor And Base

`executorMode` and `baseBranch` report the resolved execution inputs, not only
the flags typed for the command. Resolution follows this precedence:

1. Explicit command flags such as `--sandbox` and `--base`.
2. Project `factory.defaults.executor` and `factory.defaults.base` values.
3. For local execution only, the current branch as a safe base fallback.

Sandbox execution never falls back to the current sandbox workspace. If neither
an explicit nor configured base resolves, the command fails before sandbox
execution starts. A local result can contain an empty `baseBranch` only when the
current branch could not be resolved; normal execution then reports the existing
base-resolution failure rather than silently choosing another branch.

## Runner And Publish Metadata

When `runner` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | yes | Runner that performed publish-capable work: `host` or `sandbox` |
| `sandboxName` | string | no | Sandbox name when `mode` is `sandbox` |

`publishFrom` records the normalized operator request. `auto` lets Hal try the
sandbox publisher for sandbox-backed runs and fall back to host-side recovery
publish when needed. `host` publishes from the host worktree. `sandbox` runs the
publish command inside the stored sandbox workspace.

The `postRun` object may contain a `publish` object. When
`postRun.publish` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | no | Publish lifecycle status |
| `policy` | string | no | Publish policy used: `push` or `pr` |
| `branchName` | string | no | Branch that was pushed or used for the pull request |
| `recoveredBundle` | string | no | Store-relative recovery bundle used before host publish |
| `pushed` | boolean | no | Whether a branch push completed |
| `pullRequestUrl` | string | no | Pull request URL when a PR was created |
| `pullRequestId` | integer | no | Pull request number when available |
| `allowUnverified` | boolean | no | Whether an unverified stored run was explicitly allowed |
| `runner` | string | no | Actual publish runner: `host` or `sandbox` |
| `fallbackFrom` | string | no | Failed runner that caused fallback, usually `sandbox` when `publishFrom` was `auto` |
| `credentialMode` | string | no | Credential delivery mode used by the publisher, such as `env` |
| `commit` | string | no | Commit hash observed by the sandbox publisher |
| `attempts` | array | no | Per-runner publish attempts with `runner`, `status`, optional `error`, `startedAt`, and `completedAt` |
| `source` | string | no | Publish initiator such as `automatic` or `manual` |
| `completedAt` | string | no | RFC3339 timestamp when publish metadata was recorded |

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
| `path` | string | no | Local path for file artifacts |
| `storedPath` | string | no | Store-relative path for persisted artifact payloads |
| `sizeBytes` | integer | no | Size of the persisted payload in bytes |
| `createdAt` | string | no | Artifact payload timestamp in RFC3339 format |
| `summary` | object | no | Sanitized artifact-specific metadata |
| `warnings` | array | no | Sanitized warnings about artifact collection |
| `partial` | boolean | no | True when the artifact record is incomplete |

Raw `sourcePath` and `url` fields from stored run records are intentionally omitted from this JSON surface.

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
- `policy_decision`
- `failure_classification`

## Telemetry

When `telemetry` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totalDurationMs` | integer | no | Derived total run duration in milliseconds |
| `stepDurations` | array | no | Derived per-step duration records |
| `engine` | object | no | Engine name and model metadata when available |
| `sandbox` | object | no | Sandbox provider and size telemetry when available |
| `estimatedSandboxCost` | object | no | Estimated sandbox cost when provider, size, pricing, and duration are available |
| `ciOutcome` | string | no | CI outcome when available |
| `verificationOutcome` | string | no | Verification outcome when available |
| `artifactCount` | integer | no | Count of artifact metadata records stored on the run |
| `failureCategory` | string | no | Normalized failure category for failed runs, such as `validation`, `pipeline`, `engine`, `git`, `ci`, or `unknown` |

Each `stepDurations` entry contains `step`, `startedAt`, `finishedAt`, and
`durationMs`. `engine` contains `name` and `model`. `sandbox` contains
`provider` and `size`. `estimatedSandboxCost` contains `amountUsd` and
`estimated`.

## Failure Details

When `failure` is not null:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `classification` | string | yes | Deterministic failure classification |
| `errorMessage` | string | yes | Human-readable error message |
| `suggestedCommand` | string | no | Suggested inspection, retry, or resume command when safely available |

Failure classification values are:

- `validation`
- `pipeline`
- `engine`
- `git`
- `ci`
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
