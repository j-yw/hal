# Auto Contract v2

**Command:** `hal auto --json`  
**Contract Version:** 2  
**Stability:** Stable for v2 fields listed below. New optional fields may be added; existing fields and enum values will not be renamed or removed.

## Required Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `2` |
| `ok` | bool | `true` when pipeline completes successfully |
| `entryMode` | string | Entry source: `markdown_path` or `report_discovery` |
| `resumed` | bool | `true` when run started with `--resume` |
| `steps` | object | Fixed step map for pipeline execution |
| `summary` | string | Human-readable summary |

## Optional Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `duration` | string | Total wall-clock duration (for completed/failed runs when available) |
| `error` | string | Top-level failure summary when `ok=false` |
| `dryRun` | bool | Whether execution was only previewed |
| `sandboxPreview` | object | Pure sandbox dry-run intent preview; present only for `hal auto --sandbox --dry-run` |
| `syncOut` | object | Sandbox sync-out summary when `hal auto --sandbox --sandbox-sync-out` or `--sandbox-apply` produced durable local sync-out metadata |
| `syncOutApply` | object | Sandbox apply or handoff result when explicit sandbox sync-out/apply metadata was produced |
| `sandboxExecutionId` | string | Durable execution ID emitted with sandbox sync-out metadata for later `hal sandbox apply EXECUTION_ID` |
| `nextAction` | object | Recommended next command |

## Step Map (Required Keys)

`steps` always contains these keys:

- `analyze`
- `spec`
- `branch`
- `convert`
- `validate`
- `run`
- `review`
- `ci`
- `report`
- `archive`

Each step object contains:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | One of `completed`, `skipped`, `failed`, `pending` |

Additional telemetry fields are optional per step, including:

- `reason` (step-specific reason key)
- `error` (human-readable error)
- `duration`
- `branch`
- `path`
- `tasks`
- `attempts`
- `iterations`
- `issuesFound`
- `fixesApplied`
- `prUrl`

After a successful non-dry-run archive, `steps.archive.path` is the exact
collision-resolved, workspace-relative archive directory (for example,
`.hal/archive/2026-03-29-feature-2`). Dry runs and results from older Hal
versions may omit it.

`steps.convert.reason` is reserved for convert-mode telemetry and uses:

- `standard`
- `granular`

When convert fails, human-readable failure detail should be emitted via
`steps.convert.error` (do not overload `steps.convert.reason` with error text).

## Exit Status

`hal auto --json` writes exactly one `auto-v2` JSON document to stdout. Process
status and the document's `ok` field must be evaluated together:

| Status | Meaning |
|--------|---------|
| `0` | The pipeline result has `ok=true` |
| `2` | Validation or preflight failed; stdout contains `ok=false` JSON |
| `4` | Pipeline execution finished with `ok=false` |

Sandbox execution preserves the inner `hal auto --json` nonzero status. A
rendered JSON failure does not also print the same error to stderr.

For `hal auto --sandbox --dry-run --json`, all required step statuses are
`skipped` because no pipeline or sandbox execution occurs. `sandboxPreview`
describes requested target, runtime, workspace, security, and post-execution
intent. Target/workspace resolution and security enforcement remain
`unresolved`, `resourcesCreated` is `false`, and security `active` is `false`.
The preview contains no durable execution ID and is returned before opening
the execution store or contacting a sandbox boundary.

## Next Action Object

When present:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable action identifier |
| `command` | string | Suggested command |
| `description` | string | Human-readable guidance |

## Sandbox Sync-Out Fields

`syncOut`, `syncOutApply`, and `sandboxExecutionId` are omitted by default.
They are present only for
explicit local sandbox sync-out/apply runs after the remote auto JSON output is
merged with local host-side metadata.

`sandboxExecutionId` selects the exact durable execution for the apply-only
`hal sandbox apply EXECUTION_ID` path. The apply-only command does not launch a
new sandbox execution and accepts only succeeded executions whose collected
PRD shows every story complete and whose stored project and branch match the
current host worktree. When the stored sync ref is a commit, it must also match
the current host HEAD.

`syncOut` is a redaction-safe summary of durable sandbox output. It may include
`workspace`, `committed`, `uncommitted`, `untracked`, `coreArtifacts`,
`recovery`, `warnings`, and `apply`.

`syncOutApply` is the redaction-safe host apply or handoff outcome. It may
include `status`, `applied`, `dryRunPassed`, `artifactId`, `displayName`,
`displayPath`, `mode`, `reasons`, `warnings`, and `handoffInstructions`.

These objects must use durable artifact IDs, display names, relative display
paths, store-relative paths, warning codes, and apply eligibility reasons. They
must not include raw worker endpoints, remote temp paths, host temp paths,
credentials, provider secrets, or secret-bearing repository URLs.

## Example Artifacts

- `docs/contracts/examples/auto-v2-success.json`
- `docs/contracts/examples/auto-v2-failure.json`
- `docs/contracts/examples/auto-v2-sandbox-sync-out.json`
