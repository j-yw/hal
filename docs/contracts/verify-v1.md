# Verify Contract v1

**Command:** `hal verify --json`  
**Contract Version:** `verify-v1`  
**Stability:** Stable. New fields may be added; existing fields will not be removed or renamed.

The verify contract reports configured project verification checks in a machine-readable format. Shell-command checks use the `shell` adapter and include command metadata, timing, gate status, and output artifact references.

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `schemaVersion` | string | Always `"verify-v1"` |
| `generatedAt` | string | RFC 3339 timestamp when the result payload was generated |
| `status` | string | Overall gate status: `pass`, `fail`, or `warn` |
| `summary` | object | Aggregate check counts |
| `checks` | array | Per-check verification results |
| `warnings` | array | Non-fatal verification problems, usually from optional checks |
| `artifacts` | array | Output artifacts produced by verification checks |

## `summary` Fields

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total number of checks evaluated |
| `passed` | integer | Number of checks with status `pass` |
| `failed` | integer | Number of checks with status `fail` |
| `timedOut` | integer | Number of checks with status `timeout` |
| `missing` | integer | Number of checks with status `missing` |
| `skipped` | integer | Number of checks with status `skipped` |
| `warnings` | integer | Number of warning-producing optional check results |

## `checks[]` Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable configured check identifier |
| `name` | string | Human-readable check name |
| `adapter` | string | Check adapter. Shell-command checks use `shell`. |
| `status` | string | Check status: `pass`, `fail`, `timeout`, `missing`, or `skipped` |
| `required` | boolean | Whether this check gates the overall verification result |
| `command` | string | Shell command configured for the check |
| `workDir` | string | Working directory used to run the command |
| `timeoutSeconds` | integer | Configured timeout in seconds |
| `startedAt` | string | RFC 3339 timestamp when the check started |
| `finishedAt` | string | RFC 3339 timestamp when the check finished |
| `durationMs` | integer | Check runtime in milliseconds |
| `exitCode` | integer | Process exit code when a shell command exits |
| `stdoutArtifact` | string | Path to captured stdout artifact, when stdout is captured |
| `stderrArtifact` | string | Path to captured stderr artifact, when stderr is captured |
| `message` | string | Human-readable result detail |

## `warnings[]` Fields

| Field | Type | Description |
|-------|------|-------------|
| `checkId` | string | ID of the check that produced the warning |
| `status` | string | Warning-producing check status |
| `message` | string | Human-readable warning detail |

## `artifacts[]` Fields

| Field | Type | Description |
|-------|------|-------------|
| `checkId` | string | ID of the check that produced the artifact |
| `kind` | string | Artifact kind, such as `stdout` or `stderr` |
| `path` | string | Repository-relative artifact path |

## Status Values

### Top-Level `status`

| Status | Meaning |
|--------|---------|
| `pass` | All required checks passed and no optional check produced a warning |
| `fail` | One or more required checks failed the verification gate |
| `warn` | Required checks passed, but one or more optional checks produced warnings |

Required check failures and timeouts produce a failing gate. A required shell-command check with status `fail` or `timeout` must set the top-level `status` to `fail`.

### Check `status`

| Status | Meaning |
|--------|---------|
| `pass` | Check completed successfully |
| `fail` | Check completed and returned a non-zero exit code |
| `timeout` | Check exceeded `timeoutSeconds` and was terminated |
| `missing` | Check could not run because the command or working directory was unavailable |
| `skipped` | Check was intentionally not run |

## Example Artifacts

- `docs/contracts/examples/verify-v1-pass.json`
- `docs/contracts/examples/verify-v1-fail.json`
- `docs/contracts/examples/verify-v1-warn.json`

## Example

```json
{
  "schemaVersion": "verify-v1",
  "generatedAt": "2026-06-20T12:00:02.100Z",
  "status": "warn",
  "summary": {
    "total": 2,
    "passed": 1,
    "failed": 0,
    "timedOut": 0,
    "missing": 1,
    "skipped": 0,
    "warnings": 1
  },
  "checks": [
    {
      "id": "test",
      "name": "Unit tests",
      "adapter": "shell",
      "status": "pass",
      "required": true,
      "command": "go test ./...",
      "workDir": "/work/hal",
      "timeoutSeconds": 60,
      "startedAt": "2026-06-20T12:00:00Z",
      "finishedAt": "2026-06-20T12:00:02Z",
      "durationMs": 2000,
      "exitCode": 0,
      "stdoutArtifact": ".hal/reports/verify/test-stdout.txt",
      "stderrArtifact": ".hal/reports/verify/test-stderr.txt",
      "message": "check passed"
    },
    {
      "id": "optional-lint",
      "name": "Optional lint",
      "adapter": "shell",
      "status": "missing",
      "required": false,
      "command": "golangci-lint run",
      "workDir": "/work/hal",
      "timeoutSeconds": 120,
      "startedAt": "2026-06-20T12:00:02Z",
      "finishedAt": "2026-06-20T12:00:02Z",
      "durationMs": 0,
      "exitCode": 0,
      "stdoutArtifact": "",
      "stderrArtifact": "",
      "message": "optional check command is unavailable"
    }
  ],
  "warnings": [
    {
      "checkId": "optional-lint",
      "status": "missing",
      "message": "optional check command is unavailable"
    }
  ],
  "artifacts": [
    {
      "checkId": "test",
      "kind": "stdout",
      "path": ".hal/reports/verify/test-stdout.txt"
    },
    {
      "checkId": "test",
      "kind": "stderr",
      "path": ".hal/reports/verify/test-stderr.txt"
    }
  ]
}
```
