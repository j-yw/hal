# Continue Contract v1

**Command:** `hal continue --json`  
**Contract Version:** 1  
**Stability:** Stable.

## Purpose

`hal continue` is the single entry point for agents and humans to determine what to do next. It combines workflow state (`hal status`) and environment health (`hal doctor`) into one actionable answer.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `1` |
| `ready` | bool | `true` when doctor passes (no blockers) |
| `status` | object | Full `hal status --json` result |
| `doctor` | object | Full `hal doctor --json` result |
| `nextCommand` | string | The one command to run next |
| `nextDescription` | string | Why this command |
| `summary` | string | Combined human-readable summary |

## Behavior

- When `ready` is `true`: `nextCommand` is the workflow action (e.g., `hal run`)
- When `ready` is `false`: `nextCommand` is the doctor remediation (e.g., `hal init`)

## Example: Healthy, Manual In-Progress

```json
{
  "contractVersion": 1,
  "ready": true,
  "status": {
    "contractVersion": 1,
    "workflowTrack": "manual",
    "state": "manual_in_progress",
    "summary": "Manual workflow in progress (2/5 stories complete)."
  },
  "doctor": {
    "contractVersion": 1,
    "overallStatus": "pass",
    "summary": "Hal is ready to use."
  },
  "nextCommand": "hal run",
  "nextDescription": "Continue executing the remaining PRD stories.",
  "summary": "Manual workflow in progress (2/5 stories complete)."
}
```

## Example: Needs Repair

```json
{
  "contractVersion": 1,
  "ready": false,
  "status": {
    "contractVersion": 1,
    "workflowTrack": "unknown",
    "state": "not_initialized",
    "summary": "Hal is not initialized. Run hal init."
  },
  "doctor": {
    "contractVersion": 1,
    "overallStatus": "fail",
    "primaryRemediation": {"command": "hal init", "safe": true},
    "summary": "Hal is not initialized. Run hal init."
  },
  "nextCommand": "hal init",
  "nextDescription": "Fix environment issues first: Hal is not initialized. Run hal init.",
  "summary": "Hal is not initialized. Run hal init. Hal is not initialized. Run hal init."
}
```
