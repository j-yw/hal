# Status Contract v1

**Command:** `hal status --json`  
**Contract Version:** 1  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `1` for this contract |
| `workflowTrack` | string | `manual`, `compound`, `review_loop`, or `unknown` |
| `state` | string | One of the state values below |
| `artifacts` | object | Which .hal/ files exist |
| `nextAction` | object | Recommended next command |
| `summary` | string | Human-readable summary |

## Optional Fields (omitempty)

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | Configured default engine name |
| `manual` | object | Story counts, next story, branch (when track is manual) |
| `compound` | object | Pipeline step and branch (when track is compound) |
| `reviewLoop` | object | Latest report path (when review-loop reports exist) |
| `paths` | object | Canonical file paths |

## State Values

| State | Track | Meaning |
|-------|-------|---------|
| `not_initialized` | unknown | No `.hal/` directory |
| `hal_initialized_no_prd` | manual | `.hal/` exists, no `prd.json` |
| `manual_in_progress` | manual | PRD has pending stories |
| `manual_complete` | manual | All stories passed |
| `compound_active` | compound | Auto pipeline in progress |
| `compound_complete` | compound | Auto pipeline step is `done` |
| `review_loop_complete` | review_loop | Review-loop reports exist, no active PRD |

## Next Action IDs

| ID | Command | When |
|----|---------|------|
| `run_init` | `hal init` | Not initialized |
| `run_plan` | `hal plan` | No PRD |
| `run_convert` | `hal convert` | Markdown PRD exists, no JSON |
| `run_manual` | `hal run` | Stories pending |
| `run_report` | `hal report` | All stories complete, no report |
| `run_auto` | `hal auto` | Stories complete + report available |
| `resume_auto` | `hal auto --resume` | Compound pipeline active |

## Example: Manual In-Progress

```json
{
  "contractVersion": 1,
  "workflowTrack": "manual",
  "state": "manual_in_progress",
  "artifacts": {
    "halDir": true,
    "markdownPRD": true,
    "jsonPRD": true,
    "progressFile": true,
    "reportAvailable": false,
    "autoState": false
  },
  "nextAction": {
    "id": "run_manual",
    "command": "hal run",
    "description": "Continue executing the remaining PRD stories."
  },
  "summary": "Manual workflow in progress (3/5 stories complete).",
  "engine": "codex",
  "manual": {
    "branchName": "hal/my-feature",
    "totalStories": 5,
    "completedStories": 3,
    "nextStory": {
      "id": "US-004",
      "title": "Add API endpoint"
    }
  },
  "paths": {
    "prdJson": ".hal/prd.json"
  }
}
```

## Example: Not Initialized

```json
{
  "contractVersion": 1,
  "workflowTrack": "unknown",
  "state": "not_initialized",
  "artifacts": {
    "halDir": false,
    "markdownPRD": false,
    "jsonPRD": false,
    "progressFile": false,
    "reportAvailable": false,
    "autoState": false
  },
  "nextAction": {
    "id": "run_init",
    "command": "hal init",
    "description": "Initialize .hal/ directory."
  },
  "summary": "Hal is not initialized. Run hal init.",
  "engine": "codex"
}
```
