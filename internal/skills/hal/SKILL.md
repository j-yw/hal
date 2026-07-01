---
name: hal
description: Convert markdown PRDs into canonical .hal/prd.json for Hal's single auto pipeline runtime.
disable-model-invocation: true
---

# Hal PRD Converter

Convert a markdown PRD into canonical `.hal/prd.json`.

`.hal/prd.json` is the runtime PRD source for `hal auto` and all downstream pipeline gates. Do **not** write `.hal/auto-prd.json`.

## Process

1. Resolve source markdown:
   - If an explicit PRD markdown path is provided, use it.
   - Otherwise, discover the newest `.hal/prd-*.md` file.
2. Convert each requirement into a user story in the JSON format below.
3. Validate stories against the rules below.
4. Write the result to `.hal/prd.json`.

## Output Format

```json
{
  "project": "[Project Name]",
  "branchName": "hal/[feature-name-kebab-case]",
  "description": "[Feature description]",
  "userStories": [
    {
      "id": "US-001",
      "title": "[Story title]",
      "description": "As a [user], I want [feature] so that [benefit]",
      "acceptanceCriteria": ["Criterion 1", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    },
    {
      "id": "US-002",
      "title": "[Story title]",
      "description": "As a [user], I want follow-up work so that [benefit]",
      "acceptanceCriteria": ["Criterion 1", "Typecheck passes"],
      "priority": 2,
      "passes": false,
      "notes": "",
      "dependsOn": ["US-001"],
      "conflictDomains": ["api/auth"],
      "parallelSafe": false,
      "barrier": true,
      "parallelReason": "Requires serialized integration after US-001"
    }
  ]
}
```

Scheduling fields are optional. Omit `dependsOn`, `conflictDomains`, and `parallelReason` when empty, omit `parallelSafe` when unknown, and omit `barrier` when false.

## Story Rules

**Size:** Each story must be completable in ONE agent iteration (one context window). Hal spawns a fresh agent per story with no memory of previous work. If you can't describe the change in 2-3 sentences, split it.

**Order:** Stories execute by priority. Dependencies first:
1. Schema / database changes
2. Backend logic / server actions
3. UI components consuming the backend
4. Explicit verification / integration work requested by the source markdown

**Acceptance criteria must be verifiable** — specific enough to check TRUE/FALSE:

| Bad | Good |
|---|---|
| "Works correctly" | "Function returns error when input is nil" |
| "Good UX" | "Clicking delete shows confirmation dialog" |
| "Handles errors" | "Returns wrapped error with context when file not found" |

**Required final criteria:**
- Every story: `"Typecheck passes"`
- Testable logic: `"Tests pass"`
- UI changes: `"Verify in browser (skip if no dev server running, no browser tools available, or 3 attempts fail)"`

## Splitting Large Stories

"Add user notification system" becomes:
1. Add notifications table
2. Create notification service
3. Add notification bell icon to header
4. Create notification dropdown panel
5. Add mark-as-read functionality

## Conversion Rules

- **IDs**: Sequential `US-001`, `US-002`, etc.
- **Priority**: Based on dependency order
- **All stories**: `passes: false`, empty `notes`
- **branchName**: Kebab-case, prefixed with `hal/`
- **Source traceability**: Every story/task must trace to an explicit source requirement. Do not invent verification, integration, checkpoint, cleanup, or summary stories that the markdown did not request.
- **Granular mode**: Preserve explicit source stories that are already atomic. Split only work that is too large for one agent iteration; do not pad the task count to a target number.

## Scheduling Contract v1

Use scheduling metadata conservatively so downstream runners can safely identify work that may execute in parallel.

- **dependsOn**: Exact story/task IDs that must complete before this item starts. Include only true prerequisites. Never reference unknown IDs, the same ID, or a later item.
- **conflictDomains**: Stable labels for shared files, resources, subsystems, migrations, credentials, or external state that should not be modified concurrently. Omit when no concrete conflict domain is known.
- **parallelSafe**: Use `true` only when the item can run alongside other ready items without shared-state risk. Use `false` when it must be serialized. Omit when uncertain.
- **barrier**: Use `true` only for explicit source-requested fan-in/checkpoint/integration tasks. Omit when false.
- **parallelReason**: Required when `parallelSafe` or `barrier` is present. Keep it concise and specific.
- **Cycles**: Dependency cycles are invalid. If two items need the same serialized resource, prefer a shared `conflictDomains` label over circular dependencies.

Granular conversion may emit task IDs such as `T-001`, `T-002`, etc. In granular mode, add `dependsOn` and `conflictDomains` where they are clear from the PRD, and leave scheduling fields absent where the dependency or conflict is speculative. Do not add extra verification, integration, or checkpoint tasks unless they are explicitly requested by the source markdown.

For a complete output example, see [examples/prd-output.json](examples/prd-output.json).
