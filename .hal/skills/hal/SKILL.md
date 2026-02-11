---
name: hal
description: Convert a markdown PRD to prd.json format for Hal's autonomous execution pipeline.
disable-model-invocation: true
---

# Hal PRD Converter

Convert a markdown PRD from `.hal/prd-*.md` to `.hal/prd.json`.

## Process

1. Find the PRD: look in `.hal/` for `prd-*.md` files (use most recent if multiple)
2. Convert each requirement into a user story in the JSON format below
3. Validate stories against the rules below

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
    }
  ]
}
```

## Story Rules

**Size:** Each story must be completable in ONE agent iteration (one context window). Hal spawns a fresh agent per story with no memory of previous work. If you can't describe the change in 2-3 sentences, split it.

**Order:** Stories execute by priority. Dependencies first:
1. Schema / database changes
2. Backend logic / server actions
3. UI components consuming the backend
4. Verification / integration

**Acceptance criteria must be verifiable** — specific enough to check TRUE/FALSE:

| Bad | Good |
|---|---|
| "Works correctly" | "Function returns error when input is nil" |
| "Good UX" | "Clicking delete shows confirmation dialog" |
| "Handles errors" | "Returns wrapped error with context when file not found" |

**Required final criteria:**
- Every story: `"Typecheck passes"`
- Testable logic: `"Tests pass"`
- UI changes: `"Verify in browser using agent-browser skill (skip if no dev server running)"`

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

For a complete output example, see [examples/prd-output.json](examples/prd-output.json).
