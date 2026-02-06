---
name: explode
description: Break down a PRD into 8-15 granular tasks for autonomous execution. Each task must be completable in one agent iteration with boolean acceptance criteria.
disable-model-invocation: true
---

# Explode — PRD Task Breakdown

Transform a PRD into 8-15 granular, autonomously-executable tasks.

## Process

1. Read the PRD from the specified path
2. Break down into 8-15 tasks ordered by dependency
3. Write `.hal/auto-prd.json`

**Output JSON directly. Do NOT ask questions.**

## Output Format

```json
{
  "project": "[project-name]",
  "branchName": "[branch-name]",
  "description": "[feature description]",
  "userStories": [
    {
      "id": "T-001",
      "title": "[task title]",
      "description": "As a [user/developer], I need [feature] so that [benefit].",
      "acceptanceCriteria": ["Verifiable criterion", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}
```

Use `userStories` field (not `tasks`) for compatibility. Use **T-XXX** IDs (not US-XXX) to indicate autonomous pipeline tasks.

## Task Count: 8-15

| Complexity | Files affected | Target |
|---|---|---|
| Simple | 1-2 files | 8-10 tasks |
| Medium | 3-5 files | 10-12 tasks |
| Complex | 6+ files | 12-15 tasks |

Fewer than 8 = tasks too big. More than 15 = over-decomposed.

## Task Rules

**Size:** Each task must be completable in ONE agent iteration. The pipeline spawns a fresh agent per task with no memory of previous work. If you can't describe the implementation in 2-3 sentences, split it.

Right-sized: add a DB column, create one struct, implement one function with tests, add one UI component.
Too big: "implement the entire feature," "add all validation," "create CRUD operations."

**Order:** Tasks execute sequentially by priority. Dependencies first:
1. Investigation / research (produces knowledge, not code)
2. Schema / types / config structures
3. Backend logic / handlers
4. UI / CLI / integration
5. Verification / tests / docs

**Criteria must be boolean** — verifiable TRUE/FALSE by an autonomous agent:

| Bad | Good |
|---|---|
| "Works correctly" | "Function returns expected output for input X" |
| "Handles errors" | "Returns wrapped error with context when file not found" |
| "Well-tested" | "Test covers happy path and error case" |

Every task must end with `"Typecheck passes"`.

## Output

Write to `.hal/auto-prd.json` (separate from manual flow's `.hal/prd.json`).

For a complete transformation example, see [examples/exploded-tasks.json](examples/exploded-tasks.json).
