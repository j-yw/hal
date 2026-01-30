---
name: explode
description: "Break down a PRD into 8-15 granular tasks suitable for autonomous execution. Each task must be completable in one iteration with boolean acceptance criteria."
---

# Explode - PRD Task Breakdown

Transform a Product Requirements Document into 8-15 granular, autonomously-executable tasks. Each task must be small enough to complete in a single agent iteration and have verifiable boolean acceptance criteria.

---

## The Job

1. Read the PRD from the specified path
2. Analyze the scope and identify all work items
3. Break down into 8-15 granular tasks
4. Order tasks by dependency (investigation -> schema -> backend -> UI -> verification)
5. Generate `.goralph/auto-prd.json` with the tasks array

**Important:** Output JSON directly to `.goralph/auto-prd.json`. Do NOT ask clarifying questions.

---

## Input

You will receive:
- Path to the PRD file (e.g., `.goralph/prd-feature-name.md`)
- Branch name to include in the output

Read the PRD and extract:
- Feature scope and goals
- Existing task breakdown (if any)
- Functional requirements
- Technical considerations

---

## Output Format

Generate an `auto-prd.json` file with this structure:

```json
{
  "project": "[project-name]",
  "branchName": "[provided-branch-name]",
  "description": "[brief feature description from PRD]",
  "userStories": [
    {
      "id": "T-001",
      "title": "[task title]",
      "description": "As a [user/developer], I need [feature] so that [benefit].",
      "acceptanceCriteria": [
        "Specific verifiable criterion",
        "Another criterion",
        "Typecheck passes"
      ],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}
```

**Note:** Use `userStories` field (not `tasks`) for compatibility with existing Ralph loop.

---

## Task Count: 8-15 Tasks

**Why 8-15?**
- Fewer than 8: Tasks are too big, agents run out of context
- More than 15: Over-decomposed, creates coordination overhead

**Calibration guide:**
- Simple feature (1-2 files): 8-10 tasks
- Medium feature (3-5 files): 10-12 tasks
- Complex feature (6+ files, multiple systems): 12-15 tasks

If the PRD already has tasks, use them as a starting point but split any that are too large.

---

## Task Sizing: One Iteration Rule

**Each task must be completable in ONE agent iteration (one context window).**

The auto pipeline spawns a fresh agent per task. If a task is too big, the agent runs out of context and produces broken code.

### Right-sized tasks (1 iteration):
- Add a single database column/migration
- Create one Go type/struct definition
- Implement one function with tests
- Add a single UI component
- Update one configuration file
- Create one CLI command skeleton
- Add error handling to one function

### Too big (split these):
- "Implement the entire feature" -> Split into schema, backend, UI
- "Add all validation" -> Split into one task per validation rule
- "Create CRUD operations" -> Split into Create, Read, Update, Delete separately
- "Build the API" -> Split into types, handlers, routes, tests

**Rule of thumb:** If you can't describe the implementation in 2-3 sentences, split it.

---

## Task Ordering: Dependencies First

Tasks execute sequentially by priority. Earlier tasks must not depend on later ones.

### Standard ordering:

1. **Investigation (T-001, T-002)**
   - "Research existing patterns in codebase"
   - "Identify integration points"
   - These tasks produce knowledge, not code

2. **Schema/Types (T-003, T-004)**
   - Database migrations
   - Type definitions
   - Configuration structures

3. **Backend/Logic (T-005 - T-008)**
   - Core functions and algorithms
   - Server actions / API handlers
   - Business logic

4. **UI/Integration (T-009 - T-012)**
   - Components that consume backend
   - CLI commands that use core logic
   - Integration between systems

5. **Verification (T-013 - T-015)**
   - Integration tests
   - Backward compatibility checks
   - Documentation updates

### Dependency example:

```
T-001: Create config types          <- T-003 depends on this
T-002: Create config loader         <- T-003 depends on this
T-003: Integrate config into CLI    <- Uses types + loader
```

**Wrong order:**
```
T-001: Integrate config into CLI    <- Fails: no types exist
T-002: Create config types
```

---

## Acceptance Criteria: Boolean Verification

Each criterion must be verifiable as TRUE or FALSE by an autonomous agent.

### Good criteria (verifiable):
- "Create `internal/compound/types.go` with AnalysisResult struct"
- "Function returns error when input is nil"
- "`go vet ./...` passes"
- "`go test ./internal/compound/...` passes"
- "Config file includes `maxIterations` field with default 25"
- "CLI accepts `--dry-run` flag"

### Bad criteria (vague):
- "Works correctly"
- "Handles all edge cases"
- "Is well-documented"
- "Performs well"
- "User-friendly error messages"

### Rewrite vague criteria:

| Vague | Specific |
|-------|----------|
| "Works correctly" | "Function returns expected output for input X" |
| "Handles errors" | "Returns wrapped error with context when file not found" |
| "Well-tested" | "Test covers happy path and error case" |
| "Good UX" | "Shows progress spinner during long operation" |

### Every task must end with:
```
"Typecheck passes"
```

Or for Go projects specifically:
```
"Typecheck passes (go vet ./...)"
```

---

## ID Format

Use **T-XXX** format (T-001, T-002, etc.), NOT US-XXX.

- T = Task (for compound engineering)
- US = User Story (for interactive mode)

The T-XXX format indicates this is an autonomous pipeline execution.

---

## Example Transformation

### Input PRD excerpt:

```markdown
## Tasks

### T-001: Create pipeline state management
**Description:** As a developer, I need state management so the pipeline can resume.

**Acceptance Criteria:**
- [ ] Pipeline can save state
- [ ] Pipeline can load state
- [ ] Pipeline can clear state
- [ ] State includes all necessary fields
```

### Output (exploded to 4 tasks):

```json
{
  "userStories": [
    {
      "id": "T-001",
      "title": "Create PipelineState type definition",
      "description": "As a developer, I need a state struct so pipeline data can be serialized.",
      "acceptanceCriteria": [
        "Create internal/compound/state.go with PipelineState struct",
        "PipelineState contains: Step, BranchName, ReportPath, PRDPath, StartedAt, Analysis",
        "All fields have JSON tags for serialization",
        "Typecheck passes"
      ],
      "priority": 1,
      "passes": false,
      "notes": ""
    },
    {
      "id": "T-002",
      "title": "Implement loadState function",
      "description": "As a developer, I need to load state from disk so the pipeline can resume.",
      "acceptanceCriteria": [
        "Implement loadState() (*PipelineState, error) in state.go",
        "Reads from .goralph/auto-state.json",
        "Returns nil, nil when file doesn't exist",
        "Returns error when file exists but is invalid JSON",
        "Typecheck passes"
      ],
      "priority": 2,
      "passes": false,
      "notes": ""
    },
    {
      "id": "T-003",
      "title": "Implement saveState function",
      "description": "As a developer, I need to save state to disk so progress is preserved.",
      "acceptanceCriteria": [
        "Implement saveState(state *PipelineState) error in state.go",
        "Writes to .goralph/auto-state.json with 0644 permissions",
        "Uses atomic write pattern (write temp, then rename)",
        "Typecheck passes"
      ],
      "priority": 3,
      "passes": false,
      "notes": ""
    },
    {
      "id": "T-004",
      "title": "Implement clearState function",
      "description": "As a developer, I need to clear state on completion so the next run starts fresh.",
      "acceptanceCriteria": [
        "Implement clearState() error in state.go",
        "Removes .goralph/auto-state.json file",
        "Returns nil if file doesn't exist (idempotent)",
        "Typecheck passes"
      ],
      "priority": 4,
      "passes": false,
      "notes": ""
    }
  ]
}
```

Notice: One PRD task became 4 granular tasks, each completable in one iteration.

---

## Checklist

Before generating auto-prd.json:

- [ ] Read the entire PRD to understand full scope
- [ ] Generated 8-15 tasks (not fewer, not more)
- [ ] Used T-XXX IDs (not US-XXX)
- [ ] Each task completable in one iteration (small)
- [ ] Tasks ordered by dependency (types -> logic -> integration)
- [ ] Every criterion is boolean (verifiable true/false)
- [ ] Every task ends with "Typecheck passes"
- [ ] Output is valid JSON
- [ ] Saved to `.goralph/auto-prd.json`
- [ ] Did NOT ask clarifying questions

---

## Output Location

Write the JSON to: `.goralph/auto-prd.json`

This is separate from the manual flow's `.goralph/prd.json`:
- **Manual flow** (`plan`, `convert`, `validate`, `run`) → `.goralph/prd.json`
- **Auto flow** (`auto`, `explode`) → `.goralph/auto-prd.json`

The source PRD content is preserved in the `.goralph/prd-[feature].md` file.
