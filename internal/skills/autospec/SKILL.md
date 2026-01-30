---
name: autospec
description: "Generate a PRD autonomously without user interaction. Used by the auto pipeline when analysis context is provided. Self-clarifies from context rather than asking questions."
---

# Autospec - Autonomous PRD Generator

Generate Product Requirements Documents autonomously using provided analysis context. Unlike the interactive `prd` skill, autospec does NOT ask questions - it uses the analysis result to self-clarify requirements.

---

## The Job

1. Receive analysis context containing: priority item, description, rationale, acceptance criteria hints
2. Self-clarify requirements using the analysis context (NO user questions)
3. Generate a structured PRD
4. Save to `.goralph/prd-[feature-name].md`

**Important:** This skill is designed for autonomous execution. Do NOT ask the user any questions.

---

## Input Context

You will receive analysis context in this format:

```
ANALYSIS CONTEXT:
- Priority Item: [The highest priority feature/fix to implement]
- Description: [What needs to be done]
- Rationale: [Why this was selected as highest priority]
- Acceptance Criteria Hints: [Suggested criteria from analysis]
- Estimated Tasks: [Number of tasks expected]
- Branch Name: [Suggested branch name]
```

Use this context to:
- Determine the scope and boundaries
- Understand the problem being solved
- Define appropriate acceptance criteria
- Break down into right-sized tasks

---

## PRD Structure

Generate the PRD with these sections:

### 1. Introduction/Overview
Brief description of the feature and the problem it solves. Derive from the Priority Item and Description in the analysis.

### 2. Goals
Specific, measurable objectives (bullet list). Infer from the rationale and acceptance criteria hints.

### 3. Tasks
Each task needs:
- **Title:** Short descriptive name
- **Description:** "As a [user/developer], I need [feature] so that [benefit]"
- **Acceptance Criteria:** Verifiable checklist of what "done" means

**Important:** Use T-XXX IDs (T-001, T-002, etc.) NOT US-XXX.

**Format:**
```markdown
### T-001: [Title]
**Description:** As a [user/developer], I need [feature] so that [benefit].

**Acceptance Criteria:**
- [ ] Specific verifiable criterion
- [ ] Another criterion
- [ ] Typecheck passes
```

### 4. Functional Requirements
Numbered list of specific functionalities:
- "FR-1: The system must..."
- "FR-2: When X happens, the system must..."

### 5. Non-Goals (Out of Scope)
What this feature will NOT include. Be explicit about boundaries.

### 6. Technical Considerations (Optional)
- Known constraints or dependencies
- Integration points with existing systems

### 7. Open Questions
Any remaining ambiguities (these should be minimal since analysis provided context).

---

## Task Sizing: Critical for Autonomous Execution

**Each task must be completable in ONE iteration (one context window).**

The auto pipeline spawns a fresh agent instance per task. If a task is too big, the agent runs out of context and produces broken code.

### Right-sized tasks:
- Add a database column and migration
- Add a single UI component
- Update one server action with new logic
- Add a filter or form field
- Create a single API endpoint

### Too big (split these):
- "Build the entire feature" - Split into schema, backend, UI components
- "Add authentication" - Split into schema, middleware, login UI, session
- "Refactor the module" - Split into one task per file or pattern

**Rule of thumb:** If you cannot describe the implementation in 2-3 sentences, split it.

---

## Task Ordering: Dependencies First

Tasks execute in priority order. Earlier tasks must not depend on later ones.

**Correct order:**
1. Schema/database changes (migrations)
2. Type definitions and interfaces
3. Backend logic / server actions
4. UI components that use the backend
5. Integration and verification

**Wrong order:**
1. UI component (depends on backend that doesn't exist)
2. Backend logic

---

## Acceptance Criteria: Boolean Verification

Each criterion must be verifiable as TRUE or FALSE by an autonomous agent.

### Good criteria (verifiable):
- "Add `status` column to tasks table with default 'pending'"
- "Function returns error when input is empty"
- "Config file includes `autoMode` section with documented fields"
- "Typecheck passes (go vet ./...)"
- "Tests pass"

### Bad criteria (vague):
- "Works correctly"
- "Handles edge cases"
- "Good error handling"
- "User-friendly"

### Always include as final criterion:
```
Typecheck passes
```

---

## Self-Clarification Strategy

When the analysis context is ambiguous, make reasonable assumptions:

1. **Scope ambiguity:** Default to minimal viable implementation
2. **Technology ambiguity:** Follow existing patterns in the codebase
3. **Design ambiguity:** Prefer simple, explicit solutions over clever ones
4. **Order ambiguity:** Schema before backend before UI

Document assumptions in the Open Questions section.

---

## Output

- **Format:** Markdown (`.md`)
- **Location:** `.goralph/`
- **Filename:** `prd-[feature-name].md` (kebab-case, derived from analysis)

---

## Example

**Input context:**
```
ANALYSIS CONTEXT:
- Priority Item: Add config file support
- Description: Allow users to customize behavior via config.yaml
- Rationale: Users need to override defaults without code changes
- Acceptance Criteria Hints: Load from .goralph/config.yaml, provide defaults, document options
- Estimated Tasks: 4
- Branch Name: feature/config-support
```

**Output PRD:**

```markdown
# PRD: Config File Support

## Introduction

Add configuration file support so users can customize goralph behavior without modifying code. The config file will be located at `.goralph/config.yaml` and provide sensible defaults when missing.

## Goals

- Allow users to customize behavior via config.yaml
- Provide sensible defaults for all settings
- Document all configuration options
- Maintain backward compatibility (work without config)

## Tasks

### T-001: Create config types and loader
**Description:** As a developer, I need config type definitions and a loader function so the application can read user settings.

**Acceptance Criteria:**
- [ ] Create Config struct with relevant fields
- [ ] Implement LoadConfig(dir string) function
- [ ] Return default config when file is missing
- [ ] Typecheck passes

### T-002: Create default config template
**Description:** As a developer, I need a default config template so init can install it.

**Acceptance Criteria:**
- [ ] Create config.yaml template with all options
- [ ] Add comments documenting each option
- [ ] Embed template in Go code
- [ ] Typecheck passes

### T-003: Update init to install config
**Description:** As a user, I want goralph init to create config.yaml so I have a starting point.

**Acceptance Criteria:**
- [ ] Init creates .goralph/config.yaml if missing
- [ ] Existing config files are preserved
- [ ] Init output lists config.yaml
- [ ] Typecheck passes

### T-004: Integrate config into commands
**Description:** As a developer, I need commands to use the config so user settings take effect.

**Acceptance Criteria:**
- [ ] Commands load config at startup
- [ ] Config values override hardcoded defaults
- [ ] Missing config uses defaults (no error)
- [ ] Typecheck passes

## Functional Requirements

- FR-1: Load configuration from .goralph/config.yaml when present
- FR-2: Provide default values for all settings when config is missing
- FR-3: goralph init creates config.yaml template
- FR-4: Existing config files are never overwritten

## Non-Goals

- No config file validation beyond YAML syntax
- No runtime config reloading
- No environment variable overrides (this iteration)

## Technical Considerations

- Use gopkg.in/yaml.v3 for YAML parsing
- Follow existing template embedding pattern
- Config should be loaded once at command startup

## Open Questions

- None (scope is clear from analysis)
```

---

## Checklist

Before saving the PRD:

- [ ] Used T-XXX IDs (not US-XXX)
- [ ] Each task is completable in one iteration (small)
- [ ] Tasks ordered by dependency (schema to backend to UI)
- [ ] Every task has "Typecheck passes" as criterion
- [ ] Acceptance criteria are boolean (verifiable true/false)
- [ ] Saved to `.goralph/prd-[feature-name].md`
- [ ] Did NOT ask the user any questions
