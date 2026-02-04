---
name: review
description: "Review completed implementation work. Analyze progress, identify patterns for AGENTS.md, generate summary report with tech debt and recommendations."
---

# Review - Work Session Analysis

Analyze a completed work session to extract learnings, identify patterns worth documenting, and generate a summary report for the next cycle.

---

## The Job

1. Read available context (progress log, git diff, commit history, PRD goals)
2. Analyze what was built and how it was built
3. Identify genuine patterns worth documenting in AGENTS.md
4. Note any issues encountered and tech debt introduced
5. Generate prioritized recommendations for next steps
6. Return structured JSON output

**Important:** Output JSON directly. Do NOT ask clarifying questions.

---

## Available Context

You will receive some combination of:
- **Progress log**: Notes from the work session (learnings, decisions, issues)
- **Git diff**: What code changed in this session
- **Commit history**: Commit messages showing work progression
- **PRD content**: Original goals and acceptance criteria
- **Branch name**: The feature being worked on

Not all context may be available. Adapt your analysis based on what's provided.

---

## Pattern Identification Guidelines

Only extract patterns that are:

1. **Specific to this codebase** - Not generic programming advice
2. **Actionable** - Concrete guidance an agent can follow
3. **Discovered through work** - Learnings from actual implementation, not obvious from reading code

### Good patterns (specific, actionable):
- "Use atomic write pattern (write temp, then rename) for state files in .hal/"
- "Engine implementations must register via init() in internal/engine/{name}/{name}.go"
- "CLI commands delegate to compound package; cmd/ files only handle flags and display"
- "Tests use table-driven format with subtests named after the test case"

### Bad patterns (too generic):
- "Write clean code"
- "Handle errors properly"
- "Use meaningful variable names"
- "Test your code"

### Pattern format:
Each pattern should be 1-2 sentences that another developer or AI agent could follow.

---

## Output Format

Return ONLY valid JSON (no markdown code fences, no explanation):

```json
{
  "summary": "2-3 sentence summary of what was built and the approach taken",
  "patterns": [
    "Pattern 1: Specific, actionable pattern discovered",
    "Pattern 2: Another pattern worth documenting"
  ],
  "issues": [
    "Issue 1: Problem encountered and how it was resolved",
    "Issue 2: Another issue that came up"
  ],
  "techDebt": [
    "Debt 1: Shortcut taken that needs future attention",
    "Debt 2: Missing test coverage or documentation"
  ],
  "recommendations": [
    "Priority 1: Most important next step",
    "Priority 2: Second priority item",
    "Priority 3: Third priority item"
  ]
}
```

---

## Field Guidelines

### summary
- 2-3 sentences describing what was accomplished
- Focus on the outcome and approach, not implementation details
- Mention any notable technical decisions

### patterns
- 0-5 patterns (empty array is fine if no notable patterns)
- Must be specific to this codebase
- Should help future work follow the same conventions

### issues
- Problems that came up during implementation
- Include resolution or workaround used
- Helps future work avoid same pitfalls

### techDebt
- Shortcuts taken for expediency
- Missing tests or error handling
- Temporary solutions that need cleanup
- Empty array if no debt introduced

### recommendations
- 3-5 prioritized next steps
- Based on PRD goals not yet completed
- Or natural extensions of the work done
- Order by priority/importance

---

## Example Output

```json
{
  "summary": "Implemented the compound engineering pipeline with state persistence. Used a state machine pattern with explicit terminal states. The pipeline can now resume from interruptions and tracks progress across analyze, branch, prd, explode, loop, and pr steps.",
  "patterns": [
    "Pipeline state files use atomic write pattern: write to .tmp file, then rename to final location",
    "State machines should have explicit terminal states (StepDone) rather than empty string",
    "CLI commands follow pattern: create engine, create display, delegate to compound package"
  ],
  "issues": [
    "Initial implementation didn't handle empty reports directory gracefully - added explicit check before pipeline starts",
    "Git branch creation failed silently when already on target branch - added existence check"
  ],
  "techDebt": [
    "Pipeline tests use mocked engine - need integration test with real Codex CLI",
    "Error messages in state.go could be more descriptive"
  ],
  "recommendations": [
    "Add hal review command to generate reports after pipeline completion",
    "Implement retry logic for transient engine failures",
    "Add progress percentage to pipeline output"
  ]
}
```

---

## Handling Missing Context

If certain context is unavailable, adjust your analysis:

| Missing | Adaptation |
|---------|------------|
| Progress log | Focus on git diff and commits for understanding work |
| Git diff | Use commit messages and PRD comparison |
| PRD | Generate recommendations without goal context |
| Commits | Analyze current state only |

If no context is available, return an error-indicating response.

---

## Checklist

Before generating output:

- [ ] Read all provided context
- [ ] Summary captures what was built (not how)
- [ ] Patterns are codebase-specific and actionable
- [ ] Issues include resolutions
- [ ] Tech debt items are specific and addressable
- [ ] Recommendations are prioritized
- [ ] Output is valid JSON
- [ ] Did NOT ask clarifying questions
