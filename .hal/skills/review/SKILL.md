---
name: review
description: Analyze a completed work session. Extract codebase-specific patterns for AGENTS.md, identify tech debt, and generate a structured summary report.
disable-model-invocation: true
---

# Review — Work Session Analysis

Analyze a work session and return structured JSON. Do NOT ask questions.

## Input

You may receive some combination of:
- Progress log, git diff, commit history, PRD content, branch name

Adapt analysis based on what's available.

## Output

Return ONLY valid JSON (no markdown fences):

```json
{
  "summary": "2-3 sentences: what was built and the approach taken",
  "patterns": ["Codebase-specific, actionable pattern discovered"],
  "issues": ["Problem encountered and how it was resolved"],
  "techDebt": ["Shortcut taken that needs future attention"],
  "recommendations": ["Prioritized next step"]
}
```

## Pattern Guidelines

Only extract patterns that are:
1. **Specific to this codebase** — not generic programming advice
2. **Actionable** — concrete guidance an agent can follow
3. **Discovered through work** — learnings from actual implementation

Good:
- "Use atomic write pattern (write temp, then rename) for state files in .hal/"
- "Engine implementations must register via init() in internal/engine/{name}/{name}.go"
- "CLI commands delegate to compound package; cmd/ files only handle flags and display"

Bad (too generic):
- "Write clean code"
- "Handle errors properly"
- "Test your code"

## Field Guidelines

- **summary**: Outcome and approach, not implementation details (2-3 sentences)
- **patterns**: 0-5 entries. Empty array is fine. Must be codebase-specific.
- **issues**: Problems encountered + resolution/workaround
- **techDebt**: Shortcuts, missing tests, temporary solutions. Empty array if none.
- **recommendations**: 3-5 prioritized next steps based on PRD goals or natural extensions

## Missing Context

| Missing | Adaptation |
|---|---|
| Progress log | Focus on git diff and commits |
| Git diff | Use commit messages and PRD comparison |
| PRD | Generate recommendations without goal context |
| Commits | Analyze current state only |
