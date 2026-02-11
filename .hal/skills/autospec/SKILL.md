---
name: autospec
description: Generate a PRD autonomously from analysis context without user interaction. Used by the auto pipeline when analysis context is provided.
user-invocable: false
---

# Autospec — Autonomous PRD Generator

Generate a PRD from analysis context. Do NOT ask the user any questions.

## Input

You will receive analysis context:

```
ANALYSIS CONTEXT:
- Priority Item: [feature/fix to implement]
- Description: [what needs to be done]
- Rationale: [why selected as highest priority]
- Acceptance Criteria Hints: [suggested criteria]
- Estimated Tasks: [expected count]
- Branch Name: [suggested branch name]
```

## PRD Structure

Generate with these sections:

1. **Introduction/Overview** — Derived from Priority Item and Description
2. **Goals** — Inferred from rationale and criteria hints
3. **Tasks** — Using **T-XXX** IDs (T-001, T-002, etc.), NOT US-XXX
4. **Functional Requirements** — Numbered (FR-1, FR-2...)
5. **Non-Goals** — Explicit boundaries
6. **Technical Considerations** (optional)
7. **Open Questions** — Minimal since analysis provides context

### Task Format

```markdown
### T-001: [Title]
**Description:** As a [user/developer], I need [feature] so that [benefit].

**Acceptance Criteria:**
- [ ] Specific verifiable criterion
- [ ] Typecheck passes
```

## Task Rules

**Size:** Each task must be completable in ONE agent iteration. The auto pipeline spawns a fresh agent per task. If you can't describe implementation in 2-3 sentences, split it.

**Order:** Dependencies first — schema → types → backend → UI → verification.

**Criteria:** Boolean-verifiable. Every task ends with `"Typecheck passes"`.

## Self-Clarification

When analysis context is ambiguous:
- **Scope:** Default to minimal viable implementation
- **Technology:** Follow existing codebase patterns
- **Design:** Prefer simple over clever
- **Order:** Schema before backend before UI

Document assumptions in Open Questions.

## Output

Save to `.hal/prd-[feature-name].md` (kebab-case, derived from analysis).

For a complete example showing analysis context → PRD output, see [examples/sample-output.md](examples/sample-output.md).
