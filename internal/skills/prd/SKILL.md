---
name: prd
description: Generate a Product Requirements Document for a new feature. Use when planning a feature, starting a project, or asked to write requirements or spec something out.
---

# PRD Generator

Create actionable PRDs suitable for implementation by developers or AI agents.

## Process

1. Receive a feature description
2. Ask 3-5 clarifying questions with lettered options (A/B/C/D)
3. Generate a structured PRD from the answers
4. Save to `.hal/prd-[feature-name].md`

**Do NOT start implementing. Just create the PRD.**

## Step 1: Clarifying Questions

Ask only where the initial prompt is ambiguous. Focus on:
- **Goal:** What problem does this solve?
- **Functionality:** Key actions?
- **Scope:** What should it NOT do?
- **Success criteria:** How do we know it's done?

Format with lettered options so users can respond quickly ("1A, 2C, 3B"):

```
1. What is the primary goal?
   A. Improve onboarding
   B. Increase retention
   C. Reduce support burden
   D. Other: [specify]
```

## Step 2: PRD Structure

Generate with these sections:

1. **Introduction/Overview** — Feature and problem it solves
2. **Goals** — Measurable objectives
3. **User Stories** — Title, description, acceptance criteria (see format below)
4. **Functional Requirements** — Numbered list ("FR-1: The system must...")
5. **Non-Goals** — Explicit scope boundaries
6. **Design Considerations** (optional)
7. **Technical Considerations** (optional)
8. **Success Metrics**
9. **Open Questions**

### User Story Format

```markdown
### US-001: [Title]
**Description:** As a [user], I want [feature] so that [benefit].

**Acceptance Criteria:**
- [ ] Specific verifiable criterion
- [ ] Typecheck passes
- [ ] [UI stories only] Verify in browser using agent-browser skill (skip if no dev server running)
```

**Stories must be small** — completable in one focused session. If you can't describe the implementation in 2-3 sentences, split it.

**Criteria must be verifiable** — "Button shows confirmation dialog before deleting" not "works correctly."

## Output

- **Format:** Markdown
- **Location:** `.hal/prd-[feature-name].md`

For a complete PRD example, see [examples/task-priority-prd.md](examples/task-priority-prd.md).
