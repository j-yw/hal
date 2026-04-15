---
name: product
description: Generate durable product context docs for hal product plan using strict JSON-only output.
---

# Product Context Generator

Generate content for selected files in `.hal/product/`:
- `mission.md`
- `roadmap.md`
- `tech-stack.md`

This skill is generation-only.
Do not ask follow-up questions.
Do not run tools.
Do not write files.

## Input Context

The caller provides:
- selected targets
- interview answers
- existing content for selected files

Use only the provided context.
Do not infer or output unselected files.

## Output Contract

Return only a single JSON object.

Allowed keys:
- `"mission.md"`
- `"roadmap.md"`
- `"tech-stack.md"`

Rules:
- output JSON only (no prose, no markdown fences)
- include only selected files
- omit unselected files
- use string values for file content
- do not output unknown keys

Example:

```json
{
  "mission.md": "## Mission\n...",
  "roadmap.md": "## Roadmap\n..."
}
```

## Content Guidance

- `mission.md`: problem, users, value proposition, guiding principles.
- `roadmap.md`: phases, priorities, milestones, and risks.
- `tech-stack.md`: stack decisions, rationale, constraints, and operations.
