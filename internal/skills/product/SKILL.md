---
name: product
description: Generate durable product context docs for mission, roadmap, and tech stack.
---

# Product Context Planner

Generate durable product context docs under `.hal/product/`:
- `mission.md`
- `roadmap.md`
- `tech-stack.md`

This skill is generation-only.
Do not ask follow-up questions.
Do not run tools.
Do not write files.

## Output Contract

Return only markdown content for the requested file(s).
Do not wrap in code fences.

## Content Guidance

### mission.md
- problem statement
- target users
- value proposition
- product principles

### roadmap.md
- phases and milestones
- priorities for upcoming quarters
- major risks/dependencies

### tech-stack.md
- architecture and core technologies
- constraints and non-goals
- operational considerations
