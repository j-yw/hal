# Example: Analysis Context → PRD

## Input (what autospec receives)

```
ANALYSIS CONTEXT:
- Priority Item: Add task status tracking
- Description: Allow users to mark tasks as pending, in-progress, or done with visual indicators
- Rationale: Most requested feature; blocks dashboard and filtering work
- Acceptance Criteria Hints: Status stored in DB, colored badges, filter by status
- Estimated Tasks: 4
- Branch Name: hal/task-status
```

## Output (what autospec generates)

# PRD: Task Status Tracking

## Introduction

Add status tracking to tasks so users can mark progress. Tasks can be set to pending, in-progress, or done, with colored visual indicators and list filtering.

## Goals

- Store task status persistently in the database
- Show clear visual differentiation between statuses
- Enable filtering the task list by status
- Default new tasks to pending

## Tasks

### T-001: Add status field to tasks table
**Description:** As a developer, I need to store task status in the database.

**Acceptance Criteria:**
- [ ] Add status column: 'pending' | 'in_progress' | 'done' (default 'pending')
- [ ] Generate and run migration successfully
- [ ] Typecheck passes

### T-002: Display status badge on task cards
**Description:** As a user, I want to see task status at a glance.

**Acceptance Criteria:**
- [ ] Each task card shows colored status badge
- [ ] Badge colors: gray=pending, blue=in_progress, green=done
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### T-003: Add status toggle to task rows
**Description:** As a user, I want to change task status from the list.

**Acceptance Criteria:**
- [ ] Each row has status dropdown
- [ ] Changing status saves immediately
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### T-004: Filter tasks by status
**Description:** As a user, I want to filter the list to focus on certain statuses.

**Acceptance Criteria:**
- [ ] Filter dropdown: All | Pending | In Progress | Done
- [ ] Filter persists in URL params
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

## Functional Requirements

- FR-1: Add `status` field to tasks table with default 'pending'
- FR-2: Display colored status badge on each task card
- FR-3: Include status toggle on task list rows
- FR-4: Add status filter dropdown to task list header

## Non-Goals

- No status-based notifications
- No automatic status changes based on due dates
- No status history or audit log

## Technical Considerations

- Reuse existing badge component with color variants
- Filter state managed via URL search params

## Open Questions

- None (scope is clear from analysis)
