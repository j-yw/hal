# Hal Web — Full Spec

> Web UI for managing software projects. PMs write specs, hal builds them in sandboxes.

---

## 1. What Is This

A web app where you manage a software project like a todo list. You write feature specs as markdown, hal converts them into tasks, then builds them automatically in an isolated VM. You watch progress on a board and approve results before they ship.

**One sentence:** Linear meets autonomous coding.

---

## 2. How It Works (End to End)

```
You write a spec     →  hal breaks it into tasks  →  hal builds each task
     (markdown)              (prd.json)                  (in a sandbox VM)
                                                              │
                                                              ▼
                      you review results  ←  hal reviews its own code
                           │
                    approve / reject
                           │
                     PR created (or redo)
```

Mapped to hal CLI commands:

| Step | What happens | CLI equivalent |
|------|-------------|---------------|
| Write spec | You write markdown in the editor | Creating a `prd-*.md` file |
| Generate tasks | Spec is split into 8-15 small tasks | `hal convert` + `hal explode` |
| Execute | All tasks are built, one by one, automatically | `hal run` |
| Review | AI reviews its own code and fixes issues | `hal review --base <project.default_branch> --json` |
| Report | Summary of what was built + what to do next | `hal report` |
| PR | Push branch, create draft pull request | `git push` + `gh pr create` |

**Key fact:** `hal run` executes up to its configured iteration limit per invocation and reports whether the PRD is complete. The server should call `hal run --json`, stop successfully only when `ok=true` and `complete=true`, continue when `ok=true` and `complete=false`, and surface failures when `ok=false`. Completed work is preserved between invocations, but partial work from an interrupted in-progress story is not guaranteed to survive.

---

## 3. The Board

Two levels: specs (features) on the outer board, tasks (stories) inside each spec.

### Outer Board — Spec Queue

```
 Draft          Approved        Running         Waiting         Done
┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐
│ Payment  │  │ Reviews  │  │ Search       │  │ Auth     │  │ DB Setup │
│ Flow     │  │ System   │  │ 5/8 tasks    │  │          │  │ ✓        │
│          │  │          │  │ ████░░░ 62%  │  │ Gate:    │  ├──────────┤
│ [Edit]   │  │ [Run ▶]  │  │              │  │ Approve  │  │ Cart ✓   │
└──────────┘  └──────────┘  └──────────────┘  │ results? │  └──────────┘
┌──────────┐                                   │          │
│ Email    │                                   │ [Yes ✓]  │
│ Tpl      │                                   │ [No ✗]   │
│ [Edit]   │                                   │ [Redo 🔄]│
└──────────┘                                   └──────────┘
```

**Columns:**
- **Draft** — spec is being written/edited
- **Approved** — ready to execute, waiting in queue
- **Running** — hal is building the tasks right now
- **Waiting** — paused at a human checkpoint (PM must act)
- **Done** — PR created, ready to merge

Phase 1 and Phase 2 must allow only one **Running** spec per project/worktree. Today's CLI keeps active workflow state in repo-global `.hal/prd.json`, `.hal/progress.txt`, and `.hal/auto-state.json`, so additional approved specs stay queued until the active run finishes, is archived, or moves to an isolated sandbox/worktree.

### Inner Board — Tasks Within a Spec

Click into "Search" to see its tasks:

```
 Pending (3)        Running (1)           Done (4)
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ T-006 Filter │  │ T-005 API    │  │ T-001 Setup ✓│
│ T-007 Pages  │  │ ⏳ building..│  │ T-002 Index ✓│
│ T-008 Sort   │  └──────────────┘  │ T-003 Query ✓│
└──────────────┘                     │ T-004 UI   ✓│
                                     └──────────────┘
```

Tasks move automatically as the server observes hal completing them.
Phase 1 should not promise click-to-run single-task execution yet: the current `hal run --story <task-id>` flag is not a dependable story-scoped server contract because the loop still validates completion against the whole PRD.

---

## 4. The Pipeline (What Runs After You Click "Execute")

Each spec has a **pipeline** — an ordered list of steps that run automatically. Between any two steps, you can insert a **gate** (human checkpoint).

### Available Steps

| Step | What it does | hal command |
|------|-------------|-------------|
| **Execute** | Build tasks until the PRD is complete | Server-side loop: run `hal run --json`, stop successfully only when `ok=true` and `complete=true`, continue when `ok=true` and `complete=false`, and surface/handle failures when `ok=false` instead of looping blindly |
| **Review** | AI reviews code in bounded iterations, fixes valid issues, and can stop either when no valid issues remain or when it hits the iteration cap; the server must inspect the review-loop JSON (`stopReason`, totals such as valid issues/fixes applied) and only advance when the run ends clean | `hal review --base <project.default_branch> --json` (with the base branch resolved from project configuration, defaulting to `main`) |
| **Report** | Generate summary + recommendations without mutating source files, but still write report artifacts under `.hal/reports/`. `--skip-agents` only skips the `AGENTS.md` update. This uses today's legacy session-reporting command, not a diff-scoped continuation of `hal review`; because `hal report` has no `--base`, `--spec`, or diff input, its JSON must be treated as best-effort session context only. The server must persist the authoritative per-spec review scope and generate the canonical stage summary from stored diff/PRD/task data instead of assuming the CLI can reconstruct the exact reviewed work. | `hal report --json --skip-agents` (best-effort legacy session report, not an authoritative per-spec contract) |
| **Gate** | Pause and wait for PM to approve/reject | (server-side) |
| **Create PR** | Push branch, open draft PR | `git push` + `gh pr create` |
| **Auto Next** | Use report output only as optional context for proposing the next feature automatically, then pause for approval again | Proposed proposal-only command/mode (TBD). Do not use current `hal auto`, which runs the full pipeline. The web server must ignore `report.nextAction` from today's `hal report --json` contract because it currently points to `hal auto`. |

### Presets (Pick One)

**Simple** — just build it:
```
Execute → PR
```

**With Review** — build it, then polish:
```
Execute → Review → PR
```

**With Approval** — build it, polish it, let me check:
```
Execute → Review → ⏸ Gate → PR
```

**Compound** — build, polish, report, let me check:
```
Execute → Review → Report → ⏸ Gate → PR
```

Treat `Review` as a gated success condition, not just a completed command. If the review-loop result reports `stopReason: "max_iterations"` or still shows unresolved valid issues, stop the pipeline and require intervention instead of proceeding to `Report` or `Create PR`.

**Continuous** — keep building features in a loop (with checkpoints):
```
Execute → Review → Report → ⏸ Gate → Auto Next → ⏸ Gate → Execute → ...
```

You can also drag-and-drop steps to build a custom pipeline.

### How "Continuous" Works (The Compound Loop)

This is the most advanced mode. After one feature is done:

1. The server generates an authoritative per-spec **report** from stored diff/PRD/task data, optionally attaching `hal report` output only as best-effort legacy session context
2. Pipeline **pauses** — you review the report
3. You click **Approve**
4. Hal reads that server-scoped report and **proposes the next feature** to build
5. Pipeline **pauses again** — you see "hal wants to build Search Feature (10 tasks) — approve?"
6. You approve, edit, or reject the proposal
7. If approved, hal starts building the next feature
8. Repeat

**It never runs without your awareness.** Every feature cycle has two mandatory checkpoints: one after the work is done, one before the next work starts. You can break the loop at any checkpoint by rejecting, pausing, or picking a different spec from your queue.

---

## 5. Resilience (What Happens When Things Break)

### Current hal Guarantees

Today's CLI already preserves enough state to support limited resumable workflows:
- **`prd.json`** records task completion (`passes: true`). Completed work is also captured in git history, so later `hal run` invocations continue from the remaining stories.
- **`auto-state.json`** records the current pipeline step that `hal auto --resume` should run next. The pipeline updates it after successful step transitions and saves it again on failure or cancellation.
- Standalone stages like review, report, and PR creation do not have a separate persisted pipeline resume contract today.
- LLM/API retry behavior is command-specific in the existing CLI flow, not a pipeline-wide guarantee.

These are the guarantees this spec can rely on today. They describe persisted workflow state, not a running web server or remote process supervisor.

### Recovery Rules for the Current CLI

**Rule 1: Persisted state is the source of truth.**
Recovery should read `prd.json` and related state files before deciding what remains to do.

**Rule 2: Resume behavior must build on existing hal semantics.**
The web layer should treat `hal run` as repeatable story execution driven by `prd.json`, and use `hal auto --resume` only for the compound pipeline's saved-step resume. If the web app needs resumable review/report/PR orchestration, it must persist that stage state itself.

**Rule 3: Remote execution recovery is future work.**
Background execution, SSH reconnects, heartbeat monitoring, and server-restart recovery are proposed Phase 3 capabilities, not behavior that exists in hal today.

### Current Behavior vs. Planned Web Behavior

| Scenario | What is true today | Planned web/server behavior |
|---------|--------------------|-----------------------------|
| **CLI process exits or crashes** | Persisted files remain. `hal run` can continue from remaining stories in `prd.json`, and `hal auto --resume` can continue from saved auto pipeline state. | Server detects failure and resumes the right step automatically. |
| **LLM rate limit / timeout** | Retry behavior is command-specific today: `hal run` retries retryable failures automatically (3 attempts, exponential backoff), `hal review` retries prompt calls, and `hal report` does not currently expose the same built-in contract. | The web/server layer should surface available retries clearly and add its own retry/error-handling policy for stages that do not already provide one. |
| **Browser closes / WiFi drops** | Not applicable yet because there is no shipped web server. | Browser can disconnect without interrupting server-side progress. |
| **SSH drops / sandbox reboot / server restart** | Not implemented in today's CLI. | Phase 3 adds runner wrapper, heartbeat monitoring, reconnect logic, and restart recovery. |

### Stop / Pause / Resume

Pause, resume, and stop controls are also proposed server behavior. The implementation should preserve hal's existing state files and git-backed progress, but the actual web controls and signal-handling flow belong to Phase 3 work.

---

## 6. Architecture

```
┌────────────────────────────┐
│     Your Browser           │
│     (Next.js frontend)     │
└─────────────┬──────────────┘
              │ REST API + WebSocket
┌─────────────▼──────────────┐
│     Hal Server             │
│     (Go, proposed as a     │
│      future `hal serve`    │
│      command in the same   │
│      binary)               │
│                            │
│  • SQLite database         │
│  • Pipeline executor       │
│  • WebSocket event bus     │
│  • SSH to sandboxes        │
└─────────────┬──────────────┘
              │ SSH
┌─────────────▼──────────────┐
│     Sandbox VMs            │
│     (Daytona/Hetzner/      │
│      DigitalOcean/         │
│      Lightsail)            │
│                            │
│  • Git repo cloned         │
│  • hal CLI installed       │
│  • codex/claude/pi runs    │
│    here                    │
└────────────────────────────┘
```

**Why a future `hal serve` command should live in the same binary:**
- Server imports the same Go types as the CLI (`engine.PRD`, `sandbox.SandboxState`, etc.)
- No serialization bugs between server and CLI
- One binary to install once the server exists

**Why sandboxes:**
- Each project runs in isolation (no cross-contamination)
- Safe to run untrusted AI-generated code
- Sandbox survives server crashes
- You can SSH in manually to inspect/debug

---

## 7. Data Model

```sql
-- A software project (linked to a git repo)
CREATE TABLE projects (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    repo_url        TEXT NOT NULL,
    default_branch  TEXT DEFAULT 'main',
    sandbox_name    TEXT,              -- Active sandbox for this project
    pipeline_preset TEXT DEFAULT 'with_review',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- A feature spec (the thing PMs write)
CREATE TABLE specs (
    id              TEXT PRIMARY KEY,
    project_id      TEXT REFERENCES projects(id),
    title           TEXT NOT NULL,
    markdown        TEXT NOT NULL,     -- The spec content
    json_prd        TEXT,              -- Generated prd.json (after convert+explode)
    status          TEXT DEFAULT 'draft',
    -- status: draft → approved → executing → waiting → done / failed
    branch_name     TEXT,
    queue_priority  INTEGER DEFAULT 0, -- Lower = higher priority
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tasks generated from a spec
CREATE TABLE tasks (
    id              TEXT PRIMARY KEY,
    spec_id         TEXT REFERENCES specs(id),
    task_id         TEXT NOT NULL,      -- T-001, US-001
    title           TEXT NOT NULL,
    description     TEXT,
    acceptance      TEXT,               -- JSON array of criteria
    status          TEXT DEFAULT 'pending',
    -- status: pending → running → done / failed
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Pipeline execution for a spec
CREATE TABLE pipeline_runs (
    id              TEXT PRIMARY KEY,
    spec_id         TEXT REFERENCES specs(id),
    stages          TEXT NOT NULL,      -- JSON array of stage definitions
    current_stage   INTEGER DEFAULT 0,
    status          TEXT NOT NULL,
    -- status: running → paused / waiting / completed / failed / recovering
    sandbox_name    TEXT,
    last_heartbeat  DATETIME,
    started_at      DATETIME,
    completed_at    DATETIME
);

-- Execution log for each stage
CREATE TABLE stage_runs (
    id              TEXT PRIMARY KEY,
    pipeline_run_id TEXT REFERENCES pipeline_runs(id),
    stage_index     INTEGER NOT NULL,
    stage_type      TEXT NOT NULL,      -- execute/review/report/gate/pr/auto_next
    status          TEXT NOT NULL,      -- pending/running/completed/failed/waiting
    result          TEXT,               -- JSON from hal --json
    gate_action     TEXT,               -- approve/reject/retry (for gate stages)
    gate_notes      TEXT,               -- PM's feedback
    started_at      DATETIME,
    completed_at    DATETIME
);
```

---

## 8. API

### Projects
```
POST   /api/projects                     Create project
GET    /api/projects                     List projects
GET    /api/projects/:pid                Get project + sandbox status
```

### Specs
```
POST   /api/projects/:pid/specs          Create spec (draft)
GET    /api/projects/:pid/specs          List specs (filter by status)
GET    /api/specs/:sid                   Get spec + tasks + pipeline status
PUT    /api/specs/:sid                   Update spec content
POST   /api/specs/:sid/approve           Move to approved queue
POST   /api/specs/:sid/execute           Start pipeline execution
```

### Tasks
```
GET    /api/specs/:sid/tasks             List tasks for spec
```

Single-task execution from the board is deferred until hal exposes a reliably story-scoped run contract.

### Pipeline Control
```
GET    /api/specs/:sid/pipeline          Get pipeline config + progress
PUT    /api/specs/:sid/pipeline          Update pipeline stages/preset
POST   /api/specs/:sid/pipeline/pause    Pause execution
POST   /api/specs/:sid/pipeline/resume   Resume execution
POST   /api/specs/:sid/pipeline/stop     Stop and return to approved
```

### Gate Actions
```
POST   /api/specs/:sid/stages/:idx/approve   Approve → continue pipeline
POST   /api/specs/:sid/stages/:idx/reject    Reject → back to draft
POST   /api/specs/:sid/stages/:idx/retry     Re-run previous stage
```

### Sandbox
```
POST   /api/projects/:pid/sandbox/start  Start sandbox VM
POST   /api/projects/:pid/sandbox/stop   Stop sandbox VM
GET    /api/projects/:pid/sandbox/status Sandbox health
```

### Real-Time (WebSocket)
```
WS /ws/specs/:sid

Events:
  task_changed       {taskId, status}          Server-synthesized task status update
  pipeline_progress  {stage, iteration, total}  Current stage progress
  pipeline_log       {line, timestamp}          Log line from hal
  gate_waiting       {stageIndex, label}        PM needs to act
  pipeline_status    {status}                   running/paused/recovering/done
```

For Phase 1, `task_changed` must not assume `hal run --json` emits live task lifecycle events. The server should derive `done` from `.hal/prd.json` (`passes: true`), expose `running` and `failed` from server-local execution state and/or parsed log output while a `hal run` process is active, and treat the final `hal run --json` payload as invocation summary only.

---

## 9. Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Frontend | Next.js 15 + shadcn/ui + Tailwind | Fast, clean, good DX |
| Editor | Tiptap | Rich markdown for PMs (not code editor) |
| Drag-drop | @hello-pangea/dnd | Board and pipeline builder |
| State | Zustand | Simple, lightweight |
| Real-time | WebSocket | Log streaming + server-synthesized task updates |
| Backend | Go (net/http + chi) | Same language as hal, shares types |
| Database | SQLite (modernc.org/sqlite) | Single-file, no setup, embedded in binary |
| SSH | golang.org/x/crypto/ssh | Execute hal commands in sandboxes |
| Deployment | Single binary (proposed future `hal serve`) | Frontend embedded via `//go:embed` |

---

## 10. Build Plan

### Phase 1 — Core (4 weeks)
**Goal:** You can write a spec, see tasks on a board, execute them, and watch progress.

- Add a new `hal serve` command with HTTP server + SQLite
- Project and spec CRUD
- Spec editor (Tiptap markdown)
- Auto-generate tasks from spec (convert + explode)
- Task board (kanban)
- Execute button → server-side loop runs `hal run --json` locally for the single active spec in that project/worktree: continue when `ok=true && complete=false`, finish when `ok=true && complete=true`, and stop/report failure when `ok=false`
- WebSocket log streaming
- Tasks update in real-time from server-side state: mark `done` by observing `.hal/prd.json` (`passes: true`) and expose `running`/`failed` from the active process state or parsed log output instead of assuming `hal run --json` streams task lifecycle events
- Phase 1 and Phase 2 execution stay serialized per project/worktree because `.hal/prd.json`, `progress.txt`, and `auto-state.json` are repo-global. The board may show many approved specs in queue, but only one spec may execute/review/report locally at a time until per-spec worktrees or sandboxes exist.

### Phase 2 — Pipeline + Gates (3 weeks)
**Goal:** Review, report, and approval gates work.

- Pipeline model (stages as JSON array)
- Presets: simple, with_review, with_approval, compound
- Review stage (runs `hal review --base <project.default_branch> --json`; server inspects `stopReason` and unresolved valid-issue totals before advancing)
- Report stage (treats `hal report --json --skip-agents` only as best-effort legacy session context; the authoritative per-spec report is generated server-side from stored scope/diff/PRD data, and the server ignores `report.nextAction`)
- Gate stage (pauses pipeline, shows approve/reject/retry)
- Pipeline progress bar on spec cards
- Frontend pipeline builder (drag-drop stages)

### Phase 3 — Sandboxes (3 weeks)
**Goal:** Execution happens in isolated VMs, not your local machine.

- Sandbox start/stop from UI (reuses `hal sandbox` infrastructure)
- Remote execution via SSH
- Runner wrapper script (nohup + PID tracking)
- Heartbeat monitoring
- SSH reconnect with log offset
- Recovery on server restart
- Pause/Resume/Stop controls

### Phase 4 — Compound Loop + Polish (3 weeks)
**Goal:** Continuous feature development loop with PM checkpoints.

- Auto Next stage backed by a proposal-only command or mode, separate from today's full `hal auto` pipeline
- Continuous pipeline preset
- Queue priority (drag-drop reorder specs)
- Stop conditions (budget, errors, time window)
- Notifications (email/webhook when gate is waiting)
- Dashboard with execution history

---

## 11. User Flow Example

### Morning: PM writes specs

1. Open Hal Web at `localhost:8080`
2. Create project "E-commerce App", link to GitHub repo
3. Write spec: "User Authentication" — OAuth2 with Google/GitHub
4. Write spec: "Product Catalog" — CRUD for products with search
5. Write spec: "Shopping Cart" — add to cart, checkout flow

### Click Execute

6. Approve "User Authentication"
7. Click **Execute** — hal spins up sandbox, starts building
8. Watch tasks move: T-001 ✓, T-002 ✓, T-003 ✓ ... T-008 ✓
9. Pipeline hits Review stage — hal reviews its own code
10. Review: "2 issues found, 1 auto-fixed, 1 minor remaining"
11. Pipeline hits Gate — **you** decide

### Approve

12. You read the review summary — it's fine
13. Click **Approve**
14. hal creates a draft PR on GitHub
15. Spec moves to "Done"

### Next feature

16. "Product Catalog" is already approved — click **Execute**
17. Hal starts building it in the same sandbox (new branch)
18. You go do other work

### No infinite loops

Nothing starts without you clicking a button. Nothing advances past a gate without your approval. If you close your laptop and come back tomorrow, the board shows exactly where things stand. If a sandbox crashed, you see "Sandbox lost — [Restart & resume]".

---

## 12. Open Questions

| Question | Current answer |
|----------|---------------|
| Auth? | No auth in Phase 1 (localhost only). Add in Phase 4+. |
| Hosted version? | Start local-only with a future `hal serve` command. Hosted version is a separate decision. |
| Multiple sandboxes? | One per project default. Parallel execution (multiple sandboxes) in Phase 4. |
| Can PM edit auto-generated specs? | Yes. Auto Next should create a Draft that PM can edit before approving. |
| Gate timeout? | No timeout by default. Optional: auto-approve after N hours if quality checks pass. |
