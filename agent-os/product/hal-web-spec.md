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
| Review | AI reviews its own code and fixes issues | `hal review --base <default-branch>` |
| Report | Summary of what was built + what to do next | `hal report` |
| PR | Push branch, create draft pull request | `git push` + `gh pr create` |

**Key fact:** `hal run` resumes from the next incomplete task and commits completed work as it goes. It keeps going until all stories pass or the configured iteration cap is reached, so the web app should treat `complete=true` and the remaining-task state in `prd.json` as the source of truth instead of assuming one plain `hal run` always finishes everything. If anything crashes, re-running `hal run` picks up from the next incomplete task. You never lose progress.

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

Tasks move automatically as hal completes them. You can also click a single task and run it individually.

---

## 4. The Pipeline (What Runs After You Click "Execute")

Each spec has a **pipeline** — an ordered list of steps that run automatically. Between any two steps, you can insert a **gate** (human checkpoint).

### Available Steps

| Step | What it does | hal command |
|------|-------------|-------------|
| **Execute** | Run a capped, resumable execution pass; advance only when `complete=true` and no PRD stories remain. `hal run --json` is a final-result contract, so live task-board updates come from server-side log streaming and the active PRD file for the workflow: `.hal/prd.json` for manual `hal run` flows, or `.hal/auto-prd.json` when the built-in compound pipeline reaches its loop step. | `hal run --json` |
| **Review** | AI reviews code, fixes issues, repeats until clean | `hal review --base <default-branch> --json` |
| **Report** | Generate summary + recommendations without mutating `AGENTS.md` | `hal report --json --skip-agents` |
| **Gate** | Pause and wait for PM to approve/reject | (server-side) |
| **Create PR** | Push branch, open draft PR | `git push` + `gh pr create` |
| **Auto Next** | Continue the built-in compound workflow from a report, or analyze only if the server owns the follow-up steps | `hal auto --report <report-path>` |

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

**Continuous** — keep building features in a loop (with checkpoints):
```
Execute → Review → Report → ⏸ Gate → Auto Next → ...
```

You can also drag-and-drop steps to build a custom pipeline.

### How "Continuous" Works (The Compound Loop)

This is the most advanced mode. The repository currently supports two different ways to build it:

1. The server runs a feature pipeline to completion for the current approved spec: execute, review, report, gate, PR
2. After the report is ready, the **server** pauses and waits for PM approval
3. If approved, the **server** decides what happens next
4. If the product wants built-in continuation, it can call `hal auto --report <report-path>` after approval
5. That built-in compound flow then runs sequentially through analyze -> branch -> prd -> explode -> loop -> pr with no extra approval stop inside the CLI
6. If the product wants another checkpoint before branch creation or task execution, that checkpoint must stay in server-owned orchestration instead of `hal auto`
7. Repeat

**Approval checkpoints are server-owned unless a future `hal auto` mode adds them explicitly.** Today's repository exposes resumable compound state in `.hal/auto-state.json`, but once `hal auto --report <report-path>` starts it does not pause between analyze and execution. The web product must therefore gate when to invoke `hal auto`, or keep analyze/proposal generation outside that command.

---

## 5. Resilience (What Happens When Things Break)

### Why It's Simpler Than You Think

Recovery has two layers:
- **hal task execution state** lives in `prd.json`. Completed tasks stay committed, and re-running `hal run` skips finished work.
- **Compound pipeline state** already lives in `.hal/auto-state.json` when the product is using the built-in `hal auto` flow. That file persists the current pipeline step and supports resume across the built-in stages: analyze, branch, prd, explode, loop, and pr.
- **Web pipeline state** must live in the server database (or another server-owned store) for any orchestration the built-in compound pipeline does not represent. That includes custom stage sequencing such as standalone review, report publishing, approval gates, or any server-owned "what runs next" logic outside `hal auto`.

`.hal/auto-state.json` already covers resume for the built-in `hal auto --resume` pipeline, including the final PR creation step. The server needs additional durable state only for stages or metadata that are outside that pipeline contract.

So the server's job is: **detect the failure, reconnect to the sandbox, read durable hal state from the repo, and resume either the built-in `hal auto` pipeline or the correct server-owned stage for web-only orchestration.**

### The Three Recovery Rules

**Rule 1: The sandbox repo is the source of truth for task completion.**
The server never guesses task progress. It reads `prd.json` from the sandbox to know what work is already done.

**Rule 2: The web server owns only the recovery state that `hal` does not already persist.**
If the product is invoking `hal auto`, `.hal/auto-state.json` is the source of truth for the built-in compound stage. The server persists supplemental state such as gate status, run metadata, standalone review/report stages, and any other orchestration context outside the built-in pipeline. On restart it reloads that state, then decides whether to reconnect, retry, or ask for operator input.

**Rule 3: Re-run only idempotent hal commands for the stage you are resuming.**
`hal run` is safe to re-run because it skips completed tasks. `hal auto --resume` is the correct resume path for the built-in compound pipeline, including PR creation, if the product chooses to invoke that command directly. Review/report/gate stages that live outside `hal auto` need their own server-side resume rules.

**Rule 4: Detached execution and pause controls are server responsibilities unless the product invokes the built-in `hal auto` resume flow directly.**
Today's repository gives the server resumable hal state (`prd.json`, `.hal/auto-state.json`) but does not itself provide a generic `nohup` runner, PID tracking layer, or SIGTERM-based pause contract for arbitrary web stages. If the web product wants those behaviors, it must implement them in a server-owned runner wrapper and persist enough metadata to reconnect, stop, or resume safely.

### What Happens During Each Failure

| Failure | What actually happens | What you see |
|---------|----------------------|-------------|
| **You close the browser** | Nothing. Server keeps running. | When you reopen, board shows current progress. |
| **Your WiFi drops** | Same as above. Server doesn't care about your browser. | Reconnects automatically when you're back. |
| **SSH to sandbox drops** | If the server launched the stage through a detached runner wrapper, the process keeps running and the server reconnects to the log stream. If not, the server must inspect persisted hal state and decide whether to restart or resume the stage. | Brief "Reconnecting..." then back to normal. Might see "T-006 completed while disconnected." |
| **Sandbox VM reboots** | hal process dies, but filesystem survives. Server detects via heartbeat, waits for VM to come back, then resumes the matching workflow from persisted state: re-run `hal run` for execute-only/manual flows, or use `hal auto --resume` when the built-in compound pipeline was active. | "Sandbox restarting... Recovered. Resuming from T-005." |
| **Sandbox VM dies permanently** | Server waits 10 min, then marks as failed. | "Sandbox lost. 5/8 tasks were saved. [Restart sandbox & resume] or [Stop]" |
| **Server crashes** | If the current stage was launched via a detached runner wrapper, the sandbox process may still be running. On restart, the server reloads persisted web-pipeline state, reconnects to sandboxes, and either reattaches or resumes from hal/server-owned state. | "Server recovered. Reconnecting..." then back to normal. |
| **Transient LLM/API/network failures** | hal retries automatically (3 attempts, exponential backoff) for retryable errors such as rate limits, overloaded service responses, and connection or API timeout failures. Execution-hung timeouts are not retried automatically. | You might see "T-005: retry 2/3 (rate limited)" in the log. |

### Stop / Pause / Resume

| Action | What happens |
|--------|-------------|
| **Pause** | For built-in `hal auto`, prefer durable resume via `hal auto --resume`. For server-owned stages, pause behavior must come from the server's runner contract (for example PID tracking + signal policy) and persisted stage state. |
| **Resume** | Server reads its persisted pipeline stage, then resumes the matching action. For the built-in compound pipeline this means `hal auto --resume`; for Execute-only flows it can safely re-run `hal run`; other stages resume according to server-owned state and retry rules. |
| **Stop** | Stop semantics are server-owned unless the invoked hal command exposes its own durable resume path. Completed tasks and commits remain preserved in repo state. |

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
│     (Go, same binary as    │
│  Proposed web mode in hal  │
│   CLI (for example         │
│    `hal serve`)            │
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

**Why a future `hal serve` mode should live in the same binary:**
- Server imports the same Go types as the CLI (`engine.PRD`, `sandbox.SandboxState`, etc.)
- No serialization bugs between server and CLI
- If added, one binary to install and update

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
    default_sandbox_name TEXT,         -- Optional default when multiple sandboxes exist
    pipeline_preset TEXT DEFAULT 'with_review',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sandboxes are first-class project resources
CREATE TABLE sandboxes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    name            TEXT NOT NULL,     -- hal sandbox name / registry key
    provider        TEXT NOT NULL,
    status          TEXT NOT NULL,     -- running / stopped / unknown
    workspace_id    TEXT,
    ip              TEXT,
    is_default      BOOLEAN DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, name)
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
    sandbox_id      TEXT REFERENCES sandboxes(id),
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
POST   /api/specs/:sid/tasks/:taskId/run Run single task
```

`taskId` is the PRD story identifier stored in `tasks.task_id` (for example `US-001` or `T-001`). The server passes that exact value to `hal run --story <taskId>`. Do not use the tasks table primary key (`tasks.id`) for CLI execution.

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
GET    /api/projects/:pid/sandboxes                List project sandboxes
POST   /api/projects/:pid/sandboxes                Create/start a sandbox
GET    /api/projects/:pid/sandboxes/:sandboxId     Get sandbox status/details
POST   /api/projects/:pid/sandboxes/:sandboxId/stop Stop sandbox VM
POST   /api/projects/:pid/sandboxes/:sandboxId/select Mark default sandbox for new runs
```

### Real-Time (WebSocket)
```
WS /ws/specs/:sid

The current CLI machine contracts for `hal run --json`, `hal review --json`, and `hal report --json` are stage-completion payloads, not streaming task events. During `hal run`, the server is responsible for deriving live task updates by tailing log output and/or polling `.hal/prd.json`, then publishing normalized WebSocket events to the frontend.

Events:
  task_changed       {taskId, status}          Task moved to done/running/failed (derived by server from PRD polling/log parsing)
  pipeline_progress  {stage, iteration, total}  Current stage progress
  pipeline_log       {line, timestamp}          Log line from hal
  gate_waiting       {stageIndex, label}        PM needs to act
  pipeline_status    {status}                   running/paused/recovering/done
```

---

## 9. Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Frontend | Next.js 15 + shadcn/ui + Tailwind | Fast, clean, good DX |
| Editor | Tiptap | Rich markdown for PMs (not code editor) |
| Drag-drop | @hello-pangea/dnd | Board and pipeline builder |
| State | Zustand | Simple, lightweight |
| Real-time | WebSocket | Log streaming + task updates |
| Backend | Go (net/http + chi) | Same language as hal, shares types |
| Database | SQLite (modernc.org/sqlite) | Single-file, no setup, embedded in binary |
| SSH | golang.org/x/crypto/ssh | Execute hal commands in sandboxes |
| Deployment | Single binary (proposed `hal serve` mode) | Frontend embedded via `//go:embed` |

---

## 10. Build Plan

### Phase 1 — Core (4 weeks)
**Goal:** You can write a spec, see tasks on a board, execute them, and watch progress.

- `hal serve` command with HTTP server + SQLite
- Project and spec CRUD
- Spec editor (Tiptap markdown)
- Auto-generate tasks from spec (convert + explode)
- Task board (kanban)
- Execute button → runs `hal run` locally
- WebSocket log streaming
- Tasks update in real-time from server-side `.hal/prd.json` polling and/or log parsing while `hal run` executes

### Phase 2 — Pipeline + Gates (3 weeks)
**Goal:** Review, report, and approval gates work.

- Pipeline model (stages as JSON array)
- Presets: simple, with_review, with_approval, compound
- Review stage (runs `hal review --json`)
- Report stage (runs `hal report --json --skip-agents`)
- Gate stage (pauses pipeline, shows approve/reject/retry)
- Pipeline progress bar on spec cards
- Frontend pipeline builder (drag-drop stages)

### Phase 3 — Sandboxes (3 weeks)
**Goal:** Execution happens in isolated VMs, not your local machine.

- Sandbox start/stop from UI (reuses `hal sandbox` infrastructure)
- Remote execution via SSH
- Runner wrapper script for detached execution, PID tracking, and explicit pause/stop semantics
- Heartbeat monitoring
- SSH reconnect with log offset
- Recovery on server restart
- Pause/Resume/Stop controls

### Phase 4 — Compound Loop + Polish (3 weeks)
**Goal:** Continuous feature development loop with PM checkpoints.

- Auto Next stage (prefer `hal auto --report <path>` for built-in continuation; use `hal analyze` only when the server owns the follow-up workflow)
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
| Hosted version? | Start local-only (likely via a future `hal serve` mode). Hosted version is a separate decision. |
| Multiple sandboxes? | Supported from the start. Projects can have multiple sandboxes, with one optional default for new runs. |
| Can PM edit auto-generated specs? | Yes. Auto Next creates a Draft that PM can edit before approving. |
| Gate timeout? | No timeout by default. Optional: auto-approve after N hours if quality checks pass. |
