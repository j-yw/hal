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
| Review | AI reviews its own code and fixes issues | `hal review --base main` |
| Report | Summary of what was built + what to do next | `hal report` |
| PR | Push branch, create draft pull request | `git push` + `gh pr create` |

**Key fact:** `hal run` already runs ALL tasks to completion. Each completed task = a git commit. If anything crashes, `hal run` picks up from the next incomplete task. You never lose progress.

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
| **Execute** | Build all tasks | `hal run -i 50 --json` |
| **Review** | AI reviews code, fixes issues, repeats until clean | `hal review --base main --json` |
| **Report** | Generate summary + recommendations | `hal report --json` |
| **Gate** | Pause and wait for PM to approve/reject | (server-side) |
| **Create PR** | Push branch, open draft PR | `git push` + `gh pr create` |
| **Auto Next** | Use report to pick next feature automatically | `hal auto --report <path>` |

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
Execute → Review → Report → ⏸ Gate → Auto Next → ⏸ Gate → Execute → ...
```

You can also drag-and-drop steps to build a custom pipeline.

### How "Continuous" Works (The Compound Loop)

This is the most advanced mode. After one feature is done:

1. Hal generates a **report** summarizing what was built
2. Pipeline **pauses** — you review the report
3. You click **Approve**
4. Hal reads the report and **proposes the next feature** to build
5. Pipeline **pauses again** — you see "hal wants to build Search Feature (10 tasks) — approve?"
6. You approve, edit, or reject the proposal
7. If approved, hal starts building the next feature
8. Repeat

**It never runs without your awareness.** Every feature cycle has two mandatory checkpoints: one after the work is done, one before the next work starts. You can break the loop at any checkpoint by rejecting, pausing, or picking a different spec from your queue.

---

## 5. Resilience (What Happens When Things Break)

### Why It's Simpler Than You Think

hal already handles recovery. After any crash:
- **`prd.json`** tracks which tasks are done (`passes: true`). Each completion is a git commit.
- **`auto-state.json`** tracks which pipeline step was last completed.
- Running `hal run` again skips completed tasks and picks up the next one.

So the server's job is simple: **detect the failure, reconnect to the sandbox, re-run the current step.** hal does the rest.

### The Three Recovery Rules

**Rule 1: The sandbox is the source of truth.**
The server never guesses. It reads `prd.json` from the sandbox to know what's done.

**Rule 2: Every hal command is safe to re-run.**
`hal run` skips completed tasks. `hal auto --resume` continues from the last step. You can call them as many times as you want.

**Rule 3: hal runs inside `nohup` in the sandbox.**
Even if SSH drops, hal keeps running. The server just reconnects and tails the log file.

### What Happens During Each Failure

| Failure | What actually happens | What you see |
|---------|----------------------|-------------|
| **You close the browser** | Nothing. Server keeps running. | When you reopen, board shows current progress. |
| **Your WiFi drops** | Same as above. Server doesn't care about your browser. | Reconnects automatically when you're back. |
| **SSH to sandbox drops** | hal keeps running (nohup). Server reconnects in ~5s and tails the log again. | Brief "Reconnecting..." then back to normal. Might see "T-006 completed while disconnected." |
| **Sandbox VM reboots** | hal process dies, but filesystem survives. Server detects via heartbeat, waits for VM to come back, re-runs `hal run`. | "Sandbox restarting... Recovered. Resuming from T-005." |
| **Sandbox VM dies permanently** | Server waits 10 min, then marks as failed. | "Sandbox lost. 5/8 tasks were saved. [Restart sandbox & resume] or [Stop]" |
| **Server crashes** | Sandbox keeps running. On server restart, it checks all active pipelines, reconnects to sandboxes, syncs state. | "Server recovered. Reconnecting..." then back to normal. |
| **LLM rate limit / timeout** | hal retries automatically (3 attempts, exponential backoff). | You might see "T-005: retry 2/3 (rate limited)" in the log. |

### Stop / Pause / Resume

| Action | What happens |
|--------|-------------|
| **Pause** | Server sends SIGTERM to hal. hal saves `prd.json` and exits. Tasks completed so far are kept. Click Resume to continue. |
| **Resume** | Server re-runs `hal run`. hal reads `prd.json`, skips completed tasks, continues. |
| **Stop** | Server kills hal. Spec goes back to "Approved" column. All completed tasks and commits are preserved. You can re-execute later. |

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
│      hal CLI: `hal serve`) │
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

**Why `hal serve` is part of the same binary:**
- Server imports the same Go types as the CLI (`engine.PRD`, `sandbox.SandboxState`, etc.)
- No serialization bugs between server and CLI
- One binary to install: `hal serve --port 8080`

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
POST   /api/tasks/:tid/run              Run single task
```

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
  task_changed       {taskId, status}          Task moved to done/running/failed
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
| Deployment | Single binary (`hal serve`) | Frontend embedded via `//go:embed` |

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
- Tasks update in real-time as hal completes them

### Phase 2 — Pipeline + Gates (3 weeks)
**Goal:** Review, report, and approval gates work.

- Pipeline model (stages as JSON array)
- Presets: simple, with_review, with_approval, compound
- Review stage (runs `hal review --json`)
- Report stage (runs `hal report --json`)
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

- Auto Next stage (uses `hal auto` to propose next feature)
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
| Hosted version? | Start local-only (`hal serve`). Hosted version is a separate decision. |
| Multiple sandboxes? | One per project default. Parallel execution (multiple sandboxes) in Phase 4. |
| Can PM edit auto-generated specs? | Yes. Auto Next creates a Draft that PM can edit before approving. |
| Gate timeout? | No timeout by default. Optional: auto-approve after N hours if quality checks pass. |
