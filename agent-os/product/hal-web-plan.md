# Hal Web — Project Management Frontend for Hal CLI

## Vision

A web-based project management UI on top of `hal` CLI — where product/engineering managers define **what** to build, and hal autonomously executes it in sandboxes. The manager stays in control of **when** things run and **what** gets approved.

---

## The Core Problem with the Current CLI

Today's hal has two execution modes, and both have UX gaps for managers:

### 1. Manual: `hal run` — already runs ALL stories
`hal run` picks the next pending story, implements it, commits, and loops. Default 10 iterations. It already runs the entire PRD end-to-end. **There's nothing manual about it except typing the command.**

### 2. Compound: `report → auto → report → auto...` — runs forever
The compound loop is designed for fully autonomous operation. But there's no **human checkpoint** — once started, it keeps finding work and executing. A PM has no place to say "wait, let me review this before you start the next feature."

### What's Missing
**A human-in-the-loop control plane.** A place where a PM can:
- Queue up multiple features as specs
- Approve which ones get executed
- Watch execution in real-time
- Review results before approving the next batch
- NOT have an infinite loop running without their awareness

---

## The Control Model: Job Queue, Not Infinite Loop

The web frontend treats each spec as a **Job** with explicit lifecycle gates:

```
┌──────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐
│  Draft   │───▶│ Approved │───▶│ Executing │───▶│  Review  │───▶│   Done   │
│          │    │          │    │           │    │          │    │          │
│ PM writes│    │ PM clicks│    │ hal runs  │    │ PM/EM    │    │ PR ready │
│ the spec │    │ "Execute"│    │ all tasks │    │ reviews  │    │ to merge │
└──────────┘    └──────────┘    └───────────┘    └──────────┘    └──────────┘
      │                              │                │
      │         ◀────────────────────┘                │
      │         (failed → back to draft               │
      │          with error context)                   │
      │                                                │
      └────────────────────────────────────────────────┘
                    (rejected → back to draft
                     with review feedback)
```

**Key difference from CLI:** The PM is the conductor. Nothing starts without approval. Nothing advances without review. The infinite loop is replaced by explicit human decisions.

---

## What Hal CLI Already Gives Us

Every command supports `--json` — the entire CLI is already a headless API:

| Command | What it does | Web equivalent |
|---------|-------------|---------------|
| `hal plan` | AI-generates a PRD | "Generate Spec" button |
| `hal convert` | Markdown → JSON PRD | Automatic on spec save |
| `hal validate` | Check PRD quality | Validation badge on spec |
| `hal explode` | Break PRD → 8-15 tasks | Auto-generates story cards |
| `hal run` | **Execute ALL stories** | "Execute" button (runs entire PRD) |
| `hal run -s US-001` | Run single story | Click-to-run individual card |
| `hal auto` | Full pipeline (analyze→run→PR) | "Auto Pipeline" mode |
| `hal review` | Code review loop | "Review" button post-execution |
| `hal report` | Generate summary | Auto after execution completes |
| `hal status --json` | Workflow state machine | Real-time dashboard |
| `hal continue --json` | What to do next | Smart suggestions |
| `hal doctor --json` | Health checks | Environment readiness indicator |
| `hal sandbox start/stop` | Manage VMs | Sandbox controls in project settings |

### The Critical Insight
**`hal run` already runs ALL stories to completion.** The web UI just needs to:
1. Let the PM write the spec
2. Call `hal convert` + `hal explode` to generate stories
3. Show stories on a board
4. On "Execute" → call `hal run` (which handles the entire PRD)
5. Stream progress via `hal status --json` polling or log tailing
6. On completion → show results for PM review

---

## Execution Modes in the Web UI

### Mode 1: Full Spec Execution (Default)
PM clicks "Execute" on a spec → hal runs ALL stories in the PRD sequentially.
This is what most PMs want: "build this feature."

```
Spec: "User Authentication"
├── T-001: Setup auth provider    → hal handles
├── T-002: Login page             → hal handles  
├── T-003: OAuth callback         → hal handles
├── T-004: Session management     → hal handles
├── T-005: Protected routes       → hal handles
└── All done → PM reviews result
```

**Mapped to CLI:** `hal run -i 50` (high iteration count to ensure completion)

### Mode 2: Selective Story Execution
PM selects specific stories to run. Useful for:
- Re-running a failed story after adjusting the spec
- Running stories in a custom order
- Testing one story before committing to the full spec

**Mapped to CLI:** `hal run -s T-003` per selected story

### Mode 3: Auto Pipeline (Power User)
PM uploads a report or description → hal does everything:
analyze → branch → generate PRD → explode → run → create PR

**Mapped to CLI:** `hal auto --report <path>`

### Mode 4: Batch Execution (Symphony-like)
PM queues multiple specs → hal executes them in priority order, one at a time (or parallel in separate sandboxes). **Each spec requires explicit PM approval to start.**

```
Queue:
1. ✅ "User Auth"        → Done, PR #42 merged
2. ⏳ "Search Feature"   → Executing in sandbox-2...  
3. ⏸  "Payment Flow"     → Approved, waiting for sandbox
4. 📝 "Email Templates"  → Draft, not approved yet
```

**This replaces the infinite `report → auto` loop.** The PM controls the queue. Nothing starts without being approved and queued.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Hal Web (Next.js)                      │
│  Spec Editor │ Story Board │ Execution Monitor │ Review  │
└──────────────────────────┬──────────────────────────────┘
                           │ REST + WebSocket  
┌──────────────────────────▼──────────────────────────────┐
│                  Hal Server (Go)                         │
│  `hal serve` — same binary, shares all internal types    │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │
│  │ Job Queue  │  │ Event Bus  │  │ Sandbox Manager    │ │
│  │ SQLite     │  │ WebSocket  │  │ SSH exec hal cmds  │ │
│  └────────────┘  └────────────┘  └────────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │ SSH + hal CLI --json
┌──────────────────────────▼──────────────────────────────┐
│              Sandboxes (Isolated VMs)                     │
│  sandbox-1: hal run (auth feature)                       │
│  sandbox-2: hal run (search feature)                     │
│  sandbox-3: idle, ready for next job                     │
└─────────────────────────────────────────────────────────┘
```

### Why `hal serve` in the Same Binary
- **Type safety**: Import `engine.PRD`, `sandbox.SandboxState`, `cmd.RunResult` directly
- **No drift**: Server wraps the same functions the CLI calls
- **Single binary**: `hal serve --port 8080` starts everything
- **CLI parity**: Any improvement to hal CLI automatically works in the web UI

---

## The Board: PM/EM Control Surface

### Main View: Project Board

```
┌─────────────────────────────────────────────────────────────────────┐
│  🤖 Hal Web    │ E-commerce App ▼ │ 🟢 sandbox-1 │ ⏸ sandbox-2   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─── Spec Queue ──────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  📝 Draft (2)        ✅ Approved (1)       ⏳ Running (1)   │   │
│  │  ┌────────────┐     ┌────────────┐       ┌────────────┐    │   │
│  │  │ Payment    │     │ Reviews    │       │ Search     │    │   │
│  │  │ Flow       │     │ System     │       │ Feature    │    │   │
│  │  │            │     │            │       │ 5/8 tasks  │    │   │
│  │  │ [Edit]     │     │ [Execute▶] │       │ ████░░░ 62%│    │   │
│  │  └────────────┘     └────────────┘       └────────────┘    │   │
│  │  ┌────────────┐                                             │   │
│  │  │ Email      │      🔍 Review (1)       ✓ Done (3)        │   │
│  │  │ Templates  │     ┌────────────┐       ┌────────────┐    │   │
│  │  │            │     │ Auth       │       │ DB Setup   │    │   │
│  │  │ [Edit]     │     │ 3 issues   │       │ Cart       │    │   │
│  │  └────────────┘     │ [Approve✓] │       │ Products   │    │   │
│  │                      │ [Reject✗]  │       └────────────┘    │   │
│  │                      └────────────┘                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  [+ New Spec]  [📊 Dashboard]  [⚙ Settings]                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Spec Detail View (with Story Board inside)

When PM clicks into a spec, they see the kanban of individual stories:

```
┌─────────────────────────────────────────────────────────────────────┐
│  ← Back │ Spec: Search Feature │ ⏳ Executing │ 5/8 complete       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Pending (3)          In Progress (1)         Done (4)              │
│  ┌──────────────┐    ┌──────────────┐       ┌──────────────┐      │
│  │ T-006        │    │ T-005        │       │ T-001 ✓      │      │
│  │ Filter by    │    │ Search API   │       │ Setup Elastic │      │
│  │ category     │    │ endpoint     │       ├──────────────┤      │
│  │              │    │ ⏳ running... │       │ T-002 ✓      │      │
│  │ [Run ▶]      │    │              │       │ Index schema  │      │
│  └──────────────┘    │ ┌──────────┐ │       ├──────────────┤      │
│  ┌──────────────┐    │ │ Live Log │ │       │ T-003 ✓      │      │
│  │ T-007        │    │ │ ...      │ │       │ Query parser  │      │
│  │ Pagination   │    │ └──────────┘ │       ├──────────────┤      │
│  │              │    └──────────────┘       │ T-004 ✓      │      │
│  └──────────────┘                           │ Results UI    │      │
│  ┌──────────────┐                           └──────────────┘      │
│  │ T-008        │                                                  │
│  │ Sort results │                                                  │
│  └──────────────┘                                                  │
│                                                                     │
│  [⏸ Pause]  [⏹ Stop]  [🔄 Review]  [📋 Full Log]                 │
└─────────────────────────────────────────────────────────────────────┘
```

### What PMs/EMs Actually Control

| Action | What happens | Human gate? |
|--------|-------------|-------------|
| Write spec | Creates draft PRD | — |
| Edit spec | Modifies PRD content | — |
| Approve spec | Moves to "Approved" queue | **YES** |
| Execute spec | Starts `hal run` for all stories | **YES** |
| Run single story | Starts `hal run -s T-003` | **YES** |
| Pause execution | Saves state, stops sandbox | **YES** |
| Review results | Shows code review findings | — |
| Approve results | Creates PR, moves to Done | **YES** |
| Reject results | Returns to Draft with feedback | **YES** |
| Queue next spec | Starts next approved spec | **YES** |

**Every state transition that costs money or changes code requires explicit PM action.**

---

## How It Prevents the "Infinite Loop" Problem

### CLI Today (Problematic)
```
hal report → hal auto → hal report → hal auto → ...  (never stops)
```

### Web UI (Human-Controlled)
```
PM writes spec → PM approves → hal executes → PM reviews → PM approves
                                                              │
                                              PM picks next spec from queue
                                              (or does nothing — system idles)
```

### Automation Levels (PM Configurable per Project)

| Level | Name | Behavior |
|-------|------|----------|
| 1 | **Manual** | PM must click "Execute" and "Approve" for every spec |
| 2 | **Semi-Auto** | PM approves specs; execution and review run automatically. PM must approve results before next spec starts |
| 3 | **Auto-Queue** | Approved specs execute in order. PM only needs to approve final results before merge |
| 4 | **Full Auto** | Like current `hal auto` loop, but with a **stop condition**: stop when queue is empty, budget is hit, or error threshold exceeded |

Default is Level 2 (Semi-Auto). PMs upgrade when they trust the system.

### Stop Conditions (for Level 3-4)
- **Queue empty**: All approved specs are done → idle
- **Budget limit**: Sandbox hours exceed threshold → pause and notify
- **Error rate**: >3 consecutive failures → pause and notify
- **Time window**: Only execute during business hours (configurable)
- **Review gate**: Always pause after review finds critical issues

---

## Data Model

```sql
-- A software project (repo)
CREATE TABLE projects (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    repo_url      TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    automation_level INTEGER DEFAULT 2,  -- 1-4
    sandbox_config TEXT,                 -- JSON: provider, size, etc.
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- A feature spec (PRD)
CREATE TABLE specs (
    id            TEXT PRIMARY KEY,
    project_id    TEXT REFERENCES projects(id),
    title         TEXT NOT NULL,
    markdown      TEXT NOT NULL,          -- The spec content
    json_prd      TEXT,                   -- Converted prd.json (after hal convert)
    status        TEXT DEFAULT 'draft',   -- draft|approved|executing|review|done|failed
    priority      INTEGER DEFAULT 0,     -- Queue order (lower = higher priority)
    branch_name   TEXT,
    error_context TEXT,                   -- Why it failed (for retry)
    review_notes  TEXT,                   -- PM's review feedback
    approved_at   DATETIME,
    started_at    DATETIME,
    completed_at  DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Individual stories/tasks within a spec
CREATE TABLE stories (
    id            TEXT PRIMARY KEY,
    spec_id       TEXT REFERENCES specs(id),
    project_id    TEXT REFERENCES projects(id),
    story_id      TEXT NOT NULL,           -- T-001, US-001
    title         TEXT NOT NULL,
    description   TEXT,
    acceptance    TEXT,                    -- JSON array of criteria
    status        TEXT DEFAULT 'pending',  -- pending|running|done|failed
    priority      INTEGER DEFAULT 0,
    hal_output    TEXT,                    -- JSON from hal run --json
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Execution runs
CREATE TABLE runs (
    id            TEXT PRIMARY KEY,
    project_id    TEXT REFERENCES projects(id),
    spec_id       TEXT REFERENCES specs(id),
    sandbox_name  TEXT,
    run_type      TEXT NOT NULL,           -- full|single|review|auto
    status        TEXT DEFAULT 'pending',  -- pending|running|paused|completed|failed
    hal_result    TEXT,                    -- JSON from hal --json output
    story_id      TEXT,                    -- For single-story runs
    started_at    DATETIME,
    completed_at  DATETIME
);

-- Real-time event log
CREATE TABLE events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    TEXT,
    spec_id       TEXT,
    run_id        TEXT,
    event_type    TEXT NOT NULL,
    payload       TEXT,                    -- JSON
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## API Design

### Specs (the main thing PMs interact with)
```
POST   /api/projects/:pid/specs              Create spec (draft)
GET    /api/projects/:pid/specs              List specs (filterable by status)
GET    /api/projects/:pid/specs/:sid         Get spec + stories
PUT    /api/projects/:pid/specs/:sid         Update spec content
POST   /api/projects/:pid/specs/:sid/approve Approve → moves to queue
POST   /api/projects/:pid/specs/:sid/execute Start execution (hal run)
POST   /api/projects/:pid/specs/:sid/review  Start review (hal review)  
POST   /api/projects/:pid/specs/:sid/accept  Accept results → Done
POST   /api/projects/:pid/specs/:sid/reject  Reject → back to Draft
```

### Stories (generated from specs, PM can run individually)
```
GET    /api/projects/:pid/specs/:sid/stories  List stories for spec
POST   /api/projects/:pid/stories/:tid/run    Run single story
```

### Execution Control
```
POST   /api/projects/:pid/runs/:rid/pause    Pause execution
POST   /api/projects/:pid/runs/:rid/resume   Resume execution
POST   /api/projects/:pid/runs/:rid/stop     Stop execution
GET    /api/projects/:pid/runs/:rid/logs      Stream logs (SSE)
```

### Project & Sandbox
```
POST   /api/projects                          Create project
GET    /api/projects                          List projects
GET    /api/projects/:pid/status              hal status --json
GET    /api/projects/:pid/health              hal doctor --json
POST   /api/projects/:pid/sandbox/start       Start sandbox
POST   /api/projects/:pid/sandbox/stop        Stop sandbox
```

### WebSocket Events
```
WS /ws/projects/:pid

Events:
  spec_status_changed    {specId, from, to}
  story_status_changed   {storyId, from, to}
  run_progress           {runId, iteration, total, currentStory}
  run_log_line           {runId, line, timestamp}
  run_completed          {runId, result}
  sandbox_status         {name, status}
  queue_changed          {specs: [...]}
```

---

## How a PM Actually Uses This

### Scenario: Building an E-commerce App

**Morning: Write specs**
1. PM opens Hal Web, creates project "E-commerce App" linked to GitHub repo
2. Writes 3 specs:
   - "User Authentication" (priority 1)
   - "Product Catalog" (priority 2)
   - "Shopping Cart" (priority 3)
3. Each spec is a markdown document describing the feature

**Approve & Execute:**
4. PM reviews "User Authentication" spec, clicks **Approve**
5. Hal auto-converts to JSON, validates, generates 8 stories
6. PM sees stories on the board, clicks **Execute**
7. Hal spins up a sandbox, clones the repo, runs `hal init` + `hal run`
8. PM watches stories move from Pending → Running → Done in real-time

**Review:**
9. Execution completes (all 8 stories done)
10. Spec moves to "Review" column
11. PM clicks **Review** → hal runs code review
12. Review shows: "2 issues found, 1 fixed automatically"
13. PM reads the remaining issue, decides it's minor → clicks **Accept**
14. Hal creates a draft PR

**Next feature:**
15. PM clicks **Execute** on "Product Catalog" (already approved)
16. Same sandbox, new branch, hal runs the next spec
17. PM goes to lunch — execution runs in background

**No infinite loop.** Each feature starts and ends explicitly. The PM decides the pace.

---

## Tech Stack

### Frontend
- **Next.js 15** (App Router, server components where possible)
- **shadcn/ui + Tailwind** (clean, professional UI)
- **@hello-pangea/dnd** (drag-drop for kanban/queue reordering)
- **Tiptap or Monaco** (spec editor — rich markdown or code)
- **Zustand** (lightweight state management)
- **EventSource / WebSocket** (real-time updates)

### Backend (`hal serve`)
- **Go net/http + chi** (lightweight router)
- **modernc.org/sqlite** (pure Go SQLite, no CGO)
- **gorilla/websocket** (event streaming)
- **golang.org/x/crypto/ssh** (sandbox command execution)
- Embeds frontend build via `//go:embed web/dist`

### Why This Stack
- Go backend shares types with hal CLI — zero serialization bugs
- SQLite keeps it single-binary, zero-config
- Next.js gives us SSR for fast initial loads + rich client interactivity
- `//go:embed` means `hal serve` is still a single binary

---

## Implementation Phases

### Phase 1: Core Loop (4 weeks)
**Goal:** PM can write a spec, execute it, and see results

- [ ] `internal/server/` — HTTP server, SQLite, migrations
- [ ] `cmd/serve.go` — `hal serve` command
- [ ] Project + Spec CRUD API
- [ ] Spec → Story generation (`hal convert` + `hal explode` via local exec)
- [ ] Frontend: Project list, spec editor, story board
- [ ] Execution: `hal run` via local process (same machine first)
- [ ] Real-time: WebSocket log streaming + story status updates
- [ ] Spec lifecycle: Draft → Approved → Executing → Review → Done

### Phase 2: Sandbox Execution (3 weeks)
**Goal:** Execution happens in isolated sandboxes

- [ ] Sandbox provisioning (reuse `hal sandbox start`)
- [ ] Remote execution via SSH (`hal run --json` in sandbox)
- [ ] Sandbox lifecycle management (start/stop/delete from UI)
- [ ] Multi-sandbox support (parallel spec execution)
- [ ] Cost tracking (sandbox hours per spec)

### Phase 3: Review & Quality (2 weeks)
**Goal:** PM can review and approve results

- [ ] Review trigger (`hal review --base` in sandbox)
- [ ] Review results display (issues, fixes, quality score)
- [ ] Accept/Reject flow with feedback
- [ ] PR creation on accept
- [ ] Report generation and display

### Phase 4: Queue & Automation (2 weeks)
**Goal:** Multiple specs execute in sequence with configurable automation

- [ ] Spec priority queue with drag-drop reordering
- [ ] Automation levels (1-4)
- [ ] Stop conditions (budget, errors, time window)
- [ ] Notifications (spec completed, review needed, error occurred)
- [ ] Dashboard with execution history and metrics

### Phase 5: Multi-Project & Team (3 weeks)
**Goal:** Multiple projects, team access

- [ ] Multi-project portfolio view
- [ ] Auth (JWT + simple user management)
- [ ] Role-based access (admin/PM/viewer)
- [ ] Cross-project dashboard
- [ ] Activity feed

---

## Open Decisions

| Question | Options | Recommendation |
|----------|---------|---------------|
| Monorepo or separate? | `web/` in hal repo vs separate repo | Monorepo — type sharing, single version |
| Editor for specs? | Tiptap (rich) vs Monaco (code) vs textarea | Tiptap — PMs aren't developers |
| Auth from day 1? | Yes vs add later | No auth Phase 1 (localhost only), add Phase 5 |
| Local-first or cloud-first? | `hal serve` locally vs hosted | Local-first, cloud option later |
| Real-time mechanism? | WebSocket vs SSE vs polling | WebSocket for logs, polling for status |
| Sandbox per spec or per project? | Shared vs isolated | Per-project (shared), with option for per-spec |
