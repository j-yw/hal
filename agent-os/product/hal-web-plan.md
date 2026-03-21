# Hal Web — Project Management Frontend for Hal CLI

## Vision

A web-based project management UI on top of `hal` CLI — where product/engineering managers define **what** to build, and hal autonomously executes it in sandboxes. The manager stays in control of **when** things run and **what** gets approved.

---

## The Execution Pipeline: Configurable Stages with Human Gates

The key insight: hal's CLI has 3 distinct capabilities that can be mixed and matched:

| Capability | CLI Command | What It Does |
|-----------|-------------|-------------|
| **Execute** | `hal run` | Runs ALL stories in a PRD to completion |
| **Review** | `hal review --base` | Iterative code review/fix loop (find issues → fix → repeat until clean) |
| **Report** | `hal report` | Generates summary report, discovers patterns, updates AGENTS.md |

Plus the compound pipeline (`hal auto`) which chains: analyze → branch → prd → explode → execute → pr.

In the web UI, these become **pipeline stages** that a PM can toggle on/off, and between any two stages there can be a **human approval gate**.

---

## The Pipeline Builder

Each spec has a configurable pipeline. The PM chooses which stages to include and where approval gates go.

### Pipeline Presets

**Preset 1: Basic (Default)**
```
Execute → Done
```
Just run all stories. PM reviews the PR manually in GitHub.

**Preset 2: With Review**
```
Execute → Review Loop → Done
```
After stories are done, hal auto-reviews the code, fixes issues, and iterates until clean. PM gets a polished result.

**Preset 3: With Approval Gate**
```
Execute → ⏸ PM Reviews → Review Loop → ⏸ PM Approves → Done
```
PM inspects execution results before review loop starts. After review loop, PM approves before PR creation.

**Preset 4: Full Compound**
```
Execute → Review Loop → Report → ⏸ PM Reviews → Done
```
After execution and review, generate a full report with pattern discovery. PM reviews the report and decides next steps.

**Preset 5: Continuous (with safety rails)**
```
Execute → Review Loop → Report → ⏸ PM Reviews Report
                                        │
                                        ▼ (PM approves)
                              Auto Pipeline (next feature)
                                        │
                                        ▼
                              Execute → Review Loop → Report → ⏸ PM Reviews
                                                                     │
                                                                    ...
```
This is the compound loop — but with a **mandatory PM checkpoint** between features. The report from feature N feeds into the auto pipeline for feature N+1, but only after PM approval.

### Custom Pipeline (Drag-and-Drop)

PMs can build custom pipelines by dragging stages:

```
┌─────────────────────────────────────────────────────────────┐
│  Pipeline for: "User Authentication"                         │
│                                                              │
│  Available Stages:        Your Pipeline:                     │
│  ┌──────────────┐        ┌──────────────┐                   │
│  │ ▶ Execute    │───────▶│ 1. Execute   │                   │
│  └──────────────┘        ├──────────────┤                   │
│  ┌──────────────┐        │ 2. ⏸ Gate    │ ← "Review exec"  │
│  │ 🔍 Review    │───────▶├──────────────┤                   │
│  └──────────────┘        │ 3. Review    │                   │
│  ┌──────────────┐        ├──────────────┤                   │
│  │ 📊 Report    │        │ 4. Report    │                   │
│  └──────────────┘        ├──────────────┤                   │
│  ┌──────────────┐        │ 5. ⏸ Gate    │ ← "Final approve"│
│  │ ⏸ Gate       │        ├──────────────┤                   │
│  └──────────────┘        │ 6. Create PR │                   │
│  ┌──────────────┐        └──────────────┘                   │
│  │ 🔀 Create PR │                                           │
│  └──────────────┘        [Save as preset ▼]                 │
│  ┌──────────────┐                                           │
│  │ 🔄 Auto Next │ ← feeds report into next spec            │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Pipeline Stages in Detail

### Stage: Execute (`hal run`)
Runs all stories in the spec's PRD to completion.

**Inputs:** Converted + exploded PRD (stories)
**What happens:**
1. Server calls `hal run -i 50 --json` in the sandbox
2. hal picks next pending story, implements it, commits, repeats
3. WebSocket streams progress: which story is running, iteration count
4. Continues until all stories pass or max iterations hit

**Outputs:** Updated PRD with `passes: true` on completed stories
**Status on board:** Stories move from Pending → Done in real-time

**Options:**
- Max iterations (default: 50)
- Engine (codex/claude/pi)
- Timeout per story
- Run specific story only (`hal run -s T-003`)

### Stage: Review Loop (`hal review --base`)
Iterative code review: find issues → auto-fix → review again → repeat until clean.

**Inputs:** Completed code on feature branch
**What happens:**
1. Server calls `hal review --base <base-branch> --json -i 5` in sandbox
2. hal diffs the feature branch against base
3. AI reviews the diff, finds issues (with severity/file/line)
4. AI auto-fixes what it can
5. Repeats until no valid issues remain or max iterations hit

**Outputs:** `ReviewLoopResult` with:
- Issues found / valid / invalid / fixed counts
- Per-iteration breakdown
- Stop reason (`no_valid_issues` or `max_iterations`)

**Status on board:** Shows quality badge: "✅ Clean" or "⚠ 3 issues remaining"

**Options:**
- Max review iterations (default: 5)
- Engine for review
- Severity threshold (skip minor issues)

### Stage: Report (`hal report`)
Generate a summary report, discover patterns, update AGENTS.md.

**Inputs:** Completed work session (git diff, progress, PRD)
**What happens:**
1. Server calls `hal report --json` in sandbox
2. hal gathers context: progress log, git diff, commits, PRD
3. AI analyzes what was built and how
4. Identifies patterns worth documenting
5. Updates AGENTS.md with discovered patterns
6. Writes report to `.hal/reports/`

**Outputs:** `ReportResult` with:
- Report path
- Summary
- Patterns added to AGENTS.md
- Recommendations for next steps

**Status on board:** Report card shows summary + recommendations

**Why this matters for compound loop:**
The report's recommendations feed into the next feature decision. If "Auto Next" stage follows, the report becomes the input for `hal auto` which picks the next priority item.

### Stage: Approval Gate (⏸)
Human checkpoint. Nothing proceeds until PM/EM explicitly approves.

**What PM sees:**
- Summary of what completed in the previous stage
- For post-Execute: story completion status, any failures
- For post-Review: issues found/fixed, quality score
- For post-Report: summary, recommendations, patterns discovered

**PM actions:**
- **Approve** → pipeline continues to next stage
- **Reject** → spec goes back to Draft with PM's feedback notes
- **Retry** → re-run the previous stage (useful for flaky failures)

### Stage: Create PR (`git push` + `gh pr create`)
Push branch and create a draft pull request.

**Inputs:** Completed and reviewed code
**What happens:**
1. Push feature branch to remote
2. Create draft PR with description from spec + task status

**Outputs:** PR URL

### Stage: Auto Next (🔄)
Feed the report into `hal auto` to pick and execute the next feature.

**Inputs:** Report from previous stage
**What happens:**
1. `hal auto --report <path>` runs the full compound pipeline
2. Analyzes report → identifies priority item → creates branch → generates PRD → explodes → runs
3. This effectively creates a NEW spec on the board and starts executing it

**Critical constraint:** Auto Next always ends with an approval gate before starting execution. The PM sees "hal wants to work on X next — approve?"

```
... → Report → Auto Next → ⏸ "Work on X?" → Execute → ...
```

---

## How This Maps to the Board

### Spec Queue (Outer Board)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📝 Draft (2)    ✅ Approved (1)   ⏳ Running (1)                  │
│  ┌──────────┐   ┌──────────┐     ┌──────────────────────────┐     │
│  │ Payment  │   │ Reviews  │     │ Search Feature            │     │
│  │ Flow     │   │ System   │     │                            │     │
│  │          │   │          │     │ Pipeline: Execute → Review │     │
│  │ [Edit]   │   │ [▶ Run]  │     │ Stage: Execute (5/8)     │     │
│  └──────────┘   └──────────┘     │ ████████░░░ 62%           │     │
│  ┌──────────┐                     └──────────────────────────┘     │
│  │ Email    │                                                      │
│  │ Tpl      │    ⏸ Waiting (1)         ✓ Done (2)                  │
│  │ [Edit]   │   ┌──────────────┐     ┌──────────┐                 │
│  └──────────┘   │ Auth         │     │ DB Setup │                 │
│                  │              │     │ Cart     │                 │
│                  │ Gate: Review │     └──────────┘                 │
│                  │ results      │                                   │
│                  │ 2 issues     │                                   │
│                  │ [Approve ✓]  │                                   │
│                  │ [Reject ✗]   │                                   │
│                  │ [Retry 🔄]   │                                   │
│                  └──────────────┘                                   │
└─────────────────────────────────────────────────────────────────────┘
```

Notice "Auth" is in the **Waiting** column — it finished execution and review, but is paused at an approval gate. The PM sees the review results (2 issues remaining) and decides whether to approve (create PR), reject (back to draft), or retry (re-run review).

### Spec Detail View (Pipeline Progress)

```
┌─────────────────────────────────────────────────────────────────────┐
│  ← Back │ Search Feature │ Pipeline Progress                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ✅ Execute ────── ⏳ Review ────── ○ Gate ────── ○ PR              │
│     8/8 tasks       Iteration 2/5    Pending       Pending          │
│     complete        3 issues → 1                                    │
│                                                                     │
│  ┌─── Story Board ─────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  Pending (0)       Running (0)          Done (8)             │   │
│  │                                        ┌──────────┐         │   │
│  │                                        │ T-001 ✓  │         │   │
│  │                                        │ T-002 ✓  │         │   │
│  │                                        │ T-003 ✓  │         │   │
│  │                                        │ T-004 ✓  │         │   │
│  │                                        │ T-005 ✓  │         │   │
│  │                                        │ T-006 ✓  │         │   │
│  │                                        │ T-007 ✓  │         │   │
│  │                                        │ T-008 ✓  │         │   │
│  │                                        └──────────┘         │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── Review Loop (Live) ──────────────────────────────────────┐   │
│  │  Iteration 2/5                                               │   │
│  │  ┌─────────────────────────────────────────────────────┐    │   │
│  │  │ Iter 1: 5 issues found, 3 valid, 2 auto-fixed      │    │   │
│  │  │ Iter 2: 2 issues found, 1 valid, fixing...         │    │   │
│  │  └─────────────────────────────────────────────────────┘    │   │
│  │  [⏹ Stop Review]                                            │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  [📋 Execution Log]  [📋 Review Log]  [⚙ Pipeline Settings]       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The Compound Loop in Practice

### Scenario: Continuous Feature Development

PM sets up a project with **Preset 5 (Continuous)** pipeline:

```
Execute → Review → Report → ⏸ PM Review → Auto Next → ⏸ PM Approve → ...
```

**Round 1:**
1. PM writes spec "User Auth", approves it
2. Hal executes all 8 stories → ✅ complete
3. Hal runs review loop → 3 issues found, 2 auto-fixed, 1 remaining
4. Hal generates report → "Auth complete. Recommend: add search next."
5. **Pipeline pauses at gate.** PM gets notification.
6. PM opens Hal Web, sees report summary:
   - Auth: 8/8 stories done
   - Review: 1 minor issue remaining (cosmetic)
   - Recommendation: "Search feature" next
7. PM clicks **Approve**

**Round 2 (Auto-generated):**
8. `hal auto` analyzes the report, identifies "Search feature" as priority
9. A new spec card appears on the board: "Search Feature (auto-generated)"
10. **Pipeline pauses at "PM Approve" gate.** PM sees:
    - Auto-generated spec title and description
    - Estimated 10 tasks
    - Proposed branch: `hal/search-feature`
11. PM reviews the auto-generated scope, clicks **Approve**
12. Hal executes → reviews → reports → pauses for PM again

**The loop continues but NEVER without PM awareness.** Each feature cycle has two mandatory checkpoints:
1. Post-report: "Here's what we did, here's what's next — approve?"
2. Pre-execution: "We want to build X — approve?"

### Stopping the Loop

The PM can break the loop at any checkpoint by:
- Clicking **Reject** (returns to draft, PM rewrites spec)
- Clicking **Pause** (holds the queue, PM comes back later)
- Reordering the queue (different spec goes next)
- Setting a **stop condition** (budget/time/error threshold)

---

## Pipeline Data Model

```sql
-- Spec pipeline configuration
CREATE TABLE spec_pipelines (
    spec_id       TEXT PRIMARY KEY REFERENCES specs(id),
    preset        TEXT DEFAULT 'basic',      -- basic|with_review|with_gate|compound|continuous|custom
    stages        TEXT NOT NULL,              -- JSON array of stage definitions
    current_stage INTEGER DEFAULT 0,          -- Index into stages array
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Individual stage execution records
CREATE TABLE stage_runs (
    id            TEXT PRIMARY KEY,
    spec_id       TEXT REFERENCES specs(id),
    stage_index   INTEGER NOT NULL,
    stage_type    TEXT NOT NULL,              -- execute|review|report|gate|pr|auto_next
    status        TEXT DEFAULT 'pending',     -- pending|running|completed|failed|waiting
    result        TEXT,                       -- JSON: stage-specific result
    started_at    DATETIME,
    completed_at  DATETIME,
    
    -- Gate-specific fields
    gate_label    TEXT,                       -- "Review results" / "Final approve"
    gate_action   TEXT,                       -- approve|reject|retry (set by PM)
    gate_notes    TEXT,                       -- PM's feedback
    gate_acted_by TEXT,                       -- Who approved/rejected
    gate_acted_at DATETIME
);
```

Stage definition JSON:
```json
[
  {"type": "execute", "config": {"maxIterations": 50, "engine": "codex"}},
  {"type": "review",  "config": {"maxIterations": 5, "engine": "codex"}},
  {"type": "gate",    "config": {"label": "Review results before PR"}},
  {"type": "report",  "config": {"skipAgents": false}},
  {"type": "pr",      "config": {}},
  {"type": "auto_next", "config": {"requireApproval": true}}
]
```

---

## Pipeline API

```
# Pipeline configuration
GET    /api/specs/:sid/pipeline              Get pipeline config + current state
PUT    /api/specs/:sid/pipeline              Update pipeline (set preset or custom stages)

# Pipeline control
POST   /api/specs/:sid/pipeline/start        Start pipeline execution
POST   /api/specs/:sid/pipeline/pause        Pause at current stage
POST   /api/specs/:sid/pipeline/resume       Resume paused pipeline

# Gate actions (PM interactions)
POST   /api/specs/:sid/stages/:idx/approve   Approve gate → advance pipeline
POST   /api/specs/:sid/stages/:idx/reject    Reject → spec back to draft
POST   /api/specs/:sid/stages/:idx/retry     Retry previous stage

# Stage details
GET    /api/specs/:sid/stages                List all stages with status
GET    /api/specs/:sid/stages/:idx           Get stage detail + result

# WebSocket events for pipeline progress
WS /ws/specs/:sid/pipeline
  pipeline_stage_changed   {stageIndex, stageType, status}
  gate_waiting             {stageIndex, label, summary}
  stage_progress           {stageIndex, type: "execute", iteration, total, story}
  stage_progress           {stageIndex, type: "review", iteration, total, issues}
  auto_next_proposed       {proposedSpec, title, description, tasks}
```

---

## Automation Levels (Project-Wide Setting)

These control the DEFAULT pipeline preset for new specs:

| Level | Preset | Gates | Best For |
|-------|--------|-------|----------|
| 1 — Manual | Basic | PM must click Execute, no auto-review | Learning, high-risk code |
| 2 — Semi-Auto | With Gate | Auto-execute on approve, gate before PR | Day-to-day work |
| 3 — Compound | Compound | Execute+Review+Report auto, gate before next | Trusted codebase |
| 4 — Continuous | Continuous | Full loop with 2 PM gates per feature | Overnight batch |

PMs can override the project default per-spec. A "Payment Flow" spec might use Manual even in a Continuous project.

### Stop Conditions (Safety Rails for Level 3-4)

| Condition | Default | Effect |
|-----------|---------|--------|
| Queue empty | Always on | Pipeline idles when no approved specs remain |
| Budget limit | Off | Pause when sandbox hours exceed threshold |
| Error threshold | 3 failures | Pause after N consecutive stage failures |
| Time window | Off | Only advance pipeline during configured hours |
| Review severity | Off | Pause if review finds critical/high severity issues |

---

## Full Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Hal Web (Next.js)                      │
│  Spec Editor │ Pipeline Builder │ Board │ Gate Actions   │
└──────────────────────────┬──────────────────────────────┘
                           │ REST + WebSocket
┌──────────────────────────▼──────────────────────────────┐
│                  Hal Server (Go)                         │
│  `hal serve` — same binary, shares all internal types    │
│                                                          │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Pipeline   │  │ Event Bus    │  │ Sandbox Mgr    │  │
│  │ Executor   │  │ WebSocket    │  │ SSH hal cmds   │  │
│  │ per spec   │  │ broadcast    │  │ multi-sandbox  │  │
│  └────────────┘  └──────────────┘  └────────────────┘  │
│  ┌────────────┐  ┌──────────────┐                       │
│  │ Job Queue  │  │ SQLite       │                       │
│  │ stage exec │  │ specs/stages │                       │
│  └────────────┘  └──────────────┘                       │
└──────────────────────────┬──────────────────────────────┘
                           │ SSH + hal CLI --json
┌──────────────────────────▼──────────────────────────────┐
│              Sandboxes (Isolated VMs)                     │
│  sandbox-1: hal run → hal review → hal report            │
│  sandbox-2: hal run (different spec, parallel)           │
└─────────────────────────────────────────────────────────┘
```

### Pipeline Executor (Server-Side)

The core server loop per spec:

```go
func (p *PipelineExecutor) Run(ctx context.Context, specID string) error {
    pipeline := p.loadPipeline(specID)
    
    for i := pipeline.CurrentStage; i < len(pipeline.Stages); i++ {
        stage := pipeline.Stages[i]
        
        switch stage.Type {
        case "execute":
            // SSH into sandbox: hal run -i 50 --json
            // Stream progress via WebSocket
            result, err := p.runExecute(ctx, specID, stage.Config)
            p.saveStageResult(specID, i, result)
            
        case "review":
            // SSH into sandbox: hal review --base <branch> --json -i 5
            result, err := p.runReview(ctx, specID, stage.Config)
            p.saveStageResult(specID, i, result)
            
        case "report":
            // SSH into sandbox: hal report --json
            result, err := p.runReport(ctx, specID, stage.Config)
            p.saveStageResult(specID, i, result)
            
        case "gate":
            // STOP. Set status to "waiting". 
            // PM must call /api/specs/:id/stages/:i/approve to continue.
            p.setStageWaiting(specID, i, stage.Config.Label)
            p.broadcastGateWaiting(specID, i)
            return nil  // Exit loop. PM action resumes it.
            
        case "pr":
            // SSH: git push + gh pr create
            result, err := p.runCreatePR(ctx, specID, stage.Config)
            p.saveStageResult(specID, i, result)
            
        case "auto_next":
            // SSH: hal auto --report <path> --json
            // Creates a NEW spec on the board from the report
            newSpec, err := p.runAutoNext(ctx, specID, stage.Config)
            if stage.Config.RequireApproval {
                // The new spec starts in "approved" but its pipeline
                // begins with a gate: "hal wants to build X — approve?"
                p.createSpecWithGate(newSpec)
            }
        }
        
        pipeline.CurrentStage = i + 1
        p.savePipeline(specID, pipeline)
    }
    
    p.markSpecDone(specID)
    return nil
}
```

When PM clicks "Approve" on a gate:
```go
func (h *Handler) ApproveGate(specID string, stageIndex int) {
    p.setStageCompleted(specID, stageIndex, "approved")
    // Resume pipeline from next stage
    go p.pipelineExecutor.Run(ctx, specID)
}
```

---

## Implementation Phases

### Phase 1: Core + Basic Pipeline (4 weeks)
- [ ] `hal serve` — HTTP server, SQLite, migrations
- [ ] Project + Spec CRUD
- [ ] Spec → stories (convert + explode)
- [ ] Basic pipeline (Execute only)
- [ ] Frontend: board, spec editor, story cards
- [ ] Execution via local process + WebSocket log streaming
- [ ] Real-time story status updates

### Phase 2: Pipeline Stages (3 weeks)
- [ ] Pipeline model (stages, gates, presets)
- [ ] Review stage (`hal review --json`)
- [ ] Report stage (`hal report --json`)
- [ ] Approval gates (waiting state, PM actions)
- [ ] Frontend: pipeline builder, gate UI, stage progress
- [ ] Pipeline presets (basic, with_review, with_gate, compound)

### Phase 3: Sandbox + Compound (3 weeks)
- [ ] Sandbox provisioning from UI
- [ ] Remote execution via SSH
- [ ] Auto Next stage (compound loop)
- [ ] Continuous pipeline with PM checkpoints
- [ ] Stop conditions
- [ ] Multi-sandbox parallel execution

### Phase 4: Polish & Team (3 weeks)
- [ ] Dashboard + analytics
- [ ] Notifications (gate waiting, spec done, errors)
- [ ] Auth + multi-user
- [ ] Multi-project portfolio
- [ ] Custom pipeline presets

---

## How a PM Uses the Compound Loop

### Day 1: Set up the project
1. Create project linked to GitHub repo
2. Set automation level to **3 (Compound)**
3. Default pipeline becomes: Execute → Review → Report → ⏸ Gate → Auto Next → ⏸ Gate

### Day 1: Kick off first feature
4. Write spec "User Auth", click Approve
5. Pipeline starts automatically (level 3)
6. PM goes to lunch

### Day 1 afternoon: First checkpoint
7. PM gets notification: "User Auth complete — review results ready"
8. Opens board, sees Auth in "Waiting" column
9. Views: 8/8 stories done, review found 1 minor issue, report recommends "Search" next
10. Clicks **Approve**
11. Auto Next generates a new spec "Search Feature" on the board
12. Pipeline pauses: "hal wants to build Search Feature (10 tasks) — approve?"
13. PM reviews the auto-generated scope
14. PM adjusts the spec slightly (adds a requirement), clicks **Approve**
15. Hal starts executing Search

### Day 2 morning: Second checkpoint
16. Search is done + reviewed + reported
17. PM reviews, approves → Auto Next proposes "Payment Flow"
18. PM says "actually, I want to prioritize email templates"
19. Clicks **Reject** on the auto-proposed spec
20. Writes "Email Templates" spec manually, approves it
21. Pipeline continues with PM's choice instead of hal's suggestion

**The compound loop runs, but the PM is always the conductor.**

---

## Tech Stack

### Frontend
- **Next.js 15** (App Router)
- **shadcn/ui + Tailwind**
- **@hello-pangea/dnd** (drag-drop for board + pipeline builder)
- **Tiptap** (spec editor)
- **Zustand** (state)
- **EventSource / WebSocket** (real-time)

### Backend (`hal serve`)
- **Go net/http + chi** (router)
- **modernc.org/sqlite** (pure Go SQLite)
- **gorilla/websocket** (events)
- **golang.org/x/crypto/ssh** (sandbox execution)
- Embedded frontend via `//go:embed web/dist`
- Shares types with hal CLI (same binary)

---

## Open Decisions

| Question | Recommendation |
|----------|---------------|
| Should Auto Next require PM approval? | Yes, always — even at level 4. The PM can approve in batch ("approve next 3") but must see what's proposed. |
| Can PM edit auto-generated specs? | Yes. Auto Next creates a Draft that PM can edit before approving. |
| Parallel specs or sequential? | Both. Default sequential (one sandbox). PM can enable parallel (multiple sandboxes, higher cost). |
| Where do pipeline presets live? | Project-level default + per-spec override. |
| Gate timeout? | Configurable. Default: none (wait forever). Option: auto-approve after N hours if all quality checks pass. |
