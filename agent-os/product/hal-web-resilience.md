# Hal Web — Resilience: Stop, Resume, and Failure Recovery

## The Failure Modes

There are 5 distinct things that can break during pipeline execution:

```
┌─────────┐     SSH      ┌─────────┐    process    ┌─────────┐
│  Hal    │─────────────▶│ Sandbox │──────────────▶│ codex   │
│ Server  │◀─────────────│  (VM)   │◀──────────────│ CLI     │
└─────────┘              └─────────┘               └─────────┘
     │                        │                         │
  1. Server crash         3. VM reboot             5. LLM timeout
  2. Network drop         4. SSH disconnect            API error
     (browser→server)        (server→sandbox)          rate limit
```

| # | Failure | Who notices? | What's at risk? |
|---|---------|-------------|-----------------|
| 1 | **Server crash** | Nobody until restart | Server-side pipeline state |
| 2 | **Browser disconnects** | User sees spinner | Nothing — server keeps running |
| 3 | **Sandbox VM reboots** | Server sees SSH drop | Running codex process killed |
| 4 | **SSH drops** (network) | Server sees connection error | codex keeps running in sandbox (orphaned) |
| 5 | **LLM failure** | codex CLI handles retries | Current story iteration |

## Key Insight: hal Already Has 2 Recovery Layers

### Layer 1: PRD is the checkpoint file (story level)
```json
// .hal/prd.json — updated after each story completes
{
  "userStories": [
    {"id": "T-001", "passes": true},   // ← committed to git
    {"id": "T-002", "passes": true},   // ← committed to git  
    {"id": "T-003", "passes": false},  // ← was running when crash happened
    {"id": "T-004", "passes": false}   // ← not started yet
  ]
}
```

After any crash, `hal run` reads `prd.json`, finds the first story with `passes: false`, and continues from there. **Completed stories are never re-executed.** Each story completion = git commit in the sandbox.

### Layer 2: Pipeline state file (stage level)
```json
// .hal/auto-state.json — updated after each pipeline step
{
  "step": "loop",           // ← resume from here
  "branchName": "hal/auth",
  "prdPath": ".hal/prd-auth.md",
  "loopIterations": 5
}
```

After any crash, `hal auto --resume` reads `auto-state.json` and picks up from the last completed step. Steps are atomic: analyze, branch, prd, explode, loop, pr.

### What This Means for the Web Server
**The sandbox is self-healing.** If anything crashes, the server just needs to SSH back in and run `hal run` or `hal auto --resume` — hal picks up where it left off. The server doesn't need to track individual story progress; it just needs to know which stage to retry.

---

## Server-Side State Machine

The server adds a third layer of state on top of hal's two:

```
┌───────────────────────────────────────────────────────────────┐
│ Layer 3: Server DB (spec + pipeline state)                    │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ Layer 2: Sandbox .hal/auto-state.json (pipeline step)     │ │
│ │ ┌───────────────────────────────────────────────────────┐ │ │
│ │ │ Layer 1: Sandbox .hal/prd.json (story passes)         │ │ │
│ │ │          + git commits (actual code)                   │ │ │
│ │ └───────────────────────────────────────────────────────┘ │ │
│ └───────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

### Server Pipeline State
```sql
CREATE TABLE pipeline_runs (
    id              TEXT PRIMARY KEY,
    spec_id         TEXT REFERENCES specs(id),
    status          TEXT NOT NULL,     -- running|paused|waiting|completed|failed|recovering
    current_stage   INTEGER NOT NULL,
    stages          TEXT NOT NULL,     -- JSON: stage definitions
    
    -- Recovery fields
    sandbox_name    TEXT,
    sandbox_pid     INTEGER,          -- PID of hal process in sandbox (for orphan detection)
    last_heartbeat  DATETIME,         -- Last time server confirmed sandbox is alive
    retry_count     INTEGER DEFAULT 0,
    max_retries     INTEGER DEFAULT 3,
    
    -- Timing
    started_at      DATETIME,
    updated_at      DATETIME,
    completed_at    DATETIME
);

CREATE TABLE stage_executions (
    id              TEXT PRIMARY KEY,
    pipeline_run_id TEXT REFERENCES pipeline_runs(id),
    stage_index     INTEGER NOT NULL,
    stage_type      TEXT NOT NULL,
    status          TEXT NOT NULL,     -- pending|running|completed|failed|waiting|recovering
    
    -- Execution tracking
    attempt         INTEGER DEFAULT 1,
    ssh_session_id  TEXT,             -- Track which SSH connection owns this
    hal_command     TEXT,             -- Exact command being run (for resume)
    
    -- Result
    result          TEXT,             -- JSON from hal --json
    error_message   TEXT,
    
    -- Timing
    started_at      DATETIME,
    completed_at    DATETIME
);
```

---

## Handling Each Failure Mode

### Failure 1: Server Crash / Restart

**What happens:** Server process dies. All in-memory state lost. SSH connections drop. Sandbox processes may or may not keep running.

**Recovery on restart:**

```go
func (s *Server) RecoverOnStartup() {
    // Find all pipeline_runs with status = "running"
    activeRuns := s.db.FindPipelineRuns(status: "running")
    
    for _, run := range activeRuns {
        // Mark as recovering (UI shows "reconnecting...")
        s.db.UpdateStatus(run.ID, "recovering")
        
        // Check if sandbox is still alive
        sandbox := s.sandboxManager.Status(run.SandboxName)
        if sandbox.Status != "running" {
            // Sandbox died too. Mark failed, let PM decide.
            s.db.UpdateStatus(run.ID, "failed")
            s.db.SetError(run.ID, "server restarted, sandbox not running")
            s.notify(run.SpecID, "Pipeline interrupted — sandbox stopped")
            continue
        }
        
        // Sandbox is alive. Check if hal is still running inside it.
        halRunning := s.checkHalProcess(run)
        
        if halRunning {
            // hal is still executing! Reconnect the SSH log stream.
            s.reconnectLogStream(run)
            s.db.UpdateStatus(run.ID, "running")
        } else {
            // hal finished or crashed while server was down.
            // Check prd.json to see where we are.
            s.syncStateFromSandbox(run)
        }
    }
}
```

**Key principle:** On restart, the server **asks the sandbox what happened** rather than guessing. The sandbox's `prd.json` and `auto-state.json` are the source of truth.

### Failure 2: Browser Disconnects

**What happens:** User closes tab, WiFi drops, etc. WebSocket dies.

**Recovery:** Nothing to recover. **The server keeps running.** The pipeline executor is a server-side goroutine, not tied to the browser connection.

```go
// Pipeline execution lives on the server, not the browser
func (s *Server) StartPipeline(specID string) {
    // This goroutine survives browser disconnects
    go func() {
        s.pipelineExecutor.Run(ctx, specID)
    }()
}

// WebSocket is just an observer — connect/disconnect doesn't affect execution
func (s *Server) HandleWebSocket(conn *websocket.Conn, specID string) {
    // Subscribe to events for this spec
    sub := s.eventBus.Subscribe(specID)
    defer sub.Unsubscribe()
    
    for event := range sub.Events() {
        if err := conn.WriteJSON(event); err != nil {
            return // Browser gone, but pipeline keeps running
        }
    }
}
```

When the user reconnects:
1. Frontend fetches current pipeline state via REST API
2. Reconnects WebSocket for live updates
3. UI shows current progress as if nothing happened

### Failure 3: Sandbox VM Reboots / Crashes

**What happens:** The VM restarts. All running processes killed. Filesystem state preserved (prd.json, auto-state.json, git commits all survive).

**Detection:** Heartbeat fails.

```go
func (s *Server) HeartbeatLoop(run *PipelineRun) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    consecutiveFailures := 0
    
    for {
        select {
        case <-ticker.C:
            err := s.sandboxManager.Ping(run.SandboxName)
            if err != nil {
                consecutiveFailures++
                if consecutiveFailures >= 3 {
                    // Sandbox is down for 90+ seconds
                    s.handleSandboxDown(run)
                    return
                }
            } else {
                consecutiveFailures = 0
                s.db.UpdateHeartbeat(run.ID, time.Now())
            }
        case <-run.Done():
            return
        }
    }
}

func (s *Server) handleSandboxDown(run *PipelineRun) {
    s.db.UpdateStatus(run.ID, "recovering")
    s.broadcast(run.SpecID, Event{Type: "pipeline_recovering", Reason: "sandbox unreachable"})
    
    // Wait for sandbox to come back (with timeout)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()
    
    if err := s.sandboxManager.WaitReady(ctx, run.SandboxName); err != nil {
        // Sandbox didn't come back
        s.db.UpdateStatus(run.ID, "failed")
        s.broadcast(run.SpecID, Event{Type: "pipeline_failed", Reason: "sandbox did not recover"})
        return
    }
    
    // Sandbox is back. Sync state and resume.
    s.syncStateFromSandbox(run)
    s.resumePipeline(run)
}
```

**Recovery:**
1. Server detects sandbox is back via heartbeat
2. SSHs in, reads `prd.json` to see which stories completed
3. Reads `auto-state.json` to see pipeline step
4. Updates server DB to match
5. Re-runs current stage (hal automatically picks up from last completed story)

### Failure 4: SSH Connection Drops (Network Blip)

**This is the trickiest failure.** The SSH session between server and sandbox drops, but:
- The sandbox VM is fine
- `codex` might still be running inside the sandbox (it was started by SSH, but depending on the shell setup, it may or may not get SIGHUP)

**The problem:** If codex is still running, we don't want to start another `hal run` — that would create conflicts. If codex died, we do want to restart.

**Solution: Execution wrapper script in the sandbox**

Instead of running `hal run --json` directly via SSH, the server deploys a small wrapper:

```bash
#!/bin/bash
# /tmp/hal-runner.sh — deployed to sandbox by server
# Runs hal in background with PID tracking and output capture

PIDFILE="/tmp/hal-runner.pid"
LOGFILE="/tmp/hal-runner.log"
STATUSFILE="/tmp/hal-runner.status"

# If already running, exit
if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
    echo "ALREADY_RUNNING pid=$(cat $PIDFILE)"
    exit 0
fi

# Run hal in background, capture output
echo "starting" > "$STATUSFILE"
nohup hal run -i 50 --json > "$LOGFILE" 2>&1 &
echo $! > "$PIDFILE"
echo "STARTED pid=$!"
```

Server-side orchestration:

```go
func (s *Server) RunExecuteStage(ctx context.Context, run *PipelineRun, config StageConfig) error {
    sandbox := s.sandboxManager.Get(run.SandboxName)
    
    // 1. Deploy wrapper script (idempotent)
    s.deployRunner(sandbox, config)
    
    // 2. Start hal via wrapper (safe to call multiple times)
    output, err := sandbox.Exec("bash /tmp/hal-runner.sh")
    if strings.Contains(output, "ALREADY_RUNNING") {
        // Previous run still going — just reconnect the log stream
        s.tailLog(ctx, sandbox, run, "/tmp/hal-runner.log")
        return nil
    }
    
    // 3. Tail the log file over SSH (survives SSH reconnects)
    s.tailLog(ctx, sandbox, run, "/tmp/hal-runner.log")
    
    // 4. When log tailing ends (hal finished or SSH dropped), check result
    return s.checkRunResult(sandbox, run)
}

func (s *Server) tailLog(ctx context.Context, sandbox *Sandbox, run *PipelineRun, logFile string) {
    for {
        // tail -f via SSH — if SSH drops, we reconnect and seek to last position
        err := sandbox.ExecStream(ctx, fmt.Sprintf("tail -f -n +%d %s", run.LogOffset, logFile), 
            func(line string) {
                run.LogOffset++
                s.broadcast(run.SpecID, Event{Type: "run_log_line", Line: line})
                
                // Parse progress from hal's output
                if progress := parseHalProgress(line); progress != nil {
                    s.db.UpdateProgress(run.ID, progress)
                    s.broadcast(run.SpecID, Event{Type: "run_progress", Data: progress})
                }
            })
        
        if err == nil {
            return // Log stream ended normally (hal finished)
        }
        
        // SSH dropped. Wait and reconnect.
        select {
        case <-ctx.Done():
            return
        case <-time.After(5 * time.Second):
            // Check if hal is still running before reconnecting
            if !s.isHalRunning(sandbox) {
                return // hal finished while we were disconnected
            }
            // Reconnect tail from where we left off
            continue
        }
    }
}

func (s *Server) isHalRunning(sandbox *Sandbox) bool {
    output, err := sandbox.Exec("cat /tmp/hal-runner.pid && kill -0 $(cat /tmp/hal-runner.pid) 2>/dev/null && echo ALIVE || echo DEAD")
    return err == nil && strings.Contains(output, "ALIVE")
}
```

### Failure 5: LLM API Errors (Rate Limits, Timeouts)

**Already handled by hal.** The loop runner has built-in retry with exponential backoff:

```go
// internal/loop/loop.go — already exists
func (r *Runner) executeWithRetry(ctx context.Context, prompt string) engine.Result {
    for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return engine.Result{Error: ctx.Err()}
            case <-time.After(r.retryDelay(attempt)):
            }
        }
        lastResult = r.engine.Execute(ctx, prompt, r.display)
        if lastResult.Success || lastResult.Complete {
            return lastResult
        }
        if lastResult.Error != nil && !r.isRetryable(lastResult.Error) {
            return lastResult
        }
    }
    return lastResult
}
```

Retryable patterns: `rate limit`, `timeout`, `connection`, `503`, `429`, `overloaded`.

The server just needs to surface these retries in the UI so the PM can see "Story T-003: attempt 2/4 (rate limited)".

---

## The Sync Protocol: Server ↔ Sandbox

The server periodically syncs state FROM the sandbox to stay accurate. This handles all edge cases — even ones we didn't anticipate.

```go
func (s *Server) SyncStateFromSandbox(run *PipelineRun) error {
    sandbox := s.sandboxManager.Get(run.SandboxName)
    
    // 1. Read prd.json from sandbox → know which stories are done
    prdJSON, err := sandbox.Exec("cat .hal/prd.json")
    if err != nil {
        return fmt.Errorf("failed to read prd.json: %w", err)
    }
    
    var prd engine.PRD
    json.Unmarshal([]byte(prdJSON), &prd)
    
    // Update story statuses in server DB
    for _, story := range prd.UserStories {
        if story.Passes {
            s.db.UpdateStoryStatus(run.SpecID, story.ID, "done")
        }
    }
    
    // 2. Read auto-state.json → know which pipeline step we're on
    stateJSON, _ := sandbox.Exec("cat .hal/auto-state.json 2>/dev/null")
    if stateJSON != "" {
        var state compound.PipelineState
        json.Unmarshal([]byte(stateJSON), &state)
        // Map hal pipeline steps to server pipeline stages
        s.reconcileStages(run, &state)
    }
    
    // 3. Read hal status --json → canonical state
    statusJSON, _ := sandbox.Exec("hal status --json")
    if statusJSON != "" {
        // Use hal's own state assessment as final truth
        s.reconcileFromStatus(run, statusJSON)
    }
    
    // 4. Check git log for commits since last sync
    commits, _ := sandbox.Exec(fmt.Sprintf("git log --oneline %s..HEAD", run.BaseBranch))
    s.db.UpdateCommitLog(run.ID, commits)
    
    return nil
}
```

### Sync triggers:
- **Periodic**: Every 30 seconds during active execution
- **On reconnect**: After any SSH disconnect/reconnect
- **On server startup**: For all `running`/`recovering` pipelines
- **On demand**: PM clicks "Refresh" in UI

---

## Stop / Pause (Intentional)

### PM Clicks "Pause"

```go
func (s *Server) PausePipeline(specID string) error {
    run := s.db.FindActiveRun(specID)
    
    // 1. Update server state immediately (UI reflects instantly)
    s.db.UpdateStatus(run.ID, "pausing")
    s.broadcast(specID, Event{Type: "pipeline_pausing"})
    
    // 2. Tell hal to stop gracefully
    // hal run respects context cancellation — saves state before exiting
    sandbox := s.sandboxManager.Get(run.SandboxName)
    
    // Send SIGTERM to hal process — it catches this, saves prd.json, exits cleanly
    sandbox.Exec(fmt.Sprintf("kill -TERM $(cat /tmp/hal-runner.pid) 2>/dev/null"))
    
    // 3. Wait for hal to exit (max 30 seconds)
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    for {
        if !s.isHalRunning(sandbox) {
            break
        }
        select {
        case <-ctx.Done():
            // Force kill if graceful stop timed out
            sandbox.Exec(fmt.Sprintf("kill -9 $(cat /tmp/hal-runner.pid) 2>/dev/null"))
            break
        case <-time.After(2 * time.Second):
        }
    }
    
    // 4. Sync final state from sandbox
    s.SyncStateFromSandbox(run)
    
    // 5. Mark as paused
    s.db.UpdateStatus(run.ID, "paused")
    s.broadcast(specID, Event{Type: "pipeline_paused"})
    
    return nil
}
```

### PM Clicks "Resume"

```go
func (s *Server) ResumePipeline(specID string) error {
    run := s.db.FindPausedRun(specID)
    
    // 1. Sync state from sandbox (in case PM made manual changes)
    s.SyncStateFromSandbox(run)
    
    // 2. Determine what to resume
    // hal run will automatically pick up from next pending story
    // hal auto --resume picks up from last pipeline step
    s.db.UpdateStatus(run.ID, "running")
    s.broadcast(specID, Event{Type: "pipeline_resumed"})
    
    // 3. Re-run current stage
    // hal is smart enough to skip completed stories
    go s.pipelineExecutor.ResumeFromStage(context.Background(), run, run.CurrentStage)
    
    return nil
}
```

### PM Clicks "Stop" (Abort Entirely)

```go
func (s *Server) StopPipeline(specID string) error {
    run := s.db.FindActiveRun(specID)
    
    // 1. Kill hal process
    sandbox := s.sandboxManager.Get(run.SandboxName)
    sandbox.Exec("kill -9 $(cat /tmp/hal-runner.pid) 2>/dev/null")
    
    // 2. Sync final state
    s.SyncStateFromSandbox(run)
    
    // 3. Mark as stopped — spec goes back to "approved" (can re-execute)
    s.db.UpdateStatus(run.ID, "stopped")
    s.db.UpdateSpecStatus(specID, "approved") // Ready to re-execute
    s.broadcast(specID, Event{Type: "pipeline_stopped"})
    
    // 4. Do NOT destroy sandbox — work is preserved
    // PM can inspect, resume later, or start fresh
    
    return nil
}
```

---

## State Diagram: All Pipeline Transitions

```
                    ┌─────────────────────────────────┐
                    │          PM Actions              │
                    └─────────────────────────────────┘

                         approve          execute
                 Draft ──────────▶ Approved ──────────▶ Running
                   ▲                                      │
                   │                              ┌───────┼───────┐
                   │                              ▼       ▼       ▼
                   │                          Pausing  Waiting  Error
                   │                              │       │       │
                   │                              ▼       │       │
                   │                           Paused     │       │
                   │                              │       │       │
                   │              resume          │  approve/     │
                   │           ┌──────────────────┘  reject  retry│
                   │           ▼                      │       │   │
                   │        Running ◀─────────────────┘       │   │
                   │           │                              │   │
                   │           ▼                              │   │
                   │      Recovering ─────────────────────────┘   │
                   │           │                                  │
                   │           ▼     ┌────────────────────────────┘
                   │        Running  │
                   │           │     │
                   │           ▼     ▼
                   │       Completed/Failed
                   │           │
                   │    reject │
                   └───────────┘
                   
        ┌─────────────────────────────────────────────────┐
        │          Automatic Transitions                   │
        └─────────────────────────────────────────────────┘
        
        Running → Waiting       (hit a gate stage)
        Running → Completed     (all stages done)
        Running → Error         (stage failed, retries exhausted)
        Running → Recovering    (SSH drop / sandbox unreachable)
        Recovering → Running    (reconnected, hal still running)
        Recovering → Running    (reconnected, resumed from checkpoint)
        Recovering → Failed     (sandbox gone, unrecoverable)
        Pausing → Paused        (hal process stopped gracefully)
```

---

## Idempotency Rules

Every operation the server performs must be safe to repeat. This is how we handle "we're not sure what happened" scenarios.

| Operation | Idempotency | How |
|-----------|-------------|-----|
| `hal init` | ✅ Safe | No-ops if `.hal/` exists |
| `hal convert` | ✅ Safe | Overwrites `prd.json` with same content |
| `hal run` | ✅ Safe | Skips stories with `passes: true`, runs next pending |
| `hal run -s T-003` | ✅ Safe | Re-runs T-003 even if passed (explicit) |
| `hal review` | ✅ Safe | Reviews current diff, finds current issues |
| `hal report` | ⚠️ Appends | Generates new report file (timestamped) |
| `hal auto --resume` | ✅ Safe | Reads `auto-state.json`, continues from step |
| Start wrapper script | ✅ Safe | Returns `ALREADY_RUNNING` if hal is active |
| State sync | ✅ Safe | Read-only from sandbox, updates server DB |

**The most important one:** `hal run` is inherently resumable because `prd.json` tracks `passes: true/false` per story, and each completion is a git commit. You can run `hal run` 100 times and it will never redo completed work.

---

## What the PM Sees During Failures

### Normal operation
```
┌──────────────────────────────────────────┐
│ Search Feature    ⏳ Executing            │
│ Stage: Execute    5/8 stories             │
│ Current: T-005 - Search API endpoint      │
│ ████████████░░░░░ 62%                     │
│                                           │
│ [⏸ Pause]  [⏹ Stop]                      │
└──────────────────────────────────────────┘
```

### SSH disconnect (auto-recovering)
```
┌──────────────────────────────────────────┐
│ Search Feature    🔄 Reconnecting...      │
│ Stage: Execute    5/8 stories             │
│                                           │
│ Connection lost. Sandbox is still         │
│ running. Reconnecting...                  │
│ Attempt 2/10 • Last sync: 30s ago         │
│                                           │
│ [⏹ Stop]                                  │
└──────────────────────────────────────────┘
```

### Reconnected
```
┌──────────────────────────────────────────┐
│ Search Feature    ⏳ Executing            │
│ Stage: Execute    6/8 stories             │
│ Current: T-007 - Pagination               │
│ ████████████████░ 75%                     │
│                                           │
│ ✓ Reconnected. T-006 completed while     │
│   disconnected.                           │
│                                           │
│ [⏸ Pause]  [⏹ Stop]                      │
└──────────────────────────────────────────┘
```

### Sandbox crashed (needs PM decision)
```
┌──────────────────────────────────────────┐
│ Search Feature    ❌ Sandbox Lost         │
│ Stage: Execute    5/8 stories             │
│                                           │
│ Sandbox stopped responding after 10min.   │
│ 5 stories were completed and committed.   │
│                                           │
│ Options:                                  │
│ [🔄 Restart sandbox & resume]             │
│ [⏸ Pause (keep sandbox stopped)]         │
│ [⏹ Stop (mark as failed)]                │
└──────────────────────────────────────────┘
```

### Server restarted (PM opens board)
```
┌──────────────────────────────────────────┐
│ Search Feature    🔄 Recovering           │
│ Stage: Execute                            │
│                                           │
│ Server restarted. Checking sandbox...     │
│ ✓ Sandbox is running                      │
│ ✓ hal is still executing                  │
│ ✓ Reconnected log stream                  │
│ Progress: 6/8 stories done                │
│                                           │
│ Resuming in 3s...                         │
└──────────────────────────────────────────┘
```

---

## Implementation Checklist

### Phase 1: Basic resilience (ship with MVP)
- [ ] Runner wrapper script (PID tracking, nohup, log file)
- [ ] `isHalRunning` check (PID + process probe)
- [ ] Idempotent `RunExecuteStage` (safe to call multiple times)
- [ ] State sync from sandbox (`prd.json` → server DB)
- [ ] Pause/Resume/Stop controls
- [ ] Browser disconnect handling (server keeps running)
- [ ] WebSocket reconnect on frontend (fetch state on reconnect)

### Phase 2: Auto-recovery
- [ ] Heartbeat loop (30s interval)
- [ ] SSH reconnect with log offset tracking
- [ ] Sandbox-down detection and wait-for-recovery
- [ ] Server startup recovery (scan `running` pipelines)
- [ ] Recovery UI states (reconnecting, recovering)
- [ ] Notifications on failure/recovery

### Phase 3: Advanced
- [ ] Orphan process cleanup (kill stale hal processes)
- [ ] Sandbox snapshot before risky stages
- [ ] Execution audit log (every state transition persisted)
- [ ] Retry budgets per stage (don't retry forever)
- [ ] Health dashboard (sandbox uptime, failure rate, recovery time)
