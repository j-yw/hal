# Process Isolation

Every engine uses `newSysProcAttr()` + `setupProcessCleanup(cmd)` from its own `sysproc_unix.go` / `sysproc_windows.go`.

## What It Does

```go
// sysproc_unix.go
cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

cmd.Cancel = func() error {
    return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)  // kill process group
}
cmd.WaitDelay = 5 * time.Second
```

**Setsid** — Detaches from controlling TTY. Without it, CLI tools write interactive hints (e.g., "ctrl+b to run in background") to `/dev/tty`, polluting parsed output.

**Kill(-pid)** — Kills the entire process group on timeout. Without it, child processes (curl, git, node) survive after cancellation and pile up as orphans.

**WaitDelay** — 5s grace period for cleanup after kill signal.

## Why Duplicated Per Engine

The sysproc files are currently identical across engines but intentionally duplicated:
- Each engine package stays self-contained (no cross-engine imports)
- Different CLIs may need divergent process management in the future

## Call Pattern

Every command execution must include both calls:

```go
cmd.Stdin = nil  // or strings.NewReader(prompt)
cmd.SysProcAttr = newSysProcAttr()
setupProcessCleanup(cmd)
```

Never set `SysProcAttr` directly — always go through `newSysProcAttr()`.
