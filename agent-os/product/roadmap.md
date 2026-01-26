# Product Roadmap

## Phase 1: MVP

Core functionality to run single-engine sequential task execution:

- [ ] Core CLI with Cobra (`goralph run`, `goralph init`, `goralph config`)
- [ ] Config loading from `.goralph/config.yaml`
- [ ] Config writing and project detection for `goralph init`
- [ ] Claude engine adapter with stream-json parsing
- [ ] Sequential task execution loop
- [ ] Markdown PRD parsing (`- [ ]` checkbox format)
- [ ] Prompt building with context, rules, boundaries
- [ ] Retry logic with exponential backoff and jitter
- [ ] Auto-commit support
- [ ] Progress spinner with step detection
- [ ] Basic logging (info, warn, error, debug)

**Goal:** Run `goralph run PRD.md` with Claude and complete tasks sequentially.

## Phase 2: Feature Parity with TypeScript

Full feature parity with the existing TypeScript implementation:

- [ ] All 7 engine adapters (OpenCode, Cursor, Codex, Qwen, Droid, Copilot)
- [ ] Parallel execution with git worktrees
- [ ] Sandbox mode (lightweight alternative to worktrees)
- [ ] YAML task source with parallel groups
- [ ] GitHub issues task source
- [ ] Markdown folder task source
- [ ] Branch-per-task with automatic PR creation
- [ ] Webhook notifications (Discord, Slack, custom)
- [ ] Browser automation integration (agent-browser)
- [ ] Agent skills detection (`.opencode/skills`, `.claude/skills`, `.skills`)
- [ ] Deferred task tracking for session resumption
- [ ] Desktop notifications

## Phase 3: Enhancements

New features beyond TypeScript version:

- [ ] PRD JSON format for structured user stories
- [ ] Session persistence (resume interrupted runs)
- [ ] Cross-engine cost estimation
- [ ] Metrics collection (task completion rates, retry rates, token usage)
- [ ] Web monitoring dashboard
- [ ] Plugin architecture for custom engines
- [ ] Multi-repository orchestration
