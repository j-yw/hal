Let me get more details about codex CLI's exec mode and JSON output format.Now I have a clear picture. Let me also check if there's a config file and any tests to understand the patterns better.Now I have all the context I need. Let me write the PRD.PRD saved to `tasks/prd-codex-engine-support.md`. The document covers:

**8 User Stories** ordered by implementation sequence:
1. Package structure creation
2. CLI command construction
3. Output parser implementation
4. Execute method
5. Prompt method
6. StreamPrompt method
7. Unit tests
8. Integration testing

**Key technical decisions based on codebase analysis:**
- Follows the exact pattern from `internal/engine/claude/` 
- Uses `codex exec --dangerously-bypass-approvals-and-sandbox --json` for non-interactive execution
- Implements the `Engine` interface with all three methods: `Execute`, `Prompt`, `StreamPrompt`
- Registers via `engine.RegisterEngine("codex", ...)` factory pattern
- TTY detachment using `syscall.SysProcAttr{Setsid: true}` to suppress interactive hints

**Open questions** flagged for investigation during implementation:
- Exact JSONL event schema from Codex CLI needs to be captured
- Completion marker equivalent to Claude's `<promise>COMPLETE</promise>`