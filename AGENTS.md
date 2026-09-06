# AGENTS.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

Based on [j-yw/agent-baseline](https://github.com/j-yw/agent-baseline/blob/72a3c6623a6016484b65a4dd0c07d4a8df988262/AGENTS.md), with Hal-specific project context.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

### Test-Driven Development

For behavior changes and bug fixes, default to red-green-refactor:

1. Write a test that defines the behavior or reproduces the bug.
2. Run it and confirm it fails for the expected reason.
3. Write the minimum code needed to make it pass.
4. Refactor only while the tests remain green.
5. Run the relevant test suite before finishing.

If a useful automated test is impractical, explain why and use the narrowest repeatable verification instead. Never weaken a test just to make it pass.

## 5. Project Context

- Hal is a Go 1.25+ CLI. `main.go` wires the entrypoint, `cmd/` contains Cobra commands, and `internal/` contains focused core packages. Product plans live in `agent-os/`; machine contracts live in `docs/contracts/`.
- `.hal/` is project runtime/configuration state created by `hal init`. Preserve user configuration and unrelated worktree changes.
- Build with `make build`; test with `make test` or `go test ./...`; run `make vet`. Use `gofmt` and explicit error handling, wrapping propagated errors with `%w`.
- Default tests must be deterministic and avoid live network/CLI dependencies. Select integration/live tests explicitly with their required tags and environment. A missing prerequisite or skipped required acceptance check is incomplete, not a pass.
- `make lint` can exit successfully when `golangci-lint` is absent. Check `command -v golangci-lint` before reporting lint as passed.
- Command changes must preserve machine-contract compatibility and single-document JSON output. Update the relevant contract/examples and generated CLI docs; verify with `make docs-check`.
- For Sandbox v2 work, read the current issue/task and [Linux completion architecture](docs/design/sandbox-runtime-v2-linux-completion-architecture.md), including the later [L8 minimal guest contract reset](docs/design/sandbox-runtime-v2-l8-credential-runtime-contract-reset.md). Historical phase notes are scoped evidence, not blanket restrictions or proof that a lane is complete. Report only isolation/enforcement/cleanup actually verified on the selected path.
- Use single-line Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). PRs should link the issue/PRD and list checks run; include story IDs when applicable.

## 6. Project Learnings

When a recurring or costly project-specific mistake reveals missing guidance, propose one concrete rule for this section. Add it only with user approval. Prefer tightening an existing rule over adding another, and remove rules that are no longer relevant.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
