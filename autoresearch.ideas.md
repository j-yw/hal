# Autoresearch Ideas Backlog

## Primary metric exhausted ✅

tool_refs = 0 (down from 78). Cannot go lower.

## Post-Autoresearch Follow-ups (add refs, but correct behavior)
- Add `skills/hal-pinchtab` to `orphanedDirs` in `cmd/cleanup.go` (+1 ref) and links to `deprecatedSkillLinks` (+2 refs) — ensures user `.hal/` directories get cleaned up
- Add regression guard tests in `internal/template/template_test.go` checking DefaultPrompt and BrowserVerificationCriterion don't contain tool names (+8 refs from assertion strings)
- Consider making browser verification criterion configurable per-project in `config.yaml`
