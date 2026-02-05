

I'll start by examining the existing codebase to understand the current structure, Makefile, .gitignore, and version setup before writing the PRD.Now let me check if there are any existing GitHub workflows or GoReleaser config.Good — no existing CI/CD or GoReleaser config. Now I have all the context needed to write the PRD.PRD saved to `.hal/prd-goreleaser-cicd.md`.

**Summary:**
- **6 user stories** ordered by dependency: GoReleaser config → Release workflow → CI workflow → .gitignore update → Makefile targets → End-to-end verification
- **15 functional requirements** covering builds, archives, checksums, changelog, GitHub releases, Homebrew formula, CI, and local tooling
- **Non-goals** explicitly exclude LICENSE, Docker, Scoop/AUR/Snap, cask migration, and linting in CI (per your answers)
- **US-006** is the end-to-end verification story — push a tag and confirm the full pipeline works
- No UI stories, so no browser verification criteria needed