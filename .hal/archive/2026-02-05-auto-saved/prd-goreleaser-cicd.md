# PRD: GoReleaser CI/CD and Homebrew Release Pipeline

## Introduction

Set up automated cross-platform releases for `hal` using GoReleaser v2, GitHub Actions, and a Homebrew tap. The project currently has no CI/CD, no release automation, and no GoReleaser config. This PRD covers creating the GoReleaser configuration, GitHub Actions workflows (CI + release), and updating the Makefile and .gitignore to support the new release tooling. Releases publish to **j-yw/goralph** starting at **v0.1.0**.

## Goals

- Automate cross-platform binary builds for 5 targets (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
- Publish GitHub Releases with grouped changelogs, checksums, and archive files on every version tag push
- Auto-publish a Homebrew formula to `j-yw/homebrew-tap` on each release
- Run tests and vet checks in CI on every push to `main`/`develop` and on PRs to `main`
- Validate GoReleaser config in CI to catch config errors before release time
- Provide local dry-run and config-check Makefile targets for developer convenience

## User Stories

### US-001: Create GoReleaser Configuration
**Description:** As a developer, I want a `.goreleaser.yaml` config file so that GoReleaser can build cross-platform binaries, generate changelogs, create GitHub releases, and push a Homebrew formula.

**Acceptance Criteria:**
- [ ] `.goreleaser.yaml` exists at the repo root
- [ ] `version: 2` is set (GoReleaser v2 format)
- [ ] `project_name` is `hal`
- [ ] `before.hooks` runs `go mod tidy` and `go vet ./...`
- [ ] Build config: `CGO_ENABLED=0`, targets linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 (windows/arm64 excluded)
- [ ] Ldflags set `-s -w` and inject `Version`, `Commit`, `BuildDate` into `github.com/jywlabs/hal/cmd`
- [ ] Archives use `tar.gz` by default, `zip` for Windows
- [ ] Archive name template: `{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}`
- [ ] Checksum file generated as `checksums.txt` using sha256
- [ ] Changelog sorted ascending, uses GitHub, excludes `docs:`, `test:`, `chore:`, `ci:` commits, groups by Features/Bug Fixes/Refactoring/Others
- [ ] Release targets `j-yw/goralph`, draft is false, prerelease is auto, name template is `Hal v{{ .Version }}`
- [ ] Brews section configured: formula name `hal`, pushes to `j-yw/homebrew-tap` using `HOMEBREW_TAP_TOKEN` env, directory `Formula`, includes install and test blocks
- [ ] `goreleaser check` passes locally (run `goreleaser check`)
- [ ] Typecheck passes (`go vet ./...`)

### US-002: Create Release GitHub Actions Workflow
**Description:** As a developer, I want a GitHub Actions workflow that triggers on version tag pushes so that releases are fully automated.

**Acceptance Criteria:**
- [ ] `.github/workflows/release.yml` exists
- [ ] Triggers on push of tags matching `v*`
- [ ] Sets `permissions: contents: write`
- [ ] Uses `actions/checkout@v4` with `fetch-depth: 0` (full history for changelog)
- [ ] Uses `actions/setup-go@v5` with `go-version-file: go.mod`
- [ ] Runs `go test -v ./...` before releasing (tests gate the release)
- [ ] Uses `goreleaser/goreleaser-action@v6` with `version: "~> v2"` and `args: release --clean`
- [ ] Passes `GITHUB_TOKEN` and `HOMEBREW_TAP_TOKEN` as env vars to GoReleaser step
- [ ] Typecheck passes (`go vet ./...`)

### US-003: Create CI GitHub Actions Workflow
**Description:** As a developer, I want a CI workflow that runs tests and validates GoReleaser config on pushes and PRs so that I catch issues before merging.

**Acceptance Criteria:**
- [ ] `.github/workflows/ci.yml` exists
- [ ] Triggers on push to `main` and `develop` branches, and on PRs to `main`
- [ ] Contains a `test` job that: checks out code, sets up Go from `go.mod`, runs `go vet ./...`, runs `go test -v ./...`
- [ ] Contains a `goreleaser-check` job that: checks out code with `fetch-depth: 0`, sets up Go from `go.mod`, runs `goreleaser check` via `goreleaser/goreleaser-action@v6`
- [ ] Both jobs run on `ubuntu-latest`
- [ ] Both jobs run in parallel (no dependency between them)
- [ ] Typecheck passes (`go vet ./...`)

### US-004: Update .gitignore for GoReleaser
**Description:** As a developer, I want `dist/` ignored by git so that local GoReleaser dry-run output is not accidentally committed.

**Acceptance Criteria:**
- [ ] `.gitignore` contains `dist/` entry
- [ ] Entry is in the binaries/build-artifacts section of the file
- [ ] Existing entries are unchanged
- [ ] Typecheck passes (`go vet ./...`)

### US-005: Add Release Makefile Targets
**Description:** As a developer, I want `make release-dry-run` and `make release-check` targets so that I can test releases locally before pushing tags.

**Acceptance Criteria:**
- [ ] `release-dry-run` target runs `goreleaser release --snapshot --clean`
- [ ] `release-check` target runs `goreleaser check`
- [ ] Both targets are listed in the `.PHONY` line
- [ ] Both targets are documented in the `help` target output
- [ ] Existing Makefile targets and behavior are unchanged
- [ ] `make release-check` passes locally
- [ ] Typecheck passes (`go vet ./...`)

### US-006: Verify End-to-End Release Pipeline
**Description:** As a developer, I want to verify the full pipeline works by running a local dry-run and checking all expected artifacts are produced.

**Acceptance Criteria:**
- [ ] `make release-check` exits 0 (config is valid)
- [ ] `make release-dry-run` exits 0 (snapshot build succeeds)
- [ ] `dist/` directory contains 5 archive files: `hal_*_linux_amd64.tar.gz`, `hal_*_linux_arm64.tar.gz`, `hal_*_darwin_amd64.tar.gz`, `hal_*_darwin_arm64.tar.gz`, `hal_*_windows_amd64.zip`
- [ ] `dist/` contains `checksums.txt` with sha256 hashes for all 5 archives
- [ ] Each archive contains a `hal` binary (or `hal.exe` for Windows)
- [ ] `make test` and `make vet` still pass (no regressions)
- [ ] Typecheck passes (`go vet ./...`)

## Functional Requirements

- FR-1: `.goreleaser.yaml` must be a valid GoReleaser v2 config that passes `goreleaser check`
- FR-2: GoReleaser must build 5 binary targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64
- FR-3: All binaries must be compiled with `CGO_ENABLED=0` and ldflags injecting Version, Commit, and BuildDate into `github.com/jywlabs/hal/cmd`
- FR-4: Ldflags must include `-s -w` to strip debug info from release binaries
- FR-5: Archives must use `tar.gz` for Linux/macOS and `zip` for Windows
- FR-6: A `checksums.txt` file with sha256 hashes must be generated for all archives
- FR-7: The changelog must be generated from git history, grouped by conventional commit type, excluding docs/test/chore/ci commits
- FR-8: GitHub Releases must be created on `j-yw/goralph` with the name `Hal v<version>`
- FR-9: Tags matching pre-release patterns (e.g., `v0.2.0-beta.1`) must be auto-marked as prerelease
- FR-10: A Homebrew formula must be pushed to `j-yw/homebrew-tap` in the `Formula/` directory on each non-prerelease
- FR-11: The release workflow must run `go test -v ./...` before invoking GoReleaser — test failures abort the release
- FR-12: The CI workflow must run `go vet` and `go test` on pushes to `main`/`develop` and PRs to `main`
- FR-13: The CI workflow must validate GoReleaser config via `goreleaser check`
- FR-14: `dist/` must be in `.gitignore` to prevent committing local dry-run artifacts
- FR-15: Makefile must expose `release-dry-run` (snapshot build) and `release-check` (config validation) targets

## Non-Goals (Out of Scope)

- Adding a LICENSE file (handled separately)
- Docker image builds
- Scoop (Windows), AUR (Arch Linux), Snap, or Flatpak packaging
- Migrating `brews` to `homebrew_casks` (requires macOS code signing)
- Creating the `j-yw/homebrew-tap` repo (manual prerequisite)
- Creating the `HOMEBREW_TAP_TOKEN` GitHub secret (manual prerequisite)
- Linting in CI (golangci-lint) — keep minimal with just vet + test + goreleaser check
- Integration tests in CI
- Branch protection rules or required status checks configuration

## Technical Considerations

- **Go module path vs GitHub repo:** Module is `github.com/jywlabs/hal`, repo is `j-yw/goralph`. Ldflags must use the module path for the `-X` flags.
- **`//go:embed` directives:** Present in `internal/skills/embed.go` and `internal/template/template.go`. GoReleaser builds from source, so embedded files are included automatically — no special config needed.
- **Pure Go / no CGO:** Confirmed no C dependencies. `CGO_ENABLED=0` is safe and produces fully static binaries.
- **Existing ldflags in Makefile:** The Makefile already sets `Version`, `Commit`, `BuildDate` via ldflags targeting `github.com/jywlabs/hal/cmd`. GoReleaser config must use the same package path.
- **GoReleaser v2 `brews` deprecation:** `brews` was deprecated in v2.10 in favor of `homebrew_casks`, but casks require code signing. `brews` still works in v2 and there is no v3 release date. Safe to use.
- **`HOMEBREW_TAP_TOKEN`:** Required as a GitHub PAT with `repo` scope, stored as a repository secret. GoReleaser reads it from the environment.
- **`GITHUB_TOKEN`:** Automatically provided by GitHub Actions — no setup needed.

## Success Metrics

- `make release-check` passes on first try after setup
- `make release-dry-run` produces 5 archives + checksums in `dist/`
- CI workflow runs green on push to `develop` and on PRs to `main`
- First tag push (`v0.1.0`) triggers a successful release with all artifacts on GitHub
- `brew tap j-yw/tap && brew install hal && hal version` works after first release

## Open Questions

- Should the CI workflow also run on the `develop` branch for PRs (currently only triggers on PRs to `main`)?
- Should there be a notification (Slack, email) on release success/failure?
