# Rootless factory local-bundle verification

This slice gives explicitly selected worker-backed `rootless_podman` factory
runs a local-input path. Legacy/default SSH factory execution keeps its remote
clone/bootstrap and per-user Hal executable. No runtime protocol, credential
authority, scheduling policy, or strict microVM gate changes here.

## Input and execution contract

- The host source must be a clean Git worktree on a named branch, with repository
  identity matching the factory record. Planning uses the shared workspace
  planner and does not fetch a private repository, even when cached upstream
  metadata contains source HEAD.
- `--base` must name an existing **local branch**, contained in the source HEAD's
  history. Detached sources, missing/unrelated bases, and identical base/run
  branch names fail closed. There is no remote fetch or fallback. This is an
  explicit supported-input limitation, not evidence that remote bases exist.
- Source HEAD, comparison base, and factory output branch are distinct: the
  bundle exports the existing source branch and verifies its measured HEAD;
  the base is independently resolved to a commit; the output branch is created
  from source HEAD, not substituted for a nonexistent host ref.
- Initial checks happen after cached target selection but before runtime driver
  construction, create/start, auth, or command execution. A scheduler lease may
  already have been acquired and follows existing release behavior on failure.
- The source/base facts and cleanliness are checked again immediately before
  bundle export. Shared bundle verification checks the exported head against
  the original commit. The guest must contain that source HEAD and base object
  before the base and output branch are prepared. Existing dirty-workspace
  protection remains in the shared materializer.
- Workspace metadata records `git_bundle` and the source commit. It omits an
  output branch before successful branch/context preparation; only then is the
  factory output branch persisted. Repository URLs and host bundle paths are
  not added to durable workspace metadata.
- The shared allowlisted command-context preparation and `hal init` run after
  materialization. Existing auth/input policies remain separate. Final factory
  execution and retries select the image-provided `hal` on PATH, just as run/auto
  do, without installing or copying a host binary. Existing per-job Git identity
  is preserved for final execution and retry snapshots only.

## Default fake-only checks

The new default tests use injected planners, materializers, command-context
helpers, and drivers. They require no Git, Podman, image, network, or credentials.

```sh
go test -p 2 -count=1 ./cmd -run '^(TestFactoryRootlessBundle|TestWorkerGitIdentity|TestFactorySandboxExplicitScheduler|TestFactorySandboxFreshNamed)'
go test -p 2 -race -count=3 ./cmd -run '^(TestFactoryRootlessBundle|TestWorkerGitIdentity|TestFactorySandboxExplicitScheduler|TestFactorySandboxFreshNamed)'
```

## Tagged local-Git checks

These Linux tests require Git and execute local Git/shell commands only in
test-owned temporary directories. They inspect actual bundle refs and the
materialized source/base/run commits, including cached-upstream handling,
preflight negatives, and changed source/base/dirty-state rejection before export.
Missing Git fails this selected gate; it is not a skip or a pass.

```sh
go test -p 2 -tags=integration -count=1 ./cmd -run '^TestFactoryRootlessBundleRealGit'
go test -p 2 -tags=integration -race -count=3 ./cmd -run '^TestFactoryRootlessBundleRealGit'
go test -p 2 -count=1 ./cmd ./internal/sandboxexec ./internal/sandboxworkspace ./internal/factory
go vet ./cmd ./internal/sandboxexec ./internal/sandboxworkspace ./internal/factory
```

These tests are not factory live acceptance, an agent pipeline pass, image build
proof, private authentication proof, or strict sandbox readiness. A new image
and separately authorized live factory run are still required for end-to-end
acceptance. No guest repository/auth pre-seeding is an acceptance substitute.
