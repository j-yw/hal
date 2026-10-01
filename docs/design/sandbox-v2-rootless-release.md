# Sandbox v2.0 rootless release gate

## Claims and boundaries

Sandbox v2.0 ships the **rootless Podman worker lane**, labelled **container
isolation**. Acceptance covers native Linux lifecycle/exec/copy, durable worker
jobs, disconnect/crash recovery, cancellation, finalization, and Git bundle
handoffs using the existing integration tests. The gate prepares a fresh lab
image from the selected source and destroys its daemon, containers, image
storage, configuration, and temporary files on success or failure.

It does **not** claim microVM isolation, strict secure-default composition,
network/egress enforcement, or host-mediated credential isolation. Compatibility
engine auth sync deliberately puts credentials in the disposable lab/container;
that is not a credential firewall. Requested policy metadata is not evidence of
enforcement. Rootless containers share the Linux kernel. No KVM host, cloud
provider, model token, or engine credential is needed for the default gate.

The former L11 final-closure contract is not the v2.0 release contract. Native
microVM work has a separate product spec and acceptance path. macOS is
**compile-only** in this gate unless a separate Mac runtime run is arranged and
recorded; Windows is also compile-only. Cross-compilation does not establish
runtime isolation, job recovery, or cleanup on either platform.

## Release checklist

- [ ] Review the exact candidate commit, including machine contracts and CLI docs.
- [ ] Reserve exclusive use of the Podman lab. The gate owns and destroys it;
      do not point it at a lab another user needs to retain.
- [ ] Run as a non-root Linux user with rootless Podman, Go 1.25.7+, `make`,
      `git`, POSIX `sh`, `gofmt`, and `jq` on PATH. Image preparation needs
      registry/package access and enough persistent storage. Use the lab's
      existing proxy/environment settings if necessary; never disable TLS.
- [ ] Run `make sandbox-release-check` on that commit. No required native test
      may fail or skip. Missing tests, invalid JSON, command failures, image
      preparation failure, and failed destroy all block release.
- [ ] Record the sanitized evidence below. Repeat the entire gate after
      integration changes the tested head; an earlier worker run is not final
      integration evidence.
- [ ] If a token-spending engine smoke is selected, record it separately from
      default acceptance. An unselected engine smoke is not a passed check.
- [ ] Report `golangci-lint` as unavailable unless actually installed and run.

## Commands selected by the wrapper

From the repository root, with the selected Go toolchain on PATH:

```sh
make sandbox-release-check
# Equivalent:
./sandbox/release-check.sh
```

The fake-safe/regression portion runs:

```sh
go test -count=1 -json ./...
go vet ./...
make docs-check
make build
git ls-files -z '*.go' | xargs -0 gofmt -l  # must emit nothing
git diff --check
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
```

JSON is used to report default test counts; default optional-test skips do not
substitute for native acceptance. `golangci-lint run ./...` is additionally run
when available, not treated as successful when absent.

The native portion forces `HAL_SANDBOX_LAB_PODMAN_MODE=native`, runs
`sandbox/podman-lab.sh prepare` and `start`, checks Podman's live rootless flag,
and selects the lab image with
`HAL_PODMAN_TEST_IMAGE=${HAL_SANDBOX_LAB_IMAGE:-localhost/hal-agent:hal-lab}`.
These commands run through `sandbox/podman-lab.sh run --` so they use the same
isolated storage/image as the daemon, while reusing host Go build/module caches:

```sh
go test -race -count=1 -json -tags=podman_integration,l3_recovery_e2e \
  ./internal/sandboxruntime/rootlesspodman ./internal/sandboxworker ./cmd \
  -run '^(TestPodmanIntegration|TestWorkerJobPodmanIntegration|TestL3PreparedLinuxRecoveryE2E)'
go test -race -count=1 -json -tags=worker_integration,integration ./cmd \
  -run '^(TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver|TestFactoryRootlessBundleRealGit|TestFactoryFinalizationRecovery)'
```

The second selection covers the live registered worker and the retained factory
bundle/recovery tests. The wrapper derives the worker-integration environment
from the isolated lab (endpoint, worker ID, runtime, and image); operators should
not paste these values into release evidence. Both invocations must exit zero,
produce valid Go test JSON with **no `fail` or `skip` action**, and report passing
required test families. An empty selection or package-only pass is insufficient.
`destroy` runs from an exit/signal trap, including when earlier gates fail;
its failure changes the final exit status to failure. SIGKILL/power loss cannot
run a shell trap: run `make sandbox-lab-destroy` after such an interruption.

## Optional engine smoke (`--with-engine`)

This mode **spends model tokens** and explicitly seeds supported host auth into
the disposable lab. It is never selected by default. It accepts an executable
operator fixture via `HAL_SANDBOX_RELEASE_ENGINE_SMOKE`, rather than introducing
another application/engine harness. Supply a POSIX smoke script that runs inside
the lab environment, creates or clones a **disposable** Git project with a
tracked `.hal/prd.json`, a single tiny pending story, a known base branch, and
compatible engine config. Do not operate on the user's real worktree.

```sh
# Set HAL_SANDBOX_RELEASE_ENGINE_SMOKE to your reviewed fixture executable.
make sandbox-release-check ARGS=--with-engine
```

The fixture must fail on an unmet assertion and exercise the 2026-10-01 smoke:

1. `hal run --sandbox --sandbox-host "${HAL_SANDBOX_LAB_WORKER_ID:-hal-lab-worker}" --sandbox-runtime rootless_podman --sandbox-name release-engine --base main --engine codex --sandbox-sync-out --json > first.json`
   Assert JSON `ok=true`, a nonempty `sandboxExecutionId`, completed PRD, and
   collected eligible bundle artifacts. The host worktree must remain unchanged.
2. Rerun that command on the same named sandbox, writing `rerun.json`. Assert
   success and a distinct execution ID, without a container-name collision.
3. `hal sandbox apply "$(jq -er '.sandboxExecutionId' first.json)"`
   Assert the committed story change exists in the disposable host project and
   its PRD marks the story complete. Worker `--sandbox-apply` is a handoff, not
   implicit host apply; this explicit command is the apply surface.
4. Make a pending story again, replace only the **disposable container's** Codex
   executable with a shell program that exits 42 (using `hal sandbox ssh
   release-engine -- ...`), and run again. Require a nonzero command exit and
   failure JSON, not a config-validation failure before job submission. Inspect
   the manifest under the isolated `HAL_CONFIG_HOME/sandbox-executions`: it must
   have `status=failed`, `finalization.state=completed`, and no inherited lease.
   Verify the reused sandbox is not left reporting a running execution.

A fixture may instead use Claude or Pi if it supplies the corresponding actual
failing-engine executable and compatible auth/config. Do not claim every engine
passed based on one engine. The wrapper reports only the operator fixture's exit
result; review its assertions and record engine/version and observed results.
It does not discover arbitrary project tasks or silently select a paid model.

## Evidence to record

Record the exact source commit and integration commit, commands and exit codes,
default test pass/fail/skip counts, native test/subtest pass/fail/skip counts,
selected tag/selector strings, race status, platform compile outcomes, CLI doc
and formatting checks, image ID printed by the gate, and successful destroy.
Record optional engine smoke selection/result and unavailable tools explicitly.
Do not include credentials, tokens, endpoints, socket addresses, hostnames,
host-identifying paths, raw lab manifests, or full engine output in public notes.
The wrapper keeps raw command output in private temporary files and removes it
on exit; its console output is a summary, not a retained evidence archive.
On failure, reproduce the named check in the contained lab and inspect output
privately, then always destroy the lab. Never turn a missing prerequisite,
a skip, or a cleanup failure into a release pass.
