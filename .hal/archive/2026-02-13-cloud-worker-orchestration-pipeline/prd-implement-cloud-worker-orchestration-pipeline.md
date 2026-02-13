# PRD: Cloud Worker Orchestration Pipeline (Gap-Free Alignment)

## 1) Introduction / Overview

Cloud runs can be submitted and observed today, but the repository still needs a deterministic worker execution pipeline that processes queued runs end-to-end.

Deliver a deterministic cloud worker execution pipeline for run, auto, and review workflows with atomic claim semantics, workflow-aware snapshots, optional GitHub PR creation, worker CLI wiring, and stable cloud command contracts.

This PRD is synchronized with `.hal/prd.json` and is intended to remain the human-readable companion to the structured execution plan.

## 2) Goals

1. Deliver a production-usable worker pipeline from claim through terminalization.
2. Keep claim/attempt semantics deterministic across store adapters and claim service logic.
3. Persist workflow-aware final snapshots with deterministic `ComputeBundleHash(records)` semantics.
4. Support optional, safe GitHub PR creation for eligible workflows only.
5. Add `hal cloud worker` command wiring with injectable factories and sane runtime defaults.
6. Preserve existing cloud command/help, JSON contract, and redaction guarantees.
7. Ensure failure-path correctness for cancel, lease loss, profile revocation, and shutdown cleanup.

## 3) User Stories

### US-001: Atomically increment attempt_count in Postgres ClaimRun
**Description:** As a platform maintainer, I want Postgres ClaimRun to claim and increment attempt_count atomically so attempt numbering stays deterministic.
**Priority:** 1

**Acceptance Criteria:**
- [ ] internal/cloud/postgres/store.go ClaimRun updates eligible rows in one claim operation that sets status='claimed' and attempt_count=attempt_count+1.
- [ ] Claim eligibility still requires status='queued' and cancel_requested=false.
- [ ] A successful claim returns Run.AttemptCount with the incremented value.
- [ ] internal/cloud/postgres/store_test.go verifies one increment per successful claim and no increment for ineligible claims.
- [ ] Tests pass
- [ ] Typecheck passes

### US-002: Atomically increment attempt_count in Turso ClaimRun
**Description:** As a platform maintainer, I want Turso ClaimRun to claim and increment attempt_count atomically so semantics match Postgres.
**Priority:** 2

**Acceptance Criteria:**
- [ ] internal/cloud/turso/store.go ClaimRun updates eligible rows in one claim operation that sets status='claimed' and attempt_count=attempt_count+1.
- [ ] Claim eligibility still requires status='queued' and cancel_requested=false.
- [ ] A successful claim returns Run.AttemptCount with the incremented value.
- [ ] internal/cloud/turso/store_test.go verifies one increment per successful claim and no increment for ineligible claims.
- [ ] Tests pass
- [ ] Typecheck passes

### US-003: Align ClaimService attempt numbering with claimed run state
**Description:** As a platform maintainer, I want ClaimService to derive Attempt.AttemptNumber from claimed Run.AttemptCount so adapters and service logic stay consistent.
**Priority:** 3

**Acceptance Criteria:**
- [ ] ClaimService sets Attempt.AttemptNumber equal to claimed Run.AttemptCount without adding an extra increment.
- [ ] internal/cloud/claim_test.go verifies first claim attempt number is 1 and second claim after requeue is 2.
- [ ] internal/cloud/claim_test.go verifies Attempt.AttemptNumber equals Run.AttemptCount for claimed runs.
- [ ] Tests pass
- [ ] Typecheck passes

### US-004: Add shared shell escaping helper
**Description:** As a maintainer, I want one shared shell escaping helper so cloud services build shell commands safely and consistently.
**Priority:** 4

**Acceptance Criteria:**
- [ ] Add internal/cloud/shell.go with a shared single-quote escaping helper.
- [ ] The helper wraps values in single quotes and escapes embedded single quotes correctly.
- [ ] Unit tests cover plain text, whitespace, embedded single quotes, and newline input.
- [ ] Tests pass
- [ ] Typecheck passes

### US-005: Use shared shell helper in auth materialization
**Description:** As a maintainer, I want auth materialization command building to reuse the shared shell helper so escaping logic is centralized.
**Priority:** 5

**Acceptance Criteria:**
- [ ] internal/cloud/auth_materialization.go uses the shared shell helper for command construction.
- [ ] Duplicate ad-hoc escaping logic is removed from auth_materialization.go.
- [ ] internal/cloud/auth_materialization_test.go verifies generated command strings match helper escaping behavior.
- [ ] Tests pass
- [ ] Typecheck passes

### US-006: Collect sandbox bundle files with workflow artifact patterns
**Description:** As a cloud user, I want final artifact collection to filter by workflow artifact patterns so restored outputs match workflow expectations.
**Priority:** 6

**Acceptance Criteria:**
- [ ] Add internal/cloud/snapshot_collect.go with CollectSandboxBundle(...).
- [ ] Collection scans files under /workspace/.hal and stores workspace-relative paths.
- [ ] Filtering uses WorkflowDefaultArtifactPatterns(workflowKind) with MatchesArtifactPatterns and does not use input allowlist policy.
- [ ] Tests verify expected files for run and auto/review workflows.
- [ ] Tests pass
- [ ] Typecheck passes

### US-007: Capture sandbox file contents with robust base64 handling
**Description:** As a cloud user, I want file content capture to avoid wrapped base64 corruption so binary and multiline content is restored correctly.
**Priority:** 7

**Acceptance Criteria:**
- [ ] CollectSandboxBundle uses a base64 command path that produces non-wrapped output suitable for decode.
- [ ] Decode failures include the file path and stderr in returned errors.
- [ ] Tests cover multiline text and binary-safe content capture.
- [ ] Tests pass
- [ ] Typecheck passes

### US-008: Compress bundles with compatible framing
**Description:** As a platform engineer, I want bundle compression framing to stay compatible with existing pull decompression behavior.
**Priority:** 8

**Acceptance Criteria:**
- [ ] snapshot_collect.go provides CompressBundle(...) using path\u0000size\u0000content framing plus gzip.
- [ ] Compressed output is compatible with existing cmd/cloud.go decompression logic.
- [ ] Round-trip tests verify decompressed records match original records.
- [ ] Tests pass
- [ ] Typecheck passes

### US-009: Persist snapshot SHA using ComputeBundleHash(records)
**Description:** As a platform engineer, I want snapshot SHA semantics to match submit path hashing so bundle identity is deterministic.
**Priority:** 9

**Acceptance Criteria:**
- [ ] Worker snapshot persistence computes SHA with ComputeBundleHash(records).
- [ ] Compressed payload byte hash is not used for the snapshot SHA field.
- [ ] Tests verify deterministic SHA behavior for equivalent record sets.
- [ ] Tests pass
- [ ] Typecheck passes

### US-010: Implement GitHubPRCreator core behavior
**Description:** As an operator, I want worker-side PR creation to execute gh in the sandbox workspace and return parsed PR metadata.
**Priority:** 10

**Acceptance Criteria:**
- [ ] Add internal/cloud/pr_github.go with GitHubPRCreator(r runner.Runner, sandboxID, authDir string) PRCreator.
- [ ] PR creation executes gh pr create from /workspace.
- [ ] Successful command output is parsed into PR URL and reference fields.
- [ ] Tests pass
- [ ] Typecheck passes

### US-011: Apply token sourcing and escaping in GitHubPRCreator
**Description:** As an operator, I want PR creation to source credentials from materialized auth and escape all user-controlled arguments.
**Priority:** 11

**Acceptance Criteria:**
- [ ] GitHubPRCreator exports GITHUB_TOKEN from ${authDir}/credentials in the in-sandbox command.
- [ ] title, body, head, base, and repo arguments are escaped with the shared shell helper.
- [ ] Tests verify command text for token sourcing and quote-heavy arguments.
- [ ] Tests pass
- [ ] Typecheck passes

### US-012: Surface GitHubPRCreator execution failures with concrete error data
**Description:** As an operator, I want PR creation failures to include exit and stderr details so operational debugging is fast.
**Priority:** 12

**Acceptance Criteria:**
- [ ] Non-zero gh exit returns an error that includes exit code and stderr output.
- [ ] Runner execution errors are wrapped with %w and include operation context.
- [ ] Tests assert both error branches and expected error text fragments.
- [ ] Tests pass
- [ ] Typecheck passes

### US-013: Add WorkerPipeline foundation and no-work sentinel behavior
**Description:** As a maintainer, I want a WorkerPipeline core type so orchestration logic is testable outside Cobra.
**Priority:** 13

**Acceptance Criteria:**
- [ ] Add internal/cloud/worker.go defining WorkerPipelineConfig, WorkerPipeline, NewWorkerPipeline, and ErrNoWork with message 'no eligible runs in queue'.
- [ ] NewWorkerPipeline validates required dependencies and returns errors for missing dependencies.
- [ ] ProcessOne maps claim ErrNotFound to ErrNoWork.
- [ ] Tests cover constructor validation and no-work mapping.
- [ ] Tests pass
- [ ] Typecheck passes

### US-014: Enforce deterministic executeAttempt setup ordering
**Description:** As a maintainer, I want setup order to be deterministic so run lifecycle behavior is predictable.
**Priority:** 14

**Acceptance Criteria:**
- [ ] executeAttempt transitions run from claimed to running before provisioning starts.
- [ ] Setup call order is provision -> bootstrap -> auth materialization -> preflight.
- [ ] Call-order tests assert the exact sequence.
- [ ] Tests pass
- [ ] Typecheck passes

### US-015: Use status-aware failure transitions during setup failures
**Description:** As a maintainer, I want setup failure handling to transition from the correct source status so transition contracts remain valid.
**Priority:** 15

**Acceptance Criteria:**
- [ ] Setup failure helper accepts fromRunStatus as input.
- [ ] TransitionRun in setup-failure paths uses the provided fromRunStatus value instead of hardcoded running.
- [ ] Tests cover failures occurring before run reaches running.
- [ ] Tests pass
- [ ] Typecheck passes

### US-016: Propagate working branch and git credential fields
**Description:** As a maintainer, I want working branch and git credential context passed to setup and checkpoint services so writes target the expected branch.
**Priority:** 16

**Acceptance Criteria:**
- [ ] Worker computes workingBranch := WorkingBranch(runID) for each attempt.
- [ ] Bootstrap and checkpoint inputs receive workingBranch and expected git credential fields.
- [ ] Tests assert propagated branch and credential values.
- [ ] Tests pass
- [ ] Typecheck passes

### US-017: Run heartbeat across setup and execution windows
**Description:** As a worker operator, I want lease renewals active through setup and execution so long setup does not silently lose leases.
**Priority:** 17

**Acceptance Criteria:**
- [ ] Heartbeat loop starts after run transitions to running.
- [ ] Heartbeat loop remains active through setup and execution until terminal routing begins.
- [ ] Tests simulate long setup and verify heartbeat renew calls occur.
- [ ] Tests pass
- [ ] Typecheck passes

### US-018: Check cancellation before heartbeat renew on every tick
**Description:** As a worker operator, I want cancellation checks to run before lease renewal so canceled attempts stop promptly.
**Priority:** 18

**Acceptance Criteria:**
- [ ] Each heartbeat tick calls cancel.CheckAndCancel before heartbeat.Renew.
- [ ] When cancellation is detected, the tick does not call heartbeat.Renew.
- [ ] Tests verify per-tick call order and cancel short-circuit behavior.
- [ ] Tests pass
- [ ] Typecheck passes

### US-019: Handle lease_lost routing without duplicate attempt terminalization
**Description:** As a maintainer, I want lease_lost routing to respect heartbeat side effects so attempt transitions are emitted exactly once.
**Priority:** 19

**Acceptance Criteria:**
- [ ] Lease expiration sets cancel reason to lease_lost and routes through lease-lost handling.
- [ ] Worker does not emit a second TransitionAttempt failure when heartbeat already terminalized the attempt.
- [ ] Cleanup and retry evaluation still run in lease-lost handling.
- [ ] Tests pass
- [ ] Typecheck passes

### US-020: Handle profile_revoked routing without duplicate attempt terminalization
**Description:** As a maintainer, I want profile_revoked routing to finalize run state correctly while avoiding duplicate attempt transitions.
**Priority:** 20

**Acceptance Criteria:**
- [ ] Profile revocation sets cancel reason to profile_revoked and routes through profile-revoked handling.
- [ ] Worker avoids duplicate attempt terminal transitions when heartbeat already marked attempt failed.
- [ ] Run transitions to failed for the profile_revoked path.
- [ ] Tests pass
- [ ] Typecheck passes

### US-021: Use shutdown-safe background timeout contexts for cleanup
**Description:** As a platform engineer, I want terminal cleanup to continue under cancellation so lock and sandbox cleanup can finish during shutdown.
**Priority:** 21

**Acceptance Criteria:**
- [ ] When parent context is canceled, cleanup paths use context.WithTimeout(context.Background(), ...).
- [ ] Cleanup timeout behavior is covered by deterministic tests.
- [ ] Cleanup still attempts lock and sandbox release under canceled parent context.
- [ ] Tests pass
- [ ] Typecheck passes

### US-022: Map execution exit codes to deterministic terminal transitions
**Description:** As a platform engineer, I want execution result mapping to emit one deterministic run/attempt transition set per exit outcome.
**Priority:** 22

**Acceptance Criteria:**
- [ ] Exit code 0 emits exactly one attempt succeeded transition and exactly one run succeeded transition.
- [ ] Non-zero exit emits exactly one attempt failed transition with reason non_retryable and exactly one run failed transition.
- [ ] Tests assert transition counts, statuses, and failure reason values.
- [ ] Tests pass
- [ ] Typecheck passes

### US-023: Treat auth lock ErrNotFound as non-fatal during cleanup
**Description:** As a maintainer, I want cleanup to tolerate already-released auth locks so cancellation and revocation paths remain idempotent.
**Priority:** 23

**Acceptance Criteria:**
- [ ] Auth lock release treats ErrNotFound as non-fatal in terminal cleanup paths.
- [ ] Non-ErrNotFound lock release errors are returned with wrapped context.
- [ ] Tests cover both ErrNotFound and other error branches.
- [ ] Tests pass
- [ ] Typecheck passes

### US-024: Persist final snapshot payloads with deterministic metadata
**Description:** As a platform engineer, I want finalization to persist snapshot records, compressed bundle bytes, and deterministic hash metadata.
**Priority:** 24

**Acceptance Criteria:**
- [ ] Finalization stores collected records and compressed payload bytes in snapshot storage.
- [ ] Persisted snapshot SHA value equals ComputeBundleHash(records).
- [ ] Tests verify stored metadata fields and payload presence.
- [ ] Tests pass
- [ ] Typecheck passes

### US-025: Gate PR side effects by workflow kind and PREnabled
**Description:** As an operator, I want PR creation to run only for applicable workflows so run workflow terminalization has no PR side effects.
**Priority:** 25

**Acceptance Criteria:**
- [ ] PRCreate is called only when workflowKind is auto or review and PREnabled is true.
- [ ] workflowKind run never invokes PRCreate.
- [ ] Tests cover auto/review enabled and disabled branches.
- [ ] Tests pass
- [ ] Typecheck passes

### US-026: Register hal cloud worker command and flags
**Description:** As an operator, I want a dedicated cloud worker command with explicit runtime flags.
**Priority:** 26

**Acceptance Criteria:**
- [ ] Add cmd/cloud_worker.go and register worker under the cloud command tree.
- [ ] Worker command defines --worker-id, --poll-interval, --reconcile-interval, --timeout-interval, and --sandbox-image flags.
- [ ] Help output includes worker command and all new flags.
- [ ] Tests pass
- [ ] Typecheck passes

### US-027: Wire worker command factories and dotenv bootstrap
**Description:** As a maintainer, I want worker command bootstrap wiring to be injectable in tests and consistent with cloud dotenv loading behavior.
**Priority:** 27

**Acceptance Criteria:**
- [ ] Package-level store and runner factory vars are assigned via if-nil defaults and remain overrideable in tests.
- [ ] Worker startup calls godotenv.Load() before deploy config resolution.
- [ ] os.ErrNotExist from dotenv load is ignored and other dotenv errors produce non-fatal warnings.
- [ ] Tests pass
- [ ] Typecheck passes

### US-028: Provide default runner factory and non-empty sandbox image wiring
**Description:** As an operator, I want default runtime wiring to construct a valid runner and always pass a sandbox image to provision.
**Priority:** 28

**Acceptance Criteria:**
- [ ] Default runner factory validates deploy config and constructs a Daytona-backed implementation satisfying Runner, SessionExec, and GitOps interfaces.
- [ ] Worker wiring passes ProvisionConfig.Image from --sandbox-image or a non-empty default.
- [ ] Tests assert provision service is never called with an empty image.
- [ ] Tests pass
- [ ] Typecheck passes

### US-029: Implement worker loop scheduling and graceful shutdown
**Description:** As an operator, I want worker loop scheduling for poll and maintenance intervals with clean shutdown behavior.
**Priority:** 29

**Acceptance Criteria:**
- [ ] Worker loop schedules ProcessOne, reconciler, and timeout services using ticker intervals.
- [ ] Loop exits cleanly when context is canceled.
- [ ] Code comments or tests document accepted v1 behavior that long ProcessOne work can delay maintenance ticks.
- [ ] Tests pass
- [ ] Typecheck passes

### US-030: Add snapshot collection test suite
**Description:** As a maintainer, I want dedicated snapshot collection tests so artifact filtering and compression regressions are caught quickly.
**Priority:** 30

**Acceptance Criteria:**
- [ ] Add internal/cloud/snapshot_collect_test.go.
- [ ] Tests cover happy path, empty workspace, pattern filtering, command failure, and compress/decompress round-trip.
- [ ] Tests are deterministic and do not require network access.
- [ ] Tests pass
- [ ] Typecheck passes

### US-031: Add GitHub PR creator test suite
**Description:** As a maintainer, I want dedicated PR creator tests so command construction and error handling remain stable.
**Priority:** 31

**Acceptance Criteria:**
- [ ] Add internal/cloud/pr_github_test.go.
- [ ] Tests cover success, non-zero exit, runner error, token sourcing, and shell escaping behavior.
- [ ] Tests run with fake runner dependencies only.
- [ ] Tests pass
- [ ] Typecheck passes

### US-032: Add worker orchestration test suite
**Description:** As a maintainer, I want worker orchestration tests for key success and failure routes so terminalization behavior stays deterministic.
**Priority:** 32

**Acceptance Criteria:**
- [ ] Add internal/cloud/worker_test.go.
- [ ] Tests cover happy path, no work, setup failure, non-zero execution, cancel, lease_lost, profile_revoked, and PR skip-for-run behavior.
- [ ] Tests assert no duplicate attempt terminal transitions in heartbeat-driven paths.
- [ ] Tests pass
- [ ] Typecheck passes

### US-033: Add cloud worker command test suite
**Description:** As a maintainer, I want command-level tests for cloud worker so flag wiring and startup/shutdown behavior are stable.
**Priority:** 33

**Acceptance Criteria:**
- [ ] Add cmd/cloud_worker_test.go.
- [ ] Tests cover flag parsing/default values and startup/shutdown behavior with injected dependencies.
- [ ] Tests verify Cobra handler delegates to testable helper functions.
- [ ] Tests pass
- [ ] Typecheck passes

### US-034: Add claim adapter regression tests for attempt_count
**Description:** As a maintainer, I want explicit claim adapter regressions so atomic attempt_count behavior does not regress.
**Priority:** 34

**Acceptance Criteria:**
- [ ] Update internal/cloud/postgres/store_test.go and internal/cloud/turso/store_test.go for attempt_count increment assertions.
- [ ] Tests verify one increment per successful claim and no increment for ineligible claims.
- [ ] Tests pass
- [ ] Typecheck passes

### US-035: Add claim service regression tests for attempt numbering
**Description:** As a maintainer, I want claim service regression tests so Attempt.AttemptNumber remains aligned with claimed run state.
**Priority:** 35

**Acceptance Criteria:**
- [ ] Update internal/cloud/claim_test.go with attempt-number alignment assertions.
- [ ] Tests verify first claim returns attempt 1 and second claim after requeue returns attempt 2.
- [ ] Tests verify Attempt.AttemptNumber equals Run.AttemptCount.
- [ ] Tests pass
- [ ] Typecheck passes

### US-036: Update cloud help and command tree contract tests
**Description:** As an automation consumer, I want command tree changes limited to the intentional worker addition.
**Priority:** 36

**Acceptance Criteria:**
- [ ] Update cmd/cloud_help_test.go and cmd/cloud_removed_test.go for the worker subcommand addition.
- [ ] Tests assert no unrelated command or alias changes beyond worker wiring.
- [ ] Tests pass
- [ ] Typecheck passes

### US-037: Preserve lifecycle JSON output contract tests
**Description:** As an automation consumer, I want existing lifecycle JSON contracts to remain stable while worker support is added.
**Priority:** 37

**Acceptance Criteria:**
- [ ] Lifecycle integration tests continue to assert required camelCase JSON keys for cloud command outputs.
- [ ] No new snake_case aliases are introduced in commands already migrated to camelCase.
- [ ] Tests pass
- [ ] Typecheck passes

### US-038: Preserve redaction behavior in human and JSON outputs
**Description:** As an automation consumer, I want redaction guarantees preserved so secrets never leak in cloud command output paths.
**Priority:** 38

**Acceptance Criteria:**
- [ ] Secret-bearing values are redacted in human-readable cloud command outputs after worker changes.
- [ ] The same secret-bearing values are redacted in --json cloud command outputs.
- [ ] Tests pass
- [ ] Typecheck passes

## 4) Functional Requirements

- **FR-1:** Claim operations must atomically transition run status and increment `attempt_count` in Postgres and Turso adapters.
- **FR-2:** Claim service attempt numbering must be consistent with claimed run attempt counts.
- **FR-3:** Cloud shell command construction must use a shared escaping helper.
- **FR-4:** Snapshot collection must use workflow artifact-pattern filtering, not input-allowlist policy.
- **FR-5:** Snapshot compression must remain compatible with existing pull decompression framing.
- **FR-6:** Snapshot SHA must use `ComputeBundleHash(records)`.
- **FR-7:** Worker PR creation must source `GITHUB_TOKEN` from materialized credentials and safely escape all user-controlled arguments.
- **FR-8:** Worker orchestration must run in testable `internal/cloud` helpers with deterministic setup ordering and status-aware failure transitions.
- **FR-9:** Heartbeat/cancel handling must be active across setup and execution and avoid duplicate attempt terminal transitions for lease/revocation paths.
- **FR-10:** Terminal cleanup must use timeout-bounded background contexts when parent context is canceled.
- **FR-11:** Worker command wiring must include dotenv loading behavior, injectable factories, non-empty sandbox image provisioning, and graceful loop shutdown.
- **FR-12:** Existing cloud command surface, JSON contracts, and redaction behavior must remain stable except for intentional worker command addition.

## 5) Non-Goals

- Creating a separate dedicated reconciler daemon/process in this iteration.
- Redesigning existing core cloud service interfaces.
- Expanding artifact taxonomy beyond current workflow artifact groups.
- Changing JSON schemas for existing cloud commands outside the explicit worker addition.
- Building a web UI for worker operations.

## 6) Design Considerations

- Keep Cobra handlers thin and delegate side effects to testable helpers.
- Reuse existing cloud services and sentinels (`ErrNotFound`, `ErrLeaseExpired`, `ErrProfileRevoked`) rather than introducing parallel semantics.
- Preserve deterministic hash/path behavior for snapshot compatibility.
- Treat heartbeat side effects as authoritative and avoid duplicate attempt terminalization in worker routing.

## 7) Technical Considerations

- Maintain compatibility with existing bundle framing and pull decompression behavior.
- Ensure adapter parity across Postgres and Turso claim paths.
- Keep `ProvisionConfig.Image` always non-empty in worker provisioning paths.
- Prefer dependency injection for command and orchestration testability.
- Keep redaction-aware output chokepoints unchanged for existing commands.

## 8) Success Metrics

1. Worker processes queued runs end-to-end to deterministic terminal states.
2. Snapshot persistence is workflow-correct and uses deterministic `ComputeBundleHash(records)` metadata.
3. Required failure scenarios pass in tests (setup failure, cancel, lease_lost, profile_revoked, shutdown cancellation).
4. Claim adapter/service tests prove stable attempt-count and attempt-number semantics.
5. Existing cloud help/JSON/redaction contract tests remain green with only intentional worker command surface changes.

## 9) Open Questions

1. If PR creation fails for an otherwise successful auto/review run, should run status remain succeeded with warning events or transition to failed?
2. What production defaults should we adopt for poll/reconcile/timeout/heartbeat intervals after initial telemetry?
