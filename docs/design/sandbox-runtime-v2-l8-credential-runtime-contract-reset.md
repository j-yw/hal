# Sandbox Runtime v2 L8 Credential Runtime Contract Reset

## Authority and status

This note resets the implementation contract for issue #49 at integration
revision `00ebb45f`. It is grounded in the three locked issue comments:
`5068151561` (verified scope), `5068157402` (Linux-first specification), and
`5068162708` (implementation order). Those comments define L8 as production
HTTP credential-proxy, file-on-tmpfs, and SSH-agent activation whose values are
usable only by the intended job and absent after every terminal, failure, and
restart path. They do not make whole-program Go call-graph closure or an HL8E
artifact an L8 exit criterion.

This note supersedes later L8 implementation assumptions where they conflict
with that locked product boundary. It does not rewrite or delete the D2-D7
slice records: those remain useful historical evidence of what was designed,
built, and tested. In particular, the four named blockers in
`sandbox-runtime-v2-l8-d7-prepared-linux-acceptance.md` are a historical
decomposition, not the new acceptance checklist. Future work is judged by
observable credential usability, isolation, teardown, and redaction rather
than by whether every speculative internal service was completed.

The later issue comment `5302732597` records substantial credential protocol and
lifecycle test work, but its fake-only product-guard results and package tests
are not the required no-skip prepared-Linux credential E2E. That evidence does
not establish L8 completion. The selected live acceptance still has to run
against the built guest and real Firecracker job lifecycle.

This change is documentation and a documentation guard only. No runtime
behavior changes here, no live test has been run by this change, and no L8,
L10, or L11 completion claim is made.

## Evidence, inference, and selected design

Observed at the reset revision:

- the locked issue contract assigns network enforcement to L7, credential
  activation to L8, and strict composition/default selection to L10;
- the repository contains the existing `hal-init` and `hal-guest-agent`
  runtime path plus several later D7 role entrypoints;
- the HL8E generator remains fail-closed and HL8E v1 remains unissued; and
- the prepared-Linux L8 credential-delivery test is not accepted evidence.

We infer that the six-role guest topology and static reachable-call-graph gate
became an internal solution larger than the product property it was meant to
support. The call graph can improve build-time review coverage, but it is not
a runtime CFI control: it does not stop a compromised guest process from using
a syscall that an installed filter permits. The existing runnable
`hal-init`/`hal-guest-agent` path does not currently install a guest seccomp
filter, so default-deny guest syscall enforcement must not be presented as an
active L8 control. Exact image identities, the VM boundary, host-owned
authority, and live negative tests are the controls available to enforce or
directly test the reset L8 property. A future guest seccomp slice remains
useful defense in depth, but must have its own executable-path and live
evidence before it becomes a claim.

We therefore select the smallest topology that can satisfy the locked
behavior: one fresh Firecracker VM per job, with the execution chain
`hal-init -> hal-guest-agent -> job workload`. The host owns credential
authority, network authority, and job lifecycle. L8 proves usability and
cleanup for the three production modes. L10 owns strict secure-default
selection and correlates L5, L7, L8, L9, and workspace proof; L8 does not
select or advertise the strict default.

## Ownership and data flow

```text
host sandbox worker (single job/lifecycle owner)
  |
  +-- L7 network namespace, firewall, policy proxy, inspection, cleanup
  |
  +-- L8 job credential owner
  |     +-- HTTP credential proxy: secret stays host-side
  |     +-- tmpfs-file activation: bounded value crosses once into job tmpfs
  |     +-- SSH-agent relay: private key stays host-side
  |
  +-- Firecracker: one fresh VM for this job
        |
        +-- hal-init (PID 1, runtime policy and process cleanup)
              |
              +-- hal-guest-agent (bounded authenticated control)
                    |
                    +-- job workload
```

The host creates credential authority only after the VM and guest agent are
ready, binds it to the exact sandbox/job/runtime generation, and revokes it
before terminal success can be published. Guest loss, host cancellation,
timeout, nonzero exit, activation failure, or daemon recovery all converge on
the same idempotent host cleanup owner. VM destruction is a useful final
containment boundary, but it is not a substitute for closing host proxy routes,
tickets, relays, secret buffers, or durable cleanup checkpoints.

The delivery-mode contract stays narrow:

- The HTTP credential proxy accepts only the job-scoped route and authorized
  request class. The workload can demonstrate an authenticated request, but it
  cannot read the injected credential.
- The private tmpfs file is created with bounded content and restrictive
  permissions after guest readiness. Its location is outside the workspace and
  image, and the file and mount are absent after cleanup.
- The SSH-agent relay permits the intended job to perform a signing/auth
  operation. Private key bytes do not enter the guest or durable state.

No raw value belongs in manifests, job records, timelines, logs, errors,
process arguments, durable environment, artifacts, or sync-out. Safe durable
state records only opaque identity, generation, mode, phase, and cleanup
status needed for fail-closed recovery.

## Minimum guest profile

`hal-guest-credential-helper`, `hal-guest-mount-monitor`, and
`hal-guest-workload-shim` are not mandatory processes or image roles in the
accepted L8 profile. We should not require an unconditional exit 127
placeholder to be installed merely because a historical design assigned it a
role. These entrypoints may remain inert in the repository while migration is
underway; they enter the accepted profile only if a later red test proves a
missing security property that cannot be preserved cleanly by `hal-init`,
`hal-guest-agent`, and the host owner.

This is a topology decision, not permission to weaken boundaries. If guest
mount ownership cannot be made race-safe inside the existing PID 1/agent
contract, or workload privilege separation requires a dedicated executable,
we add the smallest independently justified role and its live failure tests.
We do not pre-install three long-lived principals in anticipation of such a
finding.

The initial accepted profile does not pool or reuse VMs and does not restore a
credential-bearing snapshot. A fresh VM costs boot latency, but makes job
scope and cleanup easier to reason about. Pooling can be reconsidered only
after a separate design proves generation reset, memory/device cleanup, and
equivalent negative isolation.

## HL8E boundary

HL8E v1 remains unissued and stays an offline diagnostic. We preserve its
format, importer, generator analysis, and historical tests for investigation;
we do not manufacture weaker evidence or claim a bounded Go call graph. It is
not a runnable L8 build, boot, activation, or acceptance prerequisite.

That critical-path change must be made only through future product tests:
first prove red that the selected L8 image/build/run path still requires HL8E,
then remove only that dependency while keeping exact required-role/image
digests and fail-closed image behavior. This cutover does not claim the
currently inactive guest seccomp path. A documentation assertion alone cannot
detach HL8E. The diagnostic may become a release-hardening gate in a future
issue if a tractable analysis and a clearly stated security property are
demonstrated.

## Options and tradeoffs

We considered two real directions. Option 1 is selected under the current
simplicity and delivery constraints. Option 2 remains defensible if static
syscall reachability becomes an explicit release requirement rather than a
proxy for live credential safety.

| Dimension | Option 1: minimal two-process guest, runtime enforcement | Option 2: six roles plus bounded call graph/HL8E |
| --- | --- | --- |
| Security | Fewer guest principals and IPC edges; depends on exact image identity, VM isolation, host authority, and live negatives. It makes no guest syscall-filter claim, so a guest-kernel exploit has a wider syscall surface than it would under a proven default-deny guest filter. | Adds source-derived syscall review coverage if the proof is sound. It still is not CFI and keeps more privileged processes, IPC, and lifecycle edges. |
| Performance | Pays one fresh VM boot per job; no extra helper hops. No performance result is claimed until measured. | Also pays VM boot and adds process/control hops; analysis and build issuance add release time. |
| Memory | Two required guest processes reduce baseline process state. The exact saving is unmeasured. | Additional binaries/processes and ledgers consume guest memory; the exact cost is unmeasured. |
| Reliability | One host owner and one guest control process reduce partial-start and cleanup states. VM teardown provides a clear final boundary. | Dedicated roles can isolate individual failures, but increase coordination, restart, and proof-correlation states. |
| Operability | Live evidence answers the operator question directly: did each mode work, stay scoped, and disappear? | HL8E adds build tooling, source locks, diagnostic interpretation, and issuance maintenance before the operator can run L8. |
| Migration | Reuses L5/L7 Firecracker and the existing PID 1/guest-agent path. Historical roles stay inert until removed or justified. | Preserves the D7 decomposition but requires completing or replacing the stalled analysis before any L8 run. |
| Rollback | Re-enable an explicitly tested role or restore an HL8E product gate if later evidence shows a lost property. | Removing the graph gate later repeats this reset after more implementation has coupled to it. |

Option 1 deliberately gives up a static completeness claim that the repository
cannot currently support. It retains final-binary identity, but it cannot
retain or give up a guest seccomp control that the selected runnable path never
installed. Option 2 becomes preferable only if reviewers define a falsifiable
property that HL8E uniquely enforces, demonstrate a tractable proof for the
pinned Go toolchain, and accept the extra topology and release cost.

## TDD implementation order

Every production slice follows the same rule: the red test is committed before
its minimal implementation, then focused, race-relevant, broad, and live gates
are rerun. The order below is dependency order, not evidence that any step is
already green.

1. RED: detach HL8E from the runnable L8 path. Add product tests proving the
   selected L8 image/build/run path neither reads nor requires HL8E, while a
   corrupt image identity still fails closed. Keep the offline analyzer tests
   and the unissued status intact; make no guest seccomp claim.
2. RED: lock the minimum guest topology. Add image-manifest, PID 1, process
   enumeration, and teardown tests for exactly
   `hal-init -> hal-guest-agent -> job workload`; prove the three historical
   entrypoints are not required or started by default.
3. GREEN: compose one host credential owner. Reuse the existing narrow
   credential and network boundaries. Give one owner the mode lifecycle,
   generation checks, bounded value handling, and idempotent cleanup; do not
   add a second scheduler, job store, proxy policy engine, or secret store.
4. GREEN: bind activation to one fresh VM and job. Activate only after the
   authenticated guest readiness handshake, run one workload, revoke before
   terminal publication, and destroy the VM. Persist only safe recovery state.
5. LIVE: prove each delivery mode. Make the selected prepared-Linux harness run
   `http_only`, `file_tmpfs_only`, `ssh_agent_only`, and `all_modes` against the
   freshly built digest-locked image. Each test must demonstrate real workload
   use, cross-job denial, and owned cleanup.
6. LIVE: run the terminal and restart matrix. The
   `failure_recovery_matrix` covers success, nonzero exit, activation failure,
   cancellation, timeout, proxy/relay loss, guest loss, Firecracker exit,
   partial preparation, daemon restart, repeated recovery, and idempotent
   cleanup.
7. LIVE: prove absence and redaction. Scan all durable/public surfaces for
   per-test canaries and inspect that no owned host route, listener, relay,
   buffer, file, mount, socket, VM, or cleanup-pending job remains; a skip is a
   blocker, never a pass.
8. HANDOFF: unlock L10 only after L8 passes. Record exact artifact digests,
   selected tests, pass/fail/skip counts, and cleanup evidence. L10 then owns
   the correlated strict-default selection and its missing/corrupt-proof
   negatives.

## Verification for this documentation slice

```sh
go test ./cmd -run '^TestL8ContractReset' -count=1
go test ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` may be reported only when `command -v golangci-lint` succeeds.
The default commands above do not select live tags, boot Firecracker, mutate
network namespaces, access credentials, or call billed providers. The focused
documentation test proves only that this decision and order remain explicit.

## Non-claims and later handoff

This reset does not attest that the minimum runtime topology already exists in
the produced image, that credential values are currently usable inside a real
guest, that cleanup survives restart, or that the prepared-Linux harness has
passed. It does not delete historical code, issue HL8E, enable the Jailer path,
change L7 enforcement, or select strict mode.

L8 exits only on the locked live behavior. L10 remains blocked until that
no-skip evidence is current, exact, warning-free, and correlated to the same
sandbox, execution, worker, runtime, network, and job generations.
