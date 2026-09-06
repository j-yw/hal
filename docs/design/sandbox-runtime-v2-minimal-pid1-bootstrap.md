# Minimal guest PID1 bootstrap validation

This slice follows the selected L8 minimal guest contract and the accepted
minimal-control bootstrap. It changes only the ordinary Linux PID1 entrypoint,
which the minimal image already installs. The tagged historical
`l8_production_pid1` path and its sealed gate remain unchanged.

## Order and failure behavior

PID1 keeps its current argument and process-ID checks. It then reads the single
bounded `/proc/cmdline` source once, retaining the exact bytes. Before network
configuration, start-gate release, or child supervision, it validates the minimal
namespace with `minimalcontrol.ParseBootCommandLine`. Missing minimal settings
retain ordinary L7 behavior; malformed or partial settings, read failures,
embedded controls, and oversized command lines return the existing exit127
without entering any of those side-effect boundaries. Public pins are not
credentials, but neither pins nor errors are printed or persisted.

The same retained command line feeds the existing L7 parser. Required-but-absent
L7 settings and malformed L7 settings still return127. A valid L7 configuration
still runs the existing network setup, produces the exact fixed child
environment, releases the existing gate, and supervises the same arguments.
Network failure stops before the gate; gate failure stops before the child.
Child exit codes, process-group signaling, bounded termination, and child
reaping are unchanged. Selection does not itself prove network enforcement or
authenticated readiness; the guest agent independently validates and
authenticates its accepted control session after launch.

## Red-first verification and handoff

A private entrypoint dependency seam exposes the production read/configure/
gate/supervision order to deterministic tests. The initial RED includes only
this wiring/refactor, retaining the existing L7-only parser decision: malformed
minimal input reaches the counted network, gate, and child callbacks. GREEN
adds the accepted minimal parser before the L7 parser. Test fixtures contain
synthetic public pins, not production keys or runtime evidence.

```sh
go test ./cmd/hal-guest-init -run '^TestMinimalPID1' -count=1
go test -race ./cmd/hal-guest-init ./cmd/hal-guest-agent ./internal/sandboxruntime/microvm/guestagent/minimalcontrol ./internal/sandboxruntime/microvm/guestnetwork -count=3
go test -tags=l8_production_pid1 ./cmd/hal-guest-init -count=1
go vet ./cmd/hal-guest-init
git diff --check
```

Repository-wide tests, vet, CLI docs/build and existing source guards remain
integration gates. These tests do not run as PID1, launch children, configure
host networking, boot a VM, or prove live guest teardown. There are no new
process roles, boot fields, durable/public schemas, image permission changes,
credentials, host consumers, or default strict selection. The resulting exact
guest binary must later be rebuilt into the measured image and accepted with
the real Linux lifecycle and credential matrix.

## Integration diagnostic follow-up

The full default suite at `ff278306` exposed two existing regression gates not
selected by the focused checks: the legacy call-graph diagnostic lost its named
`clone`/`clone3` rejection reason when child supervision moved behind an injected
function pointer, and the checked-in HL8Q source-lock outputs became stale.
Neither failure authorizes changing the diagnostic, syscall catalog or HL8E gate.

Production therefore calls the existing child supervisor directly after
preparation; the optional private callback remains only a deterministic test
override. This restores the diagnostic's direct production call edge without
changing startup order or any original test assertion. Regenerate the four
changed HL8Q/source-lock outputs using the existing generator, not edited pins.
HL8Q is not HL8E, and the unchanged graph test must still reject issuing HL8E
because the named process-creation syscalls remain reachable.

```sh
go test ./tools/microvm/l8/policy/generate -run '^TestL8D7(ReachableGraphNamesGoLaunchBaseExtraSyscalls|ArtifactGenerationIsDeterministicAndMatchesCheckedInOutputs)$' -count=1
```
