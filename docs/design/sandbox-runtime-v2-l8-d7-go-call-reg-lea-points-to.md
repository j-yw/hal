# L8 D7 Go CALL-reg LEA points-to; HL8E remains unissued

This slice proves one per-call register-indirect shape: a 64-bit
RIP-relative `LEA` of a listed function **start** into the call
register, reaching `CALL`/`JMP` that register without a clobber or
skipped fact. HL8E remains unissued.
`generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim
L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not a target set and is not catalog
authority. `runtime.reviewerAuthority` is extra if it is reachable.

## Per-call LEA proof

`FF D0`/`FF D1`/`FF D6` and the other ModRM.mod=3 forms stay unbounded
unless this instruction's register is proven. A proven destination is
the RIP-relative `LEAQ` target when that target is a listed function
start, the LEA is 64-bit and canonical, and the fact reaches the
transfer. An unlisted destination, an interior, or a clobber of the
call register fail closed. A global `.noptrdata`/`.data`/`.itablink`
inventory remains a traversed subset, not a complete points-to proof.
Runtime-created closures passed through another function, itab loads,
and funcval loads stay unbounded.

`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return even if extras become empty.
`generateEvidenceFromInputs` still returns `errEvidenceInputsUnavailable`
and never writes `verified-pinned-callsites.hl8e`. Default untagged
`EmbeddedExpectedPinnedCallsiteEvidence` stays fail-closed in
`pinned_evidence_default.go`. `ImportPinnedCallsiteEvidence` is not
enabled as an HL8E issuer by this slice.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7GoCallRegLEAPointsTo|^TestL8D7GoCallRegPointerTaken|^TestL8D7HL8E' -count=1
go vet ./tools/microvm/l8/policy/generate ./cmd
tools/microvm/l8/policy/verify-artifact.sh
```

These commands are fake-only. They do not boot a VM, call billed APIs, or
select live tags.

## Broad verification

```
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- issue HL8E or enable `generateEvidence` success;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- treat a global pointer-taken inventory as a complete CALL-reg proof;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- billed Azure/OpenAI;
- Hetzner/Lightsail;
- merge to `develop`.
