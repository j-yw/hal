# L8 D7 VEX length and itab method-slot CALL-reg; HL8E remains unissued

This slice walks VEX/EVEX instruction lengths so SIMD bodies no longer
hide later relative `CALL`s, and proves one more per-call
register-indirect shape: `LEAQ`/`MOV` of a `.itablink` itab, then
`MOV r64, disp(itab)` of a method slot (`disp >= 24` and 8-byte
aligned), then `CALL`/`JMP` that register. HL8E remains unissued.
`generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim
L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not a target set and is not catalog
authority. `runtime.reviewerAuthority` is extra if it is reachable.

## VEX/EVEX length

`C4`/`C5`/`62` are prefixes, not decode failures. Length follows the
0F / 0F38 / 0F3A opcode map, including `VZEROUPPER` (`C5 F8 77`) with
no ModRM. A REX prefix before VEX/EVEX fails closed. Incomplete
prefixes fail closed. A reachable VEX body must still follow a later
relative `CALL`. Remaining unproven `CALL`-reg in the Go runtime may
keep a binary unbounded; hiding the relative `CALL` is not allowed.

## Itab method slot

`.itablink` 8-byte words name itab objects. A 64-bit RIP-relative
`LEA` or `MOV` of such an address proves the register holds that itab.
`MOV r64, disp(itab)` with `disp >= 24` and `disp % 8 == 0` loads one
method pointer. If that pointer is a listed function **start**, the
following `CALL`/`JMP`-reg is that start. Type/Inter fields
(`disp < 24`), unlisted methods, missing mappings, clobbers, and
jump-table entries that skip the facts stay unbounded. A global
pointer-taken inventory remains a traversed subset, not a complete
points-to proof. Funcval trampolines and closures passed through
another function stay unbounded.

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
go test ./cmd -run '^TestL8D7GoCallRegVEXItab|^TestL8D7GoCallRegMOVRIP|^TestL8D7HL8E' -count=1
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
- treat a global pointer-taken or LEA inventory as a complete CALL-reg proof;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- billed Azure/OpenAI;
- Hetzner/Lightsail;
- merge to `develop`.
