# L8 D7 Go CALL-reg pointer-taken and jump-table facts; HL8E remains unissued

This slice binds Go register-indirect `CALL`/`JMP` from a closed
pointer-taken function-start set, and binds remaining kind-switch
jump tables whose CMP/near-JA/LEA facts are separated from dispatch by
stack stores, `TEST`, or `BT`. HL8E remains unissued.
`generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim
L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not a target set and is not catalog
authority. `runtime.reviewerAuthority` is extra if it is reachable.

## Pointer-taken CALL-reg

A ModRM.mod=3 register-indirect `CALL`/`JMP` (`FF D0`, `FF D1`,
`FF D6`, and the other register forms) is a known target set only
when every destination is a listed function **start** whose 8-byte
address appears in `.noptrdata`, `.data`, or `.itablink`. Interiors
such as `runtime.duffcopy` are not pointer-taken starts.
`.gopclntab`, `.rodata`, and `PF_X` contents are not scanned. Attaching
every pclntab function to every `CALL RAX` would re-reach
`syscall.rawVforkSyscall.abi0`. A preceding RIP-relative `LEA` does
not turn a register-indirect CALL into an allowed relative transfer.

## Jump-table facts that do not clobber index/base

A proven RIP-relative `JMP [base+index*8]` may have stack-destination
`MOV`, `TEST`, or `BT r/m, imm8` (`0F BA /4 ib`) between the 64-bit
CMP/forward-JA or AND length fact and dispatch, when those insns do
not write `base` or `index`. Near `JA` (`0F 87`) is the same length
guard as short `JA`. `0F BA /4 ib` has an imm8 length. Unknown
instructions still clobber. Indexed indirect CALL, branch-skipped
facts, `FF 24 D1` without a proven table, and unlisted table entries
stay unbounded.

## SIMD and unlisted relative transfers

64-bit opcodes `C4`, `C5`, and `62` (VEX/EVEX) fail decode. A
non-entry function whose body cannot be decoded and contains no
`syscall`/`sysenter`/`int80` bytes is a non-syscall leaf. A relative
CALL/JMP destination outside every listed span is unbounded when it
lands in executable text or the body contains a direct syscall opcode;
destinations outside every `PT_LOAD PF_X` mapping in a body without
those opcodes are decoder artifacts and are not followed.

## Honest issuance still fail-closed

`proveBoundedReachableSyscallGraph` accepts the six final guest role
binaries with empty extras and no reachable unbounded indirect.
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
go test ./cmd -run '^TestL8D7GoCallRegPointerTaken|^TestL8D7GoIndirectBound|^TestL8D7HL8E' -count=1
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
- scan `.rodata` or `.gopclntab` as a CALL-reg target set;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- billed Azure/OpenAI;
- Hetzner/Lightsail;
- merge to `develop`.
