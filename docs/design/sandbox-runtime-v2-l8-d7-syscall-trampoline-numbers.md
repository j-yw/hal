# L8 D7 HL8E remains unissued; syscall trampoline numbers are bound

This slice binds reachable `syscall.rawSyscallNoError.abi0` and
`syscall.rawVforkSyscall.abi0` CALL/JMP sites by recovering the
linux/amd64 trap/number from the direct caller's setup. HL8E remains
unissued. `generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live, does
not claim L8 complete, does not claim L10, and does not claim L11. It
does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not catalog authority and is not
trampoline-number authority. `runtime.reviewerAuthority` is extra if it
is reachable with an unlisted named syscall. Unbounded indirect CALL/JMP
still fail closed.

## Trampoline number recovery

Go ABI0 stacks the trap/number as the first argument. Direct callers of
those exact `.abi0` trampolines prove a number by `MOVQ $imm` into the
trap slot (`0(SP)`) or AX before CALL/JMP. Recovery is bounded
inter-procedural constant propagation from those direct callers only.
The immediate and transfer must be in the same basic block. A branch
target or fallthrough boundary, an intervening call, an unproved register
or memory write, a stack-pointer change, a non-`MOVQ` trap-slot store, an
indexed or segment-relative stack address, or a transfer into the middle
of a trampoline clears the fact and keeps the site unknown.

If the number is uniquely proven, the CALL/JMP classifies as that named
linux/amd64 syscall. Catalog-listed names are not extras. Unlisted names
remain extras. If the number is not uniquely proven, keep
`unknown:symbol` extra. The trampoline body `SYSCALL` is not a second
unknown site once callers classify it.

`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return even if extras become empty.
`generateEvidenceFromInputs` still returns `errEvidenceInputsUnavailable`
and never writes `verified-pinned-callsites.hl8e`. Default untagged
`EmbeddedExpectedPinnedCallsiteEvidence` stays fail-closed in
`pinned_evidence_default.go`. ImportPinnedCallsiteEvidence default
success stays disabled.

Native `_start` extras stay fail-closed live behavior, not HL8E
pinned-direct evidence. Generic Go binaries and a singular
`-evidence-binary` stay rejected.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7SyscallTrampoline|^TestL8D7RuntimeEnvelope|^TestL8D7HL8E' -count=1
go vet ./tools/microvm/l8/policy/generate ./cmd
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
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
