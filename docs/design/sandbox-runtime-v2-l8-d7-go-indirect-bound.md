# L8 D7 Go indirect targets are bound from ELF metadata; HL8E remains unissued

This slice binds previously unbounded Go control-flow edges that can
be named from Go 1.25.7 linux/amd64 ELF metadata. HL8E remains
unissued. `generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim
L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not a target set and is not catalog
authority. `runtime.reviewerAuthority` is extra if it is reachable.
Unknown or unenumerated indirect CALL/JMP still fail closed unbounded.

## Honest listed-span and jump-table binding

Pclntab spans stay authoritative and ELF `STT_FUNC` spans stay
supplemental. A relative CALL/JMP whose destination is inside a listed
`STT_FUNC` / pclntab span is that known function, even when the
destination is not the span start. That covers ABI0 interiors such as
`runtime.duffcopy`, `runtime.duffzero`, and `indexbytebody`. Unlisted
destinations stay unbounded.

A `JMP [base+index*8]` is a known target set only when the same
function proves a RIP-relative `LEAQ` of the table into `base` and an
AND/CMP length on `index`. Those facts must reach the dispatch without
an incoming branch or listed-span interior entry skipping them. A CMP
proof is 64-bit and its forward `JA` must bypass the dispatch. The
canonical table is a complete, unique, non-writable ELF mapping, and
every table word must resolve inside a listed span. In-function labels
add no extra edges. Missing length, missing table base, a noncanonical
memory prefix/base, an indexed indirect CALL, or a pointer outside
listed spans fail closed. `FF 24 D1` without that proof is not assumed
to be an itab method table.

`.itablink` / `.typelink` method, `Equal`, and `Hasher` pointers are
not a complete CALL-reg target set. Closures, `deferwrap`,
`internal/runtime/exithook` function values, and heap/stack funcvals
are pclntab functions that those tables do not uniquely name.
Attaching every pclntab function to every `CALL RAX`/`RCX`/`RSI` would
re-reach trampolines such as `syscall.rawVforkSyscall.abi0`. This
slice does not guess that set. Unproven `FF D0`/`FF D1`/`FF D6`
remain unbounded. A preceding RIP-relative LEA does not turn a
register-indirect CALL into one of the allowed relative CALL/JMP edges.

`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return even if extras become empty.
`generateEvidenceFromInputs` still returns `errEvidenceInputsUnavailable`
and never writes `verified-pinned-callsites.hl8e`. Default untagged
`EmbeddedExpectedPinnedCallsiteEvidence` stays fail-closed in
`pinned_evidence_default.go`. `ImportPinnedCallsiteEvidence` is not
enabled as an HL8E issuer by this slice.

## Remaining unbounded forms

Go guests are not fully bounded. Remaining unbounded edges from
`main.main` include unproven register-indirect CALL of map hashers,
interface `Equal`, deferred function values, and exithook `F`. Native
`_start` is unchanged. Generic Go binaries and a singular
`-evidence-binary` stay rejected.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7GoIndirectBound|^TestL8D7HL8E' -count=1
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
