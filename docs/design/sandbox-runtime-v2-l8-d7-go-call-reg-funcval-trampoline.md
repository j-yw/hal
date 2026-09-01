# L8 D7 funcval trampoline CALL-reg; HL8E remains unissued

This slice proves one-hop Go funcval dispatch: a caller that stores a
listed function **start** at `[RSP+disp]`, loads `AX` as that slot
address, and `CALL`s a trampoline whose body is `MOV r, (AX); CALL r`.
The trampoline's register-indirect call is the stored start. HL8E
remains unissued. `generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim
L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not a target set and is not catalog
authority. `runtime.reviewerAuthority` is extra if it is reachable.

## Stack funcval and trampoline

`LEA r, listed-start`, `MOV [RSP+disp], r`, `LEA AX, [RSP+disp]` proves
`AX` holds a funcval whose first word is that start. A relative `CALL`
to a trampoline with that `AX` instantiates the trampoline. A trampoline
is a function whose only unproven `CALL`-reg loads `(AX)` at displacement
0 from entry `AX` (Go first argument). The graph follows the stored start
only for that trampoline callee, not for every relative `CALL` that
happens to pass a funcval. A trampoline reached without a proven funcval
argument stays unbounded. CMP/TEST/PUSH and `MOV reg,reg` clobber only
their real destinations. A global pointer-taken inventory remains a
traversed subset, not a complete points-to proof.

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
go test ./cmd -run '^TestL8D7GoCallRegFuncvalTrampoline|^TestL8D7GoCallRegVEXItab|^TestL8D7HL8E' -count=1
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
