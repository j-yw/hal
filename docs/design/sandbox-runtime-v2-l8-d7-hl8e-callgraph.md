# L8 D7 HL8E is issued from the unique/reachable callsite graph

This slice binds a unique/reachable D4/D6 callsite graph to the D7
final-binary inspector and issues host-only HL8E from the complete guest
role set. HL8E is issued. D7 live remains disabled. This slice does not
claim D7 live, does not claim L8 complete, does not claim L10, and does
not claim L11. It does not change live D7 stub fatals.

`generateEvidence` succeeds only for `-evidence-binaries-dir` after every
required linux/amd64 role binary is identity-checked, hashed, and the
unique/reachable graph classifies every decoded `syscall` instruction.
A singular `-evidence-binary` still fails closed with
`errEvidenceInputsUnavailable`. Unrelated or generic Go binaries still
fail closed even when they embed HL8Q and `Syscall6`.

## Issued evidence

The inspector hashes every complete final role binary and executable
text, locates approved symbol `internal/runtime/syscall.Syscall6`, and
hashes instruction-length bytes at offset 12 (`0f05`). Those bytes must
equal the source-derived instruction template from Go 1.25.7
`src/internal/runtime/syscall/asm_linux_amd64.s`.

The unique/reachable graph decodes x86-64 instruction boundaries instead
of byte-scanning `0f05`. Extra decoded `syscall` sites in the pinned Go
runtime, `runtime.*` assembly, `time.now`, and `syscall.*` /
`golang.org/x/sys/unix.*` wrappers are classified as non-authority / not
the pinned-direct path. Unclassified sites fail closed with
`unique/reachable D4/D6 call graph is unavailable`. Native
`hal-guest-role-bootstrap` must decode exactly seven `_start` syscalls.

Issued outputs:

- `tools/microvm/l8/policy/verified-pinned-callsites.hl8e`
- `tools/microvm/l8/policy/verified-pinned-callsites.hl8e.sha256`
- `internal/sandboxruntime/microvm/guestagent/syscallpolicy/pinned_callsite_evidence_expected_d7_gen.go`
  under `l8_verified_pinned_callsite_evidence`

The envelope imports through `ImportPinnedCallsiteEvidence` against
`EmbeddedVerifiedPolicyArtifact` and has one binding per artifact pinned
callsite: launch-base plus pinned Go runtime. Instruction, offset, and
text-length checks pass. Default untagged
`EmbeddedExpectedPinnedCallsiteEvidence` stays fail-closed in
`pinned_evidence_default.go`.

HL8E issuance is not D7 live and does not treat L5 images as L8.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test -tags=l8_verified_policy_artifact,l8_verified_pinned_callsite_evidence ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7HL8ECallgraph' -count=1
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
- generate `verified-pinned-callsites.hl8e` from a fixture;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
