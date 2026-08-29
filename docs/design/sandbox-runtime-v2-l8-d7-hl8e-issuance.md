# L8 D7 HL8E remains unissued; final-binary inspector is bound

This slice binds a host-only linux/amd64 ELF inspector to the D7 policy
generator and prefers a complete `-evidence-binaries-dir` over a singular
`-evidence-binary`. HL8E remains unissued. This slice does not claim D7
live, does not claim L8 complete, does not claim L10, and does not claim
L11. It does not change live D7 stub fatals.

`generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. A singular ELF that embeds HL8Q and a
generic Go `Syscall6` is not a guest role identity, not the complete
final binary set, and not a unique/reachable D4/D6 call graph.

## Inspector

The inspector hashes each regular file, hashes executable `PT_LOAD`
text, and locates `internal/runtime/syscall.Syscall6`. It reads the
instruction-length bytes at offset 12 and requires those bytes equal
the source-derived `0f05` from Go 1.25.7
`src/internal/runtime/syscall/asm_linux_amd64.s`.

Guest role identity is proven from Go 1.25.7 buildinfo paths or native
bootstrap ELF constraints (`ET_EXEC`, no `INTERP`, no Go runtime). The
complete binaries-dir set is the image-pipeline names:

- `hal-init` → `github.com/jywlabs/hal/cmd/hal-guest-init`
- `hal-guest-agent` → `github.com/jywlabs/hal/cmd/hal-guest-agent`
- `hal-guest-credential-helper` → `github.com/jywlabs/hal/cmd/hal-guest-credential-helper`
- `hal-guest-mount-monitor` → `github.com/jywlabs/hal/cmd/hal-guest-mount-monitor`
- `hal-guest-workload-shim` → `github.com/jywlabs/hal/cmd/hal-guest-workload-shim`
- `hal-guest-role-bootstrap` → native `hal-guest-role-bootstrap`

This tree still lacks `cmd/hal-guest-credential-helper`,
`cmd/hal-guest-mount-monitor`, and `cmd/hal-guest-workload-shim`. A
missing-role directory fails closed. Unrelated binaries staged under
those filenames fail identity. Generic Go runtimes have many `syscall`
instructions, so the unique/reachable D4/D6 call graph is unavailable.

The generator never writes `verified-pinned-callsites.hl8e`, its
digest, or `pinned_callsite_evidence_expected_d7_gen.go` from a fixture.
Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays
fail-closed in `pinned_evidence_default.go`.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7HL8EIssuance' -count=1
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
