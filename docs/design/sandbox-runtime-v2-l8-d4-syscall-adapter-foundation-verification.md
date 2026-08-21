# L8 D4 Syscall Adapter Foundation Verification

This slice closes only the truthful D2/D4/D7 junction needed before a live
credential-helper syscall wrapper can exist. It does not claim D4 live syscall enforcement,
native bootstrap installation, final-binary evidence, or active guest proof.

## Frozen boundary

The D7 generator emits
`credentialhelper/linux/policy_install_inventory_d7_gen.go` from the exact D2
role and binary-kind catalogs. Its five ordered native bindings are:

1. PID1 to `RoleLaunchBootstrap` / `BinaryBindingKindNativeBootstrap`;
2. controller to `RoleControllerBootstrap` / `BinaryBindingKindNativeBootstrap`;
3. agent to `RoleAgentBootstrap` / `BinaryBindingKindNativeBootstrap`;
4. monitor to `RoleMonitorBootstrap` / `BinaryBindingKindNativeBootstrap`; and
5. workload shim to `RoleWorkloadTransition` / `BinaryBindingKindNativeBootstrap`.

The generated install-table digest uses
`hal/l8/d4-native-install-table/linux-amd64/v1` over the exact ordered rows.
The generator also emits the adapter-callsite inventory from exact
`EnforcementPathAdapter` rows. The currently issued D7 foundation has no such
rows, so the adapter-callsite inventory is empty and cannot enable a live constructor.

`credentialhelper/linux.NewSyscallPolicyCoreKernel` accepts only an injected
`CoreKernel` and an opaque `rolebootstrap.InstallPlan`. The guest-side
constructor loads and validates only the embedded HL8Q artifact and source-lock
authority, requires a D2 ticket for every generated adapter-callsite input,
requires the D7-issued native artifact, and correlates the policy and
install-table digests. The guest-side constructor never loads or imports HL8E.
The local resolver remains the sole production consumer of the host-only expected HL8E issuer
and binds imported final-binary evidence into the opaque host profile. Callers
cannot supply a policy, profile, expected evidence marker, or generated native
artifact.

The package-wide production guard parses every non-test Go file from the
repository root, including build-tagged variants. It first requires every other
production file to have zero guarded spellings, including `go:linkname`
directive targets, then permits one spelling in each frozen issuer leaf, one
spelling in the import leaf, and one spelling per exact local-resolver call.
The default issuer is exactly
`syscallpolicy/pinned_evidence_default.go` under
`!l8_verified_pinned_callsite_evidence`. The mutually exclusive future D7
issuer is allowed only at exact generated path
`syscallpolicy/pinned_callsite_evidence_expected_d7_gen.go` under
`l8_verified_pinned_callsite_evidence`; it remains absent until D7 has real
final-binary authority. When that generated file is present, the complementary
constraints select exactly one issuer declaration in each build context. The
allowed files are parsed independently: declaration signatures and objects
stay exact, the sole `syscallpolicy` import is decoded with `strconv.Unquote`,
and the only two bound direct calls remain in
`localresolver.VerifyL8DistributionBundle`.

The current constructor returns the stable sanitized dependency failure before
retaining or calling the injected kernel because the adapter-callsite
inventory and native generated artifact are incomplete. Removing guest access
to the host-only evidence issuer does not activate this constructor.
The non-Linux constructor rejects without inspecting its inputs.

The one-shot wrapper now exists only in
`syscall_policy_wrapper_linux.go` under the exact
`linux && amd64 && l8_d4_full_syscall_adapter` build constraint. Its only live
operation injection is the private one-method `syscallExecutor`; it contains no
raw syscall implementation. The private constructor uses the concrete D2
`Policy.NewAdapterBindings` and `Policy.AuthorizePre` methods before installing
the executor. The wrapper then permits one execution and one exact terminal D2
call, cleans every returned object before final convergence, and clears its
bindings, permit, executor, and terminal references before returning.

The positive lifecycle harness is test-only because the current D7 artifact
truthfully issues no adapter row or permit. It neither mints D2 authority nor
enters a production call graph. `NewSyscallPolicyCoreKernel` remains
unavailable, default builds exclude the wrapper, and no active policy proof is
claimed.

## Green gates

```sh
go run ./tools/microvm/l8/policy/generate -root . -check
go test -count=1 ./internal/sandboxruntime/microvm/guestagent/credentialhelper/linux ./internal/sandboxruntime/microvm/guestagent/rolebootstrap ./tools/microvm/l8/policy/generate
go test -count=1 -tags=l8_verified_policy_artifact ./internal/sandboxruntime/microvm/guestagent/syscallpolicy ./internal/sandboxruntime/microvm/guestagent/credentialhelper/linux
go test -count=1 ./cmd -run '^TestL8D4(SyscallAdapterFoundation.*|HostEvidenceHasOneRepositoryWideProductionConsumer)$'
```

The default-off full-wrapper gate is intentionally separate:

```sh
go test -count=1 -tags=l8_d4_full_syscall_adapter ./internal/sandboxruntime/microvm/guestagent/credentialhelper/linux -run '^TestL8D4FullSyscallWrapper'
```

It proves the sole private wrapper's exact
`unstarted -> claimed -> executed -> finalized` lifecycle, one executor call,
same-permit terminal call, pre/post cancellation phase, returned-object cleanup,
typed-nil and panic containment, concurrent/reentrant/reuse rejection, and
post-finalization authority erasure. The package-private positive harness is
not a D7 issuer and a passing tagged gate is not evidence that the unavailable
constructor or any default path is live.

## Non-goals

- No raw syscall, BPF installation, mount, cgroup, namespace, VSOCK, process,
  command, worker, factory, provider, or Firecracker behavior is added.
- No D7 rule, expected evidence marker, native source digest, callsite digest,
  binary identity, permit, or active proof is fabricated.
- No exported executor, wrapper, ticket, permit, binding, returned object, or
  tagged-constructor callsite is added.
- `credentialhelper/linux.NewCore` remains the existing explicit injected-core
  boundary; root commands and sandboxd do not select this constructor.
