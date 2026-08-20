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

The current constructor returns the stable sanitized dependency failure before
retaining or calling the injected kernel because the adapter-callsite
inventory and native generated artifact are incomplete. Removing guest access
to the host-only evidence issuer does not activate this constructor.
The non-Linux constructor rejects without inspecting its inputs.

## Green gates

```sh
go run ./tools/microvm/l8/policy/generate -root . -check
go test -count=1 ./internal/sandboxruntime/microvm/guestagent/credentialhelper/linux ./internal/sandboxruntime/microvm/guestagent/rolebootstrap ./tools/microvm/l8/policy/generate
go test -count=1 -tags=l8_verified_policy_artifact ./internal/sandboxruntime/microvm/guestagent/syscallpolicy ./internal/sandboxruntime/microvm/guestagent/credentialhelper/linux
go test -count=1 ./cmd -run '^TestL8D4SyscallAdapterFoundation'
```

The later full-wrapper red gate is intentionally separate:

```sh
go test -count=1 -tags=l8_d4_full_syscall_adapter ./internal/sandboxruntime/microvm/guestagent/credentialhelper/linux -run '^TestL8D4FullSyscallWrapper'
```

It must fail until the sole private wrapper implements the exact
`unstarted -> claimed -> executed -> finalized` lifecycle, makes one syscall,
uses the same D2 permit for its sole terminal call, closes any rejected returned
object, and passes the context, typed-nil, panic, error, cleanup, concurrency,
reuse, and no-object-escape matrices. A passing default gate is not a substitute
for that later tagged gate.

## Non-goals

- No raw syscall, BPF installation, mount, cgroup, namespace, VSOCK, process,
  command, worker, factory, provider, or Firecracker behavior is added.
- No D7 rule, expected evidence marker, native source digest, callsite digest,
  binary identity, permit, or active proof is fabricated.
- `credentialhelper/linux.NewCore` remains the existing explicit injected-core
  boundary; root commands and sandboxd do not select this constructor.
