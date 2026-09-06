# Sandbox Runtime v2 Phase 41 MicroVM Image Pipeline Verification

Phase 41 establishes backend-neutral, deterministic Firecracker microVM launch
asset contracts and local digest-lock resolution while preserving explicit
sandboxd Firecracker compatibility. The phase makes launch inputs structured
and verifiable without changing default runtime selection or adding a production
image pipeline.

## Implemented Scope

`internal/sandboxruntime/microvm/assets` owns the immutable launch descriptor
contracts. Descriptors carry safe IDs, safe labels, asset roles and kinds,
source metadata, host path role metadata, digest locks, optional init or agent
config metadata, and bounded resource metadata. Validation requires kernel and
rootfs roles, allows optional initrd and guest config roles, rejects malformed
digests and unsafe metadata, preserves nil-versus-explicit-empty semantics, and
returns sanitized validation errors only.

`internal/sandboxruntime/microvm/assets/localresolver` owns explicit local file
verification and SHA-256 digest locking. The resolver accepts structured asset
requests, rejects unsafe or unavailable paths, rejects symlinks and non-regular
files, reads files only for digesting, and returns deterministic immutable
descriptors. Resolver public errors expose safe codes, fields, roles, and fixed
messages without raw paths, URLs, tokens, hostnames, ports, or secret-looking
input.

`internal/sandboxruntime/microvm.Config` can carry an optional
`launchDescriptor` while preserving legacy path-only fields. Descriptor
validation runs only when a descriptor is present. Existing `KernelImagePath`,
`RootfsPath`, `InitrdPath`, `JailerPath`, `HypervisorPath`, `ImageLabel`,
`ImageDigest`, `TemplateLabel`, and `TemplateDigest` compatibility remains
available for existing callers.

`internal/sandboxruntime/microvm/firecracker` consumes descriptor kernel,
rootfs, and optional initrd paths during rendering when a descriptor is present.
Path-only rendering remains available as a compatibility fallback. Descriptor
metadata exposed through operation summaries is limited to safe roles, IDs,
labels, and digest metadata.

## Explicit Sandboxd Compatibility

`hal sandboxd --driver microvm` keeps the existing `--firecracker-executable`,
`--firecracker-kernel`, `--firecracker-rootfs`, `--firecracker-initrd`,
`--firecracker-jailer`, and `--firecracker-state-dir` flags. The command layer
collects structured values only; the local resolver owns path validation,
read-only file inspection, digesting, and descriptor construction before live
driver construction.

Invalid launch asset paths are rejected before driver construction and before
the sandboxd service opens. Error text names the relevant Firecracker flag and
safe resolver code, but it must not include raw host paths, basenames, URLs,
tokens, endpoint details, or secret-looking values.

Default command, factory, scheduler, worker, and rootless Podman paths do not
resolve launch assets, construct Firecracker launch descriptors, or start
Firecracker implicitly. Default `hal sandboxd` still registers
`rootless_podman` unless `--driver microvm` is explicitly selected with the
required Firecracker inputs.

## Verification Commands

Run asset contract and local resolver coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/assets ./internal/sandboxruntime/microvm/assets/localresolver
```

Run focused microVM config, Firecracker rendering, and Firecracker host
compatibility coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run command-level Phase 41 documentation, default-path guard, sandboxd
compatibility, and microVM redaction coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase4[1].*MicroVM|Phase4[1].*Firecracker|Sandboxd.*MicroVM|MicroVM'
```

Run the explicit sandboxd asset-resolution selector when reviewing the
Firecracker flag resolver boundary:

```sh
go test -count=1 -timeout=180s ./cmd -run 'SandboxdCommandResolvesExplicitFirecrackerLaunchAssetsBeforeDriverConstruction|SandboxdCommandRejectsUnavailableLaunchAssetBeforeMicroVMDriverConstruction|SandboxdMicroVMValidationDoesNotRunForRootlessPodmanOnly'
```

Run the full repository verification stack:

```sh
go test -count=1 -timeout=420s ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Fake-Safe Default Scope

Default Phase 41 verification is fake-safe and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images beyond temporary test files,
a live guest, a guest agent, vsock, SSH, or a running `hal sandboxd`.

Default Phase 41 tests use pure descriptor DTOs, temporary local files,
deterministic SHA-256 digest assertions, injected fake command dependencies,
parsed imports, AST source guards, JSON redaction assertions, and temporary
state directories only.

Default Phase 41 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
Firecracker process, access KVM, require root, bind network sockets, start
worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs,
invoke Firecracker SDKs, or depend on live providers or runtime adapters.

## Optional Live-Test Posture

Phase 41 does not add a required live-test gate. Optional live Firecracker
checks remain behind existing live-specific test posture such as the
`firecracker_live` build tag and operator-provided Firecracker prerequisites.
Optional live checks may verify that the descriptor-rendered kernel, rootfs,
and initrd paths still reach the explicit Firecracker live driver, but they are
not part of default Phase 41 verification.

Live checks must not weaken the default fake-safe gate or make KVM, root, a
Firecracker binary, or host images required for normal CI.

## Boundary Guards

Phase 41 guard tests keep asset contracts and the local resolver isolated from
runtime execution, worker protocol, Cobra parsing, factory records, concrete
runtime adapters, Firecracker host packages, Firecracker SDKs, network clients,
cloud SDKs, Docker or Podman APIs, and process launch behavior.

Default command, factory, scheduler, sandboxexec, and worker guards keep the
new asset pipeline out of default execution paths. The narrow sandboxd
exception is explicit: `sandboxd.go` may collect Firecracker flag values and
call the local resolver only for `--driver microvm`, then pass the resolved
descriptor to the injected microVM driver constructor.

Public output and documented error guards cover descriptor validation errors,
resolver errors, sandboxd flag errors, and Firecracker operation summaries.
They must keep raw host paths, path basenames, URLs, hostnames, ports, tokens,
headers, credential markers, and secret-looking values out of public text and
JSON.

## Non-Goals

Phase 41 does not implement sandbox templates or kits, image building,
kernel/rootfs provisioning, network proxy enforcement, credential proxy
delivery, default Firecracker runtime selection, worker protocol changes,
factory record persistence, Firecracker SDK integration, or a production live
image pipeline.

Phase 41 does not make descriptor metadata a factory record contract, does not
register Firecracker in default scheduler choices, does not add network or
credential delivery semantics, and does not make guest-agent, vsock, exec, or
copy support part of the image asset pipeline.

## Future Handoff Areas

Future phases are responsible for templates and kits, image packaging, network
proxy integration, credential proxy delivery, worker and scheduler registration
policy, production image lifecycle management, and live E2E coverage.

Template and kit work should consume immutable descriptors rather than raw
paths. Network proxy and credential proxy work should add explicit metadata and
delivery boundaries instead of overloading launch asset fields. Production
image lifecycle work should preserve the current split: descriptor contracts
remain data-only, local resolution stays read-only and explicit, Firecracker
rendering consumes validated descriptors, and command wiring remains an opt-in
boundary.

## Review Notes

Keep the Phase 41 verification document and
`cmd/phase41_microvm_image_pipeline_docs_test.go` in sync when focused command
selectors, guard names, sandboxd flag behavior, or public redaction guarantees
change. Keep `cmd/phase41_microvm_image_pipeline_guard_test.go` aligned with
the narrow explicit sandboxd exception so the default Hal paths stay fake-safe
and compatible with existing explicit Firecracker behavior.
