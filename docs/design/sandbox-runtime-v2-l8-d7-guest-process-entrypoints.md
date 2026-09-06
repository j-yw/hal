# L8 D7 guest process entrypoints

This slice adds default-off, Linux-only process entrypoints for the
capability-free credential controller, per-job mount owner, and one-shot
workload transition. The packages contain no independently testable policy.
They construct existing D6 APIs, reject missing/extra/typed-nil
dependencies, never install a default SSH extension, and fail closed without
live sockets, bind, listen, or dial.

It does not claim L8 complete, does not claim L10, and does not claim L11.
D7 prepared-Linux acceptance remains unaccepted. D7 live stub fatals and
HL8E remain unissued.

## Exact NewHelper ownership

`l8composition.NewHelper` is called only inside
`cmd/hal-guest-credential-helper`. `cmd/hal-guest-agent` remains the only
intended `NewClient` caller and is not re-architected by this slice.

`cmd/hal-guest-mount-monitor` is the per-job mount owner entrypoint. It
consumes the `rolebootstrap` installer only and constructs
`l8composition.NewControllerMonitorState`.

`cmd/hal-guest-workload-shim` is the one-shot workload transition
entrypoint. It consumes the `rolebootstrap` installer only for
`RoleWorkloadShim`.

Non-Linux stubs fail closed with exit 127. Production Linux mains fail
closed with the same sanitized exit when a required constructor returns
`dependency_unaccepted`, `ErrDependency`, `ErrContractDependency`, or
another documented contract error. This slice does not synthesize success.

## Default-off command paths

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory command-path wiring of these guest process
entrypoints.

## Fail-closed remaining live behaviors

Remaining live Serve, HL8M, exec, listen, bind, and dial stay unaccepted.
`sshrelay.NewHelperExtension` is not a default SSH install. Sealed D7
artifacts, including `rolebootstrap.EmbeddedGeneratedArtifact` and
`NewSyscallPolicyCoreKernel`, still fail closed until D7 issues them.

## Focused fake-only commands

```
go test ./cmd/hal-guest-credential-helper ./cmd/hal-guest-mount-monitor ./cmd/hal-guest-workload-shim -count=1
go test ./cmd -run '^TestL8D7GuestProcessEntrypoints' -count=1
go vet ./cmd/hal-guest-credential-helper ./cmd/hal-guest-mount-monitor ./cmd/hal-guest-workload-shim ./cmd
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

`golangci-lint` reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- change D7 live stub fatals;
- issue HL8E or edit `tools/microvm/l8/policy/verified-syscall-policy.hl8q`;
- implement live helper Serve, mount-monitor sockets, or workload exec;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
