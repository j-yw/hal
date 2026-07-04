# Sandbox Runtime v2 Phase 54 Release Package Verification

Phase 54 US-002 guards the release build and package command surface for this
branch. Phase 54 US-003 defines the default fake-only CI matrix for routine
verification on ordinary developer and CI hosts. The branch build artifact is
the Hal CLI binary, produced locally as `./hal`.

## Default CI Matrix

Default CI is fake-only. It must not require live runtime prerequisites such as
Firecracker, KVM, Docker/Podman, sandboxd, cloud provider access, registry
credentials, proxy listeners, firewall mutation, real API secrets, live
environment markers, or tagged live test suites.

The default matrix is:

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

These commands validate tests, vet, generated CLI documentation drift, the local
Hal binary build, and whitespace. Optional live suites stay outside default CI
and must be documented as explicit opt-in operator checks.

Phase 54 planning workflow references use plain `hal convert`; they do not
require `hal convert --granular`.

## Expected Build Command

Use the Makefile build target as the release build command:

```sh
make build
```

The target compiles the root module with version metadata and writes the Hal
binary to `./hal`.

For a local package configuration check, use the GoReleaser validation target
when GoReleaser is installed:

```sh
make release-check
```

`make release-check` is config validation only. It must not publish releases or
read release credentials.

## Guarded Surface

The guarded default package/build path is limited to local Go compilation and
configuration validation. It must stay free of root privilege setup, KVM,
Firecracker, Docker/Podman, sandboxd, cloud provider access, registry
credentials, proxy listeners, firewall mutation, and real API secrets.

Tag-triggered publishing, Homebrew tap updates, sandbox image builds, optional
live suites, and operator-run live diagnostics are outside this default
package/build guard.

## Focused Guard

Run the Phase 54 command-surface guard:

```sh
go test -count=1 ./cmd -run TestPhase54
```

Then run the documented release build command:

```sh
make build
```

The expected binary surface is `./hal`; a quick local smoke check is:

```sh
./hal version
```
