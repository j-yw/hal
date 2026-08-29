# L8 syscall-policy generation

`roles-v1.yaml` and the three lock files are the reviewed, bounded inputs for
the D7 syscall-policy artifact. The generator validates the pinned Go 1.25.7
runtime source and x/sys v0.41.0 catalog source before producing any authority.

Run the artifact-only verification gate from the repository root:

```sh
tools/microvm/l8/policy/verify-artifact.sh
```

The gate builds the generator twice with Go 1.25.7, requires byte-identical
executables, checks the independently locked generator digest, regenerates the
HL8Q outputs in memory, and verifies the checked-in bytes through the D2
importer. Untagged builds remain fail closed.

HL8E is issued from the unique/reachable D4/D6 callsite graph of the complete
linux/amd64 guest role set. The generator inspects ELFs and requires
`-evidence-binaries-dir`. A single ELF that happens to embed HL8Q and a generic
Go runtime syscall symbol does not prove its role identity, the complete final
binary set, or the required unique/reachable callsite graph. Missing helper,
monitor, or shim role binaries fail closed. Unrelated or generic binaries fail
closed. Extra decoded `syscall` sites must classify as non-authority / not the
pinned-direct path; unclassified sites fail closed.

Issue from the complete final guest role binaries:

```sh
go run ./tools/microvm/l8/policy/generate \
  -root "$PWD" \
  -evidence-binaries-dir /absolute/path/to/final/guest-role-binaries
```

That invocation writes `verified-pinned-callsites.hl8e`, its digest, and the
host-only tagged expected-evidence source after the inspector hashes every
role binary, proves `internal/runtime/syscall.Syscall6` at offset 12 equals
source-derived `0f05`, and classifies the unique/reachable callsite graph.
D7 live remains disabled.
