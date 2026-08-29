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

HL8E issuance is still disabled. The generator inspects linux/amd64 ELFs
and prefers a complete `-evidence-binaries-dir` over a singular
`-evidence-binary`. Authority is an entry-point plus call-edge reachable
graph from `main.main` or `_start`, not `runtime.*` / `syscall.*` prefix
classification. Pclntab spans are authoritative, every relative branch
target is followed, and ambiguous symbols, truncated transfers, and
indirect control flow fail closed. Pinned-direct allow is only
`internal/runtime/syscall.Syscall6` plus `0f05` at offset 12. Reachable
extra syscalls fail closed with named reasons (`futex`, `mmap`,
`exit_group`, native `getuid`/`exit_group`, and the rest documented in
the reachable-graph design). A singular ELF that happens to embed HL8Q
and a generic Go runtime syscall symbol does not prove its role identity
or the complete final binary set. Missing helper, monitor, or shim role
binaries fail closed. Consequently, even supplying `-evidence-binary` or
a complete binaries dir fails closed while extra reachable syscalls
remain.

The reserved future invocation is:

```sh
go run ./tools/microvm/l8/policy/generate \
  -root "$PWD" \
  -evidence-binaries-dir /absolute/path/to/final/guest-role-binaries
```

The current generator always rejects that invocation and never writes
`verified-pinned-callsites.hl8e`, its digest, or the host-only tagged
expected-evidence source. Future issuance must first pin every permitted
role/binary identity and prove the documented final-binary call graph.
