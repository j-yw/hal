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

HL8E issuance is intentionally later than artifact generation and is disabled
in this slice. A single ELF that happens to embed HL8Q and a generic Go runtime
syscall symbol does not prove its role identity, the complete final binary set,
or the required unique/reachable callsite graph. Consequently, even supplying
`-evidence-binary` fails closed until D4/D6 provide the final linked inputs and
D7 can bind and inspect that complete set.

The reserved future invocation is:

```sh
go run ./tools/microvm/l8/policy/generate \
  -root "$PWD" \
  -evidence-binary /absolute/path/to/final/guest-role-binary
```

The current generator always rejects that invocation and never writes
`verified-pinned-callsites.hl8e`, its digest, or the host-only tagged
expected-evidence source. Future issuance must first pin every permitted
role/binary identity and prove the documented final-binary call graph.
