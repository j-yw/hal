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

HL8E issuance is intentionally later than artifact generation. After D4/D6
produce a final Go 1.25.7 guest role binary that actually embeds the exact
generated HL8Q, run:

```sh
go run ./tools/microvm/l8/policy/generate \
  -root "$PWD" \
  -evidence-binary /absolute/path/to/final/guest-role-binary
```

The issuer rejects an unlinked artifact, the wrong Go version, a non-amd64 ELF,
missing or ambiguous symbols, source/template drift, and instruction offsets
outside the exact symbol or executable text. Only a successful inspection
writes `verified-pinned-callsites.hl8e`, its digest, and the host-only tagged
expected-evidence source.
