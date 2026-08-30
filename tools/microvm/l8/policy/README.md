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
target is followed, and a relative CALL/JMP into a listed `STT_FUNC` /
pclntab span is that known function (including ABI0 interiors such as
`runtime.duffcopy`, `runtime.duffzero`, and `indexbytebody`). Proven
canonical RIP-relative `JMP [base+index*8]` kind-switch tables with an
unskippable AND or 64-bit CMP/forward-JA length, a unique non-writable
mapping, and listed-span entries are known targets. Stack stores,
`TEST`, and `BT` that do not write `base`/`index` may sit between the
length fact and dispatch; `0F BA /4 ib` has an imm8 length. Indexed
indirect CALL, branch-skipped facts, ambiguous symbols, truncated
transfers, and unproven register-indirect `CALL`/`JMP` fail closed.
Register-indirect `CALL`/`JMP` (`FF D0`/`FF D1`/`FF D6` and other
ModRM.mod=3 forms) is a known target set only when every destination is
a listed function **start** whose address appears as an 8-byte pointer
in `.noptrdata`, `.data`, or `.itablink`. Scanning `.gopclntab`,
`.rodata`, or `PF_X` contents, or attaching every pclntab function, is
forbidden because that re-reaches trampolines such as
`syscall.rawVforkSyscall.abi0`. 64-bit VEX/EVEX opcodes `C4`/`C5`/`62`
fail decode; a non-entry body without `syscall`/`sysenter`/`int80`
bytes is a non-syscall leaf. A relative transfer into unlisted
executable text stays unbounded. Prefix is not authority and
`runtime.*` is not a target set. Pinned-direct allow is only
`internal/runtime/syscall.Syscall6` plus `0f05` at offset 12. Named Go
PID1 extras are explicit D7 `runtimeEnvelope` / launch-base origin-3
rows, not prefix membership. Named native `_start` identity-preflight
plus PID1 listen-table, launch-base seccomp, clone3, execveat, and recvmsg
extras are explicit D7 `nativeEnvelope` / launch-bootstrap origin-1 rows,
used only for the native bootstrap binary. Prefix is not authority. Reachable
`syscall.rawSyscallNoError.abi0` and `syscall.rawVforkSyscall.abi0`
CALL/JMP sites recover the linux/amd64 trap/number from the direct
caller's `MOVQ $imm` into the trap slot or AX; catalog-listed names
are not extras, unlisted names remain extras, and unproven numbers
stay `unknown:symbol`. Go `clone` and `clone3` remain extras because they
are process-creation/shim authority without exact argument templates in
the Go runtime envelope. Native `_start` catalogs `clone3`, `execveat`, and
`recvmsg` for the bootstrap binary only. Launch-base allows exact
`execveat` of PID1-held FDs 5 and 6 with `AT_EMPTY_PATH` and envp NULL;
it does not allow unrestricted `execve`/`execveat` or `sendmsg`/`recvmsg`
by catalog name: classic seccomp cannot see pathname bytes or SCM_RIGHTS
fd contents. Pathname `execve` is no longer a native `_start` site.
Controller and agent have no PID1-held sealed executable FD in the frozen
image-init plan; rbx 0/1 clone3 children FAIL CLOSED before execveat as
the remaining admission gap. Launch-base does not extend ScalarOneOf
beyond `{5, 6}` and does not allow-all execveat.
`runtime.reviewerAuthority` is extra if reachable with an unlisted
named syscall. A singular ELF that happens to embed HL8Q
and a generic Go runtime syscall symbol does not prove its role identity
or the complete final binary set. Missing helper, monitor, or shim role
binaries fail closed. Consequently, even supplying `-evidence-binary` or
a complete binaries dir fails closed while extra reachable syscalls or
unproven register-indirect CALL remain.

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
