# Selected minimal Firecracker config equality

This bounded slice follows the accepted selected admission/recovery projection
at `ed32e3745d2614c81e1d46a66fc658af4cb508f8` and the
[host controller design](sandbox-runtime-v2-minimal-host-controller.md).
It binds independently sealed public settings to the separately measured
Firecracker config. It does not activate the unavailable runtime consumer.

## RED checkpoint

The real private eight-role admission fixture uses ordinary sealed memfds,
an unnamed Unix socketpair and an injected current-user seed UID. Each of 33
inconsistency cases first proves that the existing pure config decoder, asset
identity/hash/seal checks, strict Firecracker JSON parser and actual seed
loader accept its inputs. The retained Firecracker bytes and asset descriptor
remain unchanged. Current admission nevertheless reaches the callback.

Cases cover two variable NIC fields, four valid static network variations,
controller public key/key generation/nonce, and all 24 variable members of the
25-field prelaunch tuple. The public-key case installs a matching new seed;
job-correlated fields change coherently, and the image-digest case measures a
new sealed rootfs. None relies on a pre-existing rejection. The fixed driver,
interface ID and guest interface have separate existing rejection controls.
Matching admission checks input immutability and borrowed FD offset retention;
existing six/seven-role, child-gate and unavailable-consumer controls remain.

## Approved GREEN boundary, not implemented by this checkpoint

After existing sealed asset checks and before seed consumption, bound the
Firecracker config to `1..maxStrictJailerConfigBytes` (1 MiB), read exactly those
retained FD9 bytes with positional reads, and pass an owned byte reader plus
the independently recorded size/digest to `readStrictJailerConfig`. Do not wrap,
close, seek or reopen the borrowed descriptor. Preserve the current seed
consumption, key wiping, borrowed-handle and selected-store contracts.

Extract only the pure NIC/exact raw six-field comparison from the accepted L7
mapper. Keep its absent-expectation behavior and opaque descriptor/generation
validation unchanged. Render expected minimal boot settings from the sealed
Control/Job/rootfs pins through the existing guest renderer; parse expected
and actual boot settings with the existing guest parser and compare their
opaque `BootConfig` values. This reuses the canonical 25-field binding digest,
public-key/nonce validation and combined 4095-byte plus proc-newline budget.
Unrelated console arguments remain valid; raw L7 IPv6/proxy spellings must
match exactly, not merely normalize to the same value.

This is equality of validated bytes, not independently current L7 authority.
Actual SCM namespace correlation, surviving L7 ownership/cleanup, strict
coordinator path/vsock semantics, runtime construction and controller/readiness
remain separate dependencies. No schema, public API, credentials, guest boot,
VM, namespace, enforcement or cleanup acceptance is claimed here.

Focused checkpoint command (the mismatch test is intentionally RED):

```sh
go test -p 2 -count=1 -json ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControl(FirecrackerConfig|Config(LegacyAndGateSentinels|UnavailableRuntimeRemainsClosed))'
```
