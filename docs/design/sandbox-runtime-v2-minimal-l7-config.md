# Selected minimal Jailer L7 config mapping

## Status and scope

This is a DESIGN/RED checkpoint based on `de9518fb`. It refines the Linux
completion architecture and selected L8 minimal contract reset without changing
L7 enforcement, legacy image authority, or runtime selection. The only
production delta in RED is an ignored private expectation field on
`strictJailerCoordinatorRequest`; the existing validator is unchanged.

The selected Jailer schema currently rejects every `network-interfaces` key,
including an empty array. L7 already owns a descriptor for the exact prepared
TAP and guest boot mapping. The next GREEN slice will consume that descriptor
for private config validation and rendering, not create another network
manager or claim that config intent establishes live enforcement.

## Inputs, outputs, and trust boundary

The private `minimalL7ConfigExpectation` contains:

- the opaque `l7network.LaunchDescriptor` returned by the actual retained
  session's `LaunchDescriptor(expectedIdentity)`;
- the independently selected runtime generation; and
- the independently selected topology generation.

The expected generations must not be copied from candidate JSON or inferred
from interface names. `LaunchDescriptor.ProofGenerations` must match both.
Zero/unissued descriptors fail. The full ten-field L7 identity is checked when
the same session issues the descriptor; its accessors expose only two of those
identity fields. This pure mapper cannot independently establish the remaining
identity or the source of the caller's selected expectations.

The later owner must correlate sandbox, execution, worker, and runtime
generation with the selected J job, preserving its separate host ID and runtime
ID. Runtime ID is not a substitute for runtime generation. All plan, policy,
proxy, topology, and rule identities come from the existing trusted L7 intent.

| Config output | Exact descriptor source |
|---|---|
| One `network-interfaces` entry | `NetworkInterface()` |
| `iface_id` | Fixed `net1` |
| `host_dev_name`, `guest_mac` | Retained session's TAP name and MAC |
| `hal_l7_net_if` | Fixed `eth0` from `StaticNetwork()` |
| `hal_l7_ipv4`, `hal_l7_ipv4_gateway` | Descriptor IPv4 address/prefix and gateway |
| `hal_l7_ipv6`, `hal_l7_ipv6_gateway` | Descriptor IPv6 address/prefix and gateway |
| `hal_l7_proxy` | Descriptor's canonical public proxy URL |

GREEN will add only these four JSON keys to strict parsing:
`network-interfaces`, `iface_id`, `host_dev_name`, `guest_mac`. A selected
expectation requires exactly one complete object with all three values equal
to the descriptor. Without an expectation, any presence of the network field
remains rejected, including `null` or an empty array. Presence must therefore
not be inferred only from decoded slice length.

Preserve bounded exact-size/hash decoding, one JSON document, canonical names,
unknown-field rejection, duplicate rejection, and all current resource/path,
device, mode, and cgroup checks. Reject selected mismatches before any identity,
cgroup, filesystem, process, or namespace operation. Errors keep the existing
sanitized config category; do not append raw addresses, interfaces, or args.

## Boot composition and package boundary

The new private mapper belongs in `firecrackerhost/minimal_l7_config*.go`. It
will derive the six-field L7 boot fragment and exact NIC object from the opaque
descriptor, validate the guest mapping through `guestnetwork.ParseBootCommandLine`,
and leave inputs unchanged. Selected validation must reject missing, partial,
duplicate, unknown, or substituted L7 settings rather than repair candidate
values by normalization.

The selected prelaunch constructor, owned by a separate slice, supplies its
trusted base boot arguments. Compose those with this exact L7 fragment before
calling `minimalcontrol.RenderBootCommandLine` to append the minimal public
pins. The complete rendered command line must fit 4095 bytes, reserving one
byte for Linux's `/proc/cmdline` newline. Both guest parsers consume the same
bounded whole line. Test the final combined renderer, not just fragment size.

Do not call the legacy full `firecracker` network renderer with manufactured
L7/L8 asset proof: it accepts different verified image authorities. Its current
L7-only 1024-byte budget, fixed base boot arguments, legacy paths, and tests
remain untouched. No PID1, guest parser, selected runtime constructor, producer,
supervisor schema, or seven-FD protocol change is part of this slice.

## Snapshot versus retained lifetime

`LaunchDescriptor` is an immutable snapshot, not a revocable live authority.
Its accessors do not recheck session state after issuance. Never serialize it
as proof or retain its raw values as a substitute for the actual L7 owner.

The later selected owner must retain the same `l7network.Session` and obtain
`ProcessNamespace(expectedIdentity)` from it. That opaque wrapper rechecks
the session while duplicating namespace files. Current selected J recovery
passes raw namespace FDs only; this mapper does not solve that lifetime gap.

The later owner slice must correlate proxy/topology loss with quarantine and
actual J termination, retain cleanup/retry authority through owner/reconnect
failures, and use `CleanupAfterVMQuiesced` only with actual termination proof.
An old descriptor, a namespace FD, or a successful config check cannot justify
active L7 metadata or combined terminal success. Guest raw-packet inspection
also needs a selected authenticated guest binding: the existing production L7
verifier is tied to the legacy `ProductionVsockBridge` and is not automatically
reusable as minimal-control evidence.

## RED evidence and next GREEN gates

The committed tests exercise the existing validator, not absent API symbols:

1. Exact descriptor-derived selected NIC and six valid boot fields are rejected
   today, for both IPv4 and IPv6 public proxy mappings.
2. Selecting that expectation while omitting the NIC is accepted today.
3. Without an expectation, descriptor NIC, `null`, and empty array remain
   rejected; legacy no-network config remains accepted.

The descriptor is issued by the real L7 coordinator using existing injected
proxy/topology/rule boundaries and `NewLinuxTAP` with an in-memory command
boundary. Only the private journal uses ordinary temporary files. Namespace
duplication, guest inspection, and VM inspection panic if reached. Cleanup
aborts the fake pre-VM session and waits for its loss watcher. No external CLI,
real namespace, firewall, TAP, socket, VM, or network is used.

These REDs do not yet test a production mapper, the combined minimal boot
renderer, or late session revocation. GREEN must add focused negatives for
zero descriptor; independently mismatched generations; changed interface/TAP/MAC;
missing/null/empty/multiple NICs; wrong JSON types, aliases, duplicate/unknown
keys; altered/partial/duplicate/unknown boot fields; combined budget boundary
and overflow; and unchanged caller inputs. Keep legacy rejection controls and
prove failures occur before the coordinator's host dependencies.

Focused commands (Linux ordinary tests, no external CLI dependencies):

```sh
go test -p 2 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalL7Config' -count=1
go test -p 2 -race ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(MinimalL7ConfigUnselected|StrictJailerCoordinator)' -count=3
go test -p 2 -race ./internal/sandboxruntime/microvm/firecrackerhost/l7network -run '^TestFirecrackerHostTopology(LaunchHandoff|Namespace)' -count=3
```

After GREEN, repeat relevant legacy renderer, guest network, minimal bootstrap,
coordinator, race, vet, and cross-platform compile gates. Main owns integrated
broad QA. Neither this checkpoint nor GREEN can claim guest boot, live network
enforcement, credentials, guest seccomp, HL8E issuance, or strict readiness.
