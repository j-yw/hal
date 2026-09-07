# Selected minimal bootstrap namespace binding

DESIGN/RED checkpoint from `4f097e6c`. The actual eight-role runtime consumer
remains unavailable. This is not a root supervisor, live L7 or VM acceptance.

The current `serveBootstrap` checks peer UID, packet role, two actual nsfs
descriptors, their distinct device/inode tuples and the tuple in the packet.
It does not compare them to the independent sealed eight-role public namespace
pins, or require the first descriptor to be a user namespace and the second a
network namespace. Thus internally consistent packet/descriptor substitutions
can reach namespace ownership, genesis persistence and the child callback.

## Compiling RED boundary

Only a private no-op `bindMinimalControlNamespaces(owned, admission)` seam is
added. It represents the later constructor's handoff, does not modify the
receiver, and is not called by the unavailable production runtime consumer.
Tests call it inside actual eight-role admission, then call the actual existing
`serveBootstrap` over unnamed Unix seqpacket sockets with real SCM_RIGHTS.

The candidate handles are opened read-only from the current process's user,
network or mount namespace. The fixture independently verifies their real
namespace kind and generic nsfs tuple prerequisites. It never creates or enters
a namespace. Store and child callbacks use the existing fake FSM store/counters;
only the ordinary same-UID socket receiver is real. Root-only constructor gates
remain unchanged. Every sender-owned handle is checked after receipt.

Required REDs are four independent sealed-tuple mismatches, a mount namespace
substituted into either otherwise matching role, and an eight-role store with
the binding handoff omitted. Matching, immutable-snapshot and absent-option
six/seven receiver controls execute separately. No required gate may skip.

The actual RED run with race detection repeated three times has 24 failing
test/subtest events (seven mismatches plus their parent per run), 18 control
passes and zero skips. Every mismatch reached one child start, one gate release,
three fake-store events and actual received-FD transfer. The decoded-mutation
control presently proves fixture validity only; the no-op binder does not yet
implement snapshot capture or namespace validation.

## Proposed minimal GREEN

Mint a private scalar namespace projection inline during actual eight-role
admission, alongside the existing recovery projection. Copy the full canonical
config correlation and four namespace numbers; never derive them from the
candidate packet, later decoded-config mutations, paths or a reconstructed L7
descriptor. The private binding seam copies that admission-owned projection
into the existing runtime after checking the independent recovery/genesis
correlation. It creates no runtime authority or listener.

In `serveBootstrap`, after existing generic FD validation and before taking
ownership or entering the FSM, apply the selected check. An actual eight-role
store/runtime with missing or zero projection must fail closed; testing only
whether the optional pointer is nonnil is insufficient. Require the exact
full-config correlation, nonzero distinct sealed tuple, packet/actual-FD tuple
equality, and `NS_GET_NSTYPE` equal to `CLONE_NEWUSER`, then `CLONE_NEWNET`.
Unsupported ioctl or any uncertainty rejects. Existing pre-transfer cleanup
owns rejected received FDs; do not close sender handles or introduce another
descriptor-ownership framework. Six/seven branches without this selection
remain unchanged.

After the first GREEN, cover malformed/missing/duplicate/swapped FDs, repeated
bootstrap, rejected-copy closure, successor/sender protection, missing/replaced
projection and full-config mismatch. Preserve exact immutable RED assertions.

Expected production ownership: dedicated namespace projection/validator files,
the small admission capture, the private admission/runtime projection fields,
and the single pre-transfer `serveBootstrap` check. No controller, protocol,
guest, coordinator, producer, privilege setup or live network changes.

The later eight-role runtime constructor must call the binding seam. These
tests do not implement that constructor or establish that its L7 owner remains
current. The producer must still retain the actual L7 session and the exact
namespace duplicates, and teardown must verify its own resources.

```sh
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControlNamespaces'
```
