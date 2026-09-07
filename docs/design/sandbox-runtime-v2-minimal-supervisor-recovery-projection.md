# Minimal supervisor admission and recovery projection

## Scope and authority

DESIGN/RED foundation at `99b58782390f0805efbdaf01d4eadbb52f70bb79`.
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md), and
[accepted controller design](sandbox-runtime-v2-minimal-host-controller.md)
govern. This is one dependency of the real eight-role supervisor, not controller,
producer, network, credential, or launch completion.

The actual selected admission already validates the distinct bounded canonical
supervisor config, measured sealed assets and one-shot controller seed. It closes
the seed FD before its callback and clears the derived key afterward. However,
the callback cannot reach the admitted handles, and the existing selected store
accepts only the seven-role config. This slice supplies that concrete admission
to store handoff without making the production supervisor available.

`unavailableMinimalControlSupervisor` remains unchanged. There is no root/boot,
process, namespace, guest listener, readiness or credential acceptance here.

## Existing coupling

All paths below are under `internal/sandboxruntime/microvm/firecrackerhost/`.

- `minimal_control_config_linux.go`, `withMinimalControlSupervisorAdmission`:
  owns FD9/10 imports, validates eight distinct underlying objects, measures
  kernel/rootfs/FC config, consumes FD10, then calls the selected observer.
  The outer executable dispatcher retains ownership of the first six handles.
- `minimal_control_config.go`, `minimalControlSupervisorAdmission`: currently
  holds the decoded config, SHA256 of its complete canonical bytes, and the
  callback-scoped key. It is not a runtime or cleanup authority.
- `jailer_recovery_record.go`: seven-role encode/decode wrappers validate the
  seven discriminator and derive `configCorrelation` from that entire config.
  `SeedCorrelationDigest` is the same public config correlation in the existing
  in-memory FSM record; it is not a digest of either private key.
- `jailer_recovery_store_linux.go`: retained record reads, publication/readback
  and recovery-current checks use that seven-config value. Reservation `Config`
  and `recoveryAuthority().current` instead require the measured FC-file SHA256.
  The two digests are intentionally not interchangeable.

## Bounded proposed interface

The admission gets `borrowed [7]int`, in the same role order as the first seven
inherited descriptors: control socket, owner directory, sealed supervisor config,
kernel, rootfs, stable recovery key, sealed FC config. Values are actual retained
handles, not assumed numeric 3..9. FD10 is absent and already closed when the
callback begins. These handles may be used only during the callback; admission
and dispatcher still close them exactly once. A later runtime needing ownership
beyond that scope must separately duplicate and own the necessary CLOEXEC FDs.
This slice creates no additional descriptor, process inheritance or ownership
transfer.

A private `minimalControlRecoveryProjection` contains only immutable scalar
copies: full eight-config SHA256, exact six-field job tuple, policy UID/GID and
measured FC-file SHA256. Admission mints it only after canonical selected config,
asset and seed validation, from the bytes and values already admitted. There is
no digest-override argument, caller-config constructor, exported issuer, marker
relabeling or reconstructed opaque L7 descriptor. It retains no map, role slice,
seed/private key, FD, runtime pointer or network authority. Later mutation of the
callback's decoded config cannot change the selected projection.

The existing `jailerRecoveryStore` gets a minimal-only projection slot. Its nil
case preserves the exact current seven-role wrapper behavior. A nonnil projection
must validate its complete required scalar shape; a missing/zero selected
projection cannot fall back through an eight-role config relabeled as seven.

After separate GREEN approval, share the current record encode/decode body over
these exact validated correlations. Existing seven-role wrappers must still run
their original validator and derive their digest themselves. The selected branch
uses only the admission-issued projection. Keep the disk schema, canonical bytes,
owner field selection, job validation, reservation/terminal checks, cleanup-only
fresh-client decoder and legacy six-role record branch unchanged.

The existing store must use the same projection for genesis, write/readback,
retained reads and recovery-current checks. Full supervisor correlation enters
the record; measured FC SHA enters only reservation and coordinator currentness.
No projection is a reservation or a successful cleanup checkpoint. Preserve the
original store lock, exact retained inode, one-way consumed-temp ownership,
uncertainty poison and successor-preserving cleanup.

## Files and test boundary

Proposed production ownership is limited to `minimal_control_config.go`,
`minimal_control_config_linux.go`, new
`minimal_control_recovery_projection.go`, `jailer_recovery_record.go`, and
`jailer_recovery_store_linux.go`, plus narrowly named tests and this note.
No executable dispatcher, runtime constructor, coordinator, namespace, worker,
tool, protocol, schema-version or source-guard changes belong to this milestone.

Compiling RED may add only ignored zero-valued admission/store fields and the
private projection shape, with no behavior change. Tests use the real existing
admission fixture and actual selected store filesystem operations. They never
manufacture projection fields or replace the selected discriminator.

The intended first failures are the callback's missing borrowed handles and the
actual seven-only validator rejecting a valid selected eight-config genesis.
Later assertions for record/readback, FC currentness, reservation mismatch and
immutable projection are not claimed exercised when genesis fails first.

The frozen RED is compiling behavior, not missing-symbol scaffolding:

```sh
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^TestMinimalSupervisorRecovery'
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^Test(MinimalControlConfig|JailerRecovery(Record|StorePublication|SelectedConfig))'
```

The first command reaches four intended failing leaves (one missing borrow,
three eight-config genesis rejections), five failure events including the parent,
two passing controls and zero skips. The second is the existing adjacent
admission/config/record/publication regression set, not a selected runtime test.
The seven-role config and complete disk-record SHA256 golden values were captured
independently from the unchanged old codec/fixture before this RED seam. They
are not computed from a new paired encoder/decoder during the assertion.

GREEN gates must prove:

1. Exact seven borrowed handles remain open/CLOEXEC during callback, FD10 is
   already closed, key clearing and all descriptor cleanup remain unchanged.
2. Actual selected store genesis/readback uses SHA256 of the full eight-config
   bytes. Changing a selected-only field changes this correlation even with
   identical measured FC bytes. Wrong correlation is rejected.
3. Recovery-current and busy reservation validate the separate measured FC SHA,
   exact runtime/job and UID/GID; substituting the full config digest fails.
4. Zero/missing projection, changed job, wrong reservation and rewritten retained
   record fail closed. Callback config/map mutation cannot rewrite the snapshot.
5. Exact seven-role record bytes and wrappers are unchanged; six/seven config
   decoders still reject eight-role input. Default selected callback stays
   unavailable without creating any record or launching anything.
6. Existing store publication, poison, retained lease, terminal retry and
   successor-preservation tests remain active.

Use focused default/race tests, adjacent admission/record/store tests, vet,
Darwin compile and relevant existing source guards. Fixtures are ordinary
same-UID private files/sealed memfds/socketpairs with injected expected seed UID,
not production root or live namespace observations. No required live check is
skipped or presented as passed; none is attempted in this foundation.

## Required next dependencies

`minimal_l7_config.go` accepts an opaque live-session-issued descriptor; that
descriptor cannot cross exec. A distinct selected-only sealed projection must
compare the independently frozen NIC and six raw boot fields with the measured
FC bytes, plus exact 25-field minimal boot pins. Ordinary nil/default validation
must remain unchanged. The full-config hash alone does not prove those values
match one another or that an L7 session is current.

`l8_runtime_owner_runtime_linux.go:serveBootstrap` currently compares received
namespace handles with the accompanying packet correlation, not the sealed
minimal config's independently frozen namespace tuple. That selected comparison
must precede ownership transfer or child preparation. Do not reopen namespaces
or derive expected values from the same candidate packet.

Only after these byte/descriptor checks are accepted can a separately reviewed
runtime constructor load the stable key, create reconnect ownership and carry the
original-channel cancellation/deadline through preparation and gate release.
That later slice must preserve the immediate revision-2 reply, same surviving
manager/process, joined controller lifetime and outside-lock shutdown ordering.
Actual L7 owner loss/terminal cleanup remains a separate coupled dependency.
This foundation must not turn a recovery projection into any of that authority.
