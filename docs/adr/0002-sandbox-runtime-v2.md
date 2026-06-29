# ADR 0002: Sandbox Runtime v2

## Status

Proposed

## Context

Sandbox Runtime v2 needs an agreed architecture boundary before any runtime
or CLI implementation begins. Phase 0 is limited to documenting that boundary
in this ADR so later phases can be reviewed against a stable decision record.

Phase 0 makes no runtime behavior changes. It also makes no production code
changes; the only intended product change in Phase 0 is this file:
`docs/adr/0002-sandbox-runtime-v2.md`.

Existing sandbox users should continue to rely on the current SSH-machine
provider behavior while Sandbox Runtime v2 is designed. The compatibility path
for this ADR is preserving those providers until a later implementation phase
introduces and verifies a replacement runtime.

## Decision

The target runtime for Sandbox Runtime v2 is self-hosted microVM workers. This
ADR records that destination so future phases can align implementation work to
one runtime architecture.

The MVP is architecture and extraction first: establish ownership boundaries,
extract shared sandbox orchestration, and preserve existing behavior before any
new runtime is enabled. Phase 0 does not deliver Podman support, `sandboxd`, or
microVM implementation work.

Normal Hal workflows remain local by default while Sandbox Runtime v2 is
designed and extracted. `hal run` remains local by default, and `hal auto`
remains local by default. Phase 0 does not introduce new default remote
execution behavior or new default sandbox execution behavior for either
workflow.

New sandbox command flags are delayed until after factory extraction. Phase 0
adds no new CLI flags for `hal run` or `hal auto`; sandbox flag design and
implementation for both commands belongs in a later phase after shared factory
and sandbox orchestration boundaries have been extracted.

Future Sandbox Runtime v2 contract changes must be additive unless a new v2
contract is introduced. Phase 0 contract work is limited to documenting this
compatibility rule in the ADR; it does not modify contract files, add a new
runtime contract, or change any existing machine-readable contract surface.

## Consequences

To be expanded by subsequent documentation tasks.

## Phased Rollout Boundaries

To be expanded by subsequent documentation tasks.

## Compatibility Assumptions

Current SSH-machine providers remain the compatibility path for existing
sandbox usage. Phase 0 does not move users, factory runs, or sandbox commands
to a new runtime, and it does not change how current providers are configured,
selected, started, reused, or inspected.

Future Sandbox Runtime v2 phases must treat existing sandbox users and provider
integrations as compatibility inputs. Any migration away from the SSH-machine
provider path requires an explicit implementation PRD, contract review where a
machine-readable surface changes, and a rollout plan that preserves current
behavior until the new runtime is intentionally enabled.

## Non-Goals

To be expanded by subsequent documentation tasks.
