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

## Decision

The target runtime for Sandbox Runtime v2 is self-hosted microVM workers. This
ADR records that destination so future phases can align implementation work to
one runtime architecture.

The MVP is architecture and extraction first: establish ownership boundaries,
extract shared sandbox orchestration, and preserve existing behavior before any
new runtime is enabled. Phase 0 does not deliver Podman support, `sandboxd`, or
microVM implementation work.

## Consequences

To be expanded by subsequent documentation tasks.

## Phased Rollout Boundaries

To be expanded by subsequent documentation tasks.

## Compatibility Assumptions

To be expanded by subsequent documentation tasks.

## Non-Goals

To be expanded by subsequent documentation tasks.
