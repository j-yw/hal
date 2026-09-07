package firecrackerhost

// A selected-only scalar snapshot, not a runtime, reservation or cleanup proof.
// Only actual validated eight-role admission populates this distinct type.
// Sharing the private codec's scalar shape does not supply an alternate issuer
// or a constructor accepting a caller-provided correlation digest.
type minimalControlRecoveryProjection jailerRecoveryRecordBinding
