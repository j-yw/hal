package firecrackerhost

// A selected-only scalar snapshot, not a runtime, reservation or cleanup proof.
// DESIGN/RED: only actual validated admission may populate it in the subsequent
// implementation; no caller-provided digest constructor is introduced here.
type minimalControlRecoveryProjection struct {
	configCorrelation       string
	job                     jailerRecoveryJob
	uid, gid                uint32
	firecrackerConfigSHA256 string
}
