package firecrackerhost

// This value is decoded public metadata, never current readiness authority.
// The compiling RED leaves both codec operations unavailable.
type minimalControlReadinessEventV1 struct {
	configSHA256           [32]byte
	supervisorGeneration   string
	processGeneration      string
	transportGeneration    uint64
	sessionID              [32]byte
	readinessBindingSHA256 [32]byte
}

func encodeMinimalControlReadinessEvent(minimalControlReadinessEventV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerProtocol
}

func decodeMinimalControlReadinessEvent([]byte) (minimalControlReadinessEventV1, error) {
	return minimalControlReadinessEventV1{}, errL8RuntimeOwnerProtocol
}
