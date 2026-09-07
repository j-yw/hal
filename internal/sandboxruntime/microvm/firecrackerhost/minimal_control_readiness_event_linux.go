//go:build linux

package firecrackerhost

// This pure observation boundary never receives, parses or owns descriptor
// rights. The later actual receiver must close every received right on error.
func decodeMinimalControlReadinessDatagram(wire, ancillary []byte, flags int) (minimalControlReadinessEventV1, error) {
	return minimalControlReadinessEventV1{}, errL8RuntimeOwnerProtocol
}
