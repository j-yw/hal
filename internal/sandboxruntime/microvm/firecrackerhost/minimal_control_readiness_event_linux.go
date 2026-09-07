//go:build linux

package firecrackerhost

import "golang.org/x/sys/unix"

// This pure observation boundary never receives, parses or owns descriptor
// rights. The later actual receiver must close every received right on error.
func decodeMinimalControlReadinessDatagram(wire, ancillary []byte, flags int) (minimalControlReadinessEventV1, error) {
	if len(ancillary) != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return minimalControlReadinessEventV1{}, errL8RuntimeOwnerProtocol
	}
	return decodeMinimalControlReadinessEvent(wire)
}
