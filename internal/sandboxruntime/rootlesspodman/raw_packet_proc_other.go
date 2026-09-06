//go:build !linux

package rootlesspodman

import "context"

type unsupportedRawPacketProcessInspector struct{}

func defaultRawPacketProcessInspector() RawPacketProcessInspector {
	return unsupportedRawPacketProcessInspector{}
}

func (unsupportedRawPacketProcessInspector) VerifyRawPacketProcess(context.Context, int, int64) error {
	return ErrRawPacketIsolationUnverified
}
