//go:build linux

package firecrackerhost

import (
	"context"
	"os"
)

// Observations are private and per-client. Production uses authoritative Linux
// checks; ordinary-file tests explicitly inject ownership/peer observations.
type jailerRecoveryReconnectOps struct {
	directory func(*os.File) error
	bootID    func() (string, error)
	inspect   func(uint32) (l8RuntimeOwnerProcessObservation, error)
	connect   func(*os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error)
}

func reconnectJailerRecoverySupervisorWithOps(context.Context, *os.File, jailerRecoveryJob, jailerRecoveryReconnectOps) (*jailerRecoveryClient, error) {
	return nil, errL8RuntimeOwnerInvalid
}
