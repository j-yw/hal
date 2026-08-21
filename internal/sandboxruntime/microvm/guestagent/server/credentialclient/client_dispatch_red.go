package credentialclient

import (
	"context"
	"errors"
)

var ErrClientDispatchDependencyUnaccepted = errors.New("credential client dispatcher dependency is unaccepted")

// serveCredentialLifecycle is the sole future persistent control/helper
// dispatcher. The RED contract freezes its ownership under Client.Serve; no
// operation, proof, or cleanup behavior is implemented in this candidate.
func (client *Client) serveCredentialLifecycle(context.Context) error {
	return ErrClientDispatchDependencyUnaccepted
}
