//go:build linux

package firecrackerhost

import "context"

// Compiling RED scaffold only: no completion authority is issued or selected
// by production. The delegate exposes the existing premature retirement.
type minimalJailerFinalization struct{}

func (client *jailerRecoveryClient) finalizeMinimalCleanup(ctx context.Context) (*minimalJailerFinalization, error) {
	if err := client.stopAndCommit(ctx); err != nil {
		return nil, err
	}
	return nil, errL8RuntimeOwnerInvalid
}
