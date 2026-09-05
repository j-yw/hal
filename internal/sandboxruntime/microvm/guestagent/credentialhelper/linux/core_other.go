//go:build !linux

package linux

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"

// NewCore fails closed away from Linux without inspecting or retaining the
// configured dependency.
func NewCore(CoreOptions) (credentialhelper.Core, error) {
	return nil, credentialhelper.ErrContractDependency
}
