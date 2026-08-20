//go:build !linux

package linux

import (
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

func TestNewCoreFailsClosedOffLinux(t *testing.T) {
	core, err := NewCore(CoreOptions{})
	if core != nil || !errors.Is(err, credentialhelper.ErrContractDependency) {
		t.Fatalf("NewCore() = %#v, %v, want fail-closed dependency error", core, err)
	}
}
