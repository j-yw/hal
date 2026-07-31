//go:build !linux

package linuxrules

import (
	"errors"
	"testing"
)

func TestLinuxRulesProductionExecutorFailsClosedOffLinux(t *testing.T) {
	executor, err := NewProductionExecutor(ProductionExecutorOptions{NSenterPath: "/usr/bin/nsenter", NFTPath: "/usr/bin/nft"})
	if !errors.Is(err, ErrUnsupported) || executor != nil {
		t.Fatalf("NewProductionExecutor = (%#v, %v), want nil ErrUnsupported", executor, err)
	}
}
