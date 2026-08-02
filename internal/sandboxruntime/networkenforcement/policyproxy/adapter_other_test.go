//go:build !linux

package policyproxy

import (
	"errors"
	"testing"
)

func TestL6PolicyProxyNonLinuxFailsClosed(t *testing.T) {
	adapter, err := New(Config{})
	if adapter != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New = (%#v, %v), want nil ErrUnsupported", adapter, err)
	}
}
