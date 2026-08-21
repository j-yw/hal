//go:build !linux

package firecrackerhost

import (
	"errors"
	"testing"
)

func TestL8RuntimeOwnerNonLinuxFoundationFailsClosed(t *testing.T) {
	if l8RuntimeOwnerPlatformSupported() {
		t.Fatal("non-Linux runtime-owner foundation reported support")
	}
	if value, err := readL8RuntimeOwnerHostBootID(); value != "" || !errors.Is(err, errL8RuntimeOwnerUnsupported) {
		t.Fatalf("read host boot ID = %q, %v", value, err)
	}
	if value, err := inspectL8RuntimeOwnerProcess(1); value != (l8RuntimeOwnerProcessObservation{}) || !errors.Is(err, errL8RuntimeOwnerUnsupported) {
		t.Fatalf("inspect process = %#v, %v", value, err)
	}
	seed := l8RuntimeOwnerTestSeed()
	if err := writeL8RuntimeOwnerRecord("/unsupported", firecrackerRuntimeOwnerRecordV1{}, seed, "boot"); !errors.Is(err, errL8RuntimeOwnerUnsupported) {
		t.Fatalf("write record = %v", err)
	}
	if value, err := readL8RuntimeOwnerRecord("/unsupported", seed, "boot"); value != (firecrackerRuntimeOwnerRecordV1{}) || !errors.Is(err, errL8RuntimeOwnerUnsupported) {
		t.Fatalf("read record = %#v, %v", value, err)
	}
}
