//go:build linux

package firecrackerhost

import (
	"testing"
	"time"
)

func TestL8JobCredentialRuntimeLinuxProductionConstructorAcceptsInjectedFakes(t *testing.T) {
	now := time.Date(2026, time.August, 28, 4, 5, 6, 0, time.UTC)
	runtime, err := NewProductionL8JobCredentialRuntime(l8JobCredentialRuntimeTestDeps(t, now, nil, nil, nil, nil))
	if err != nil || runtime == nil || !runtime.production {
		t.Fatalf("NewProductionL8JobCredentialRuntime = %#v, %v", runtime, err)
	}
}

func TestL8JobCredentialRuntimeLinuxPlatformIsSupported(t *testing.T) {
	if !l8JobCredentialRuntimePlatformSupported() {
		t.Fatal("linux job credential runtime reported unsupported")
	}
	if ErrL8JobCredentialRuntimeUnsupported == nil {
		t.Fatal("unsupported sentinel missing")
	}
}
