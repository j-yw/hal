//go:build !linux

package vsock

import "testing"

func TestControlAndLegacyListenersFailClosedOffLinux(t *testing.T) {
	for _, listen := range []func() (Listener, error){ListenLinux, ListenLinuxControl} {
		if listener, err := listen(); listener != nil || err == nil {
			t.Fatal("non-Linux listener selected fallback")
		}
	}
}
