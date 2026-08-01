//go:build !linux

package firecracker

import "testing"

func TestL7SealedLaunchMaterialFailsClosedOffLinux(t *testing.T) {
	material, err := newSealedL7LaunchMaterial("/state")
	if err == nil || material != nil {
		t.Fatalf("newSealedL7LaunchMaterial() = %#v, %v; want fail-closed unsupported result", material, err)
	}
}
