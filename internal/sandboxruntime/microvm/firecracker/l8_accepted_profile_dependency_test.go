//go:build l8_d6_live_firecracker_overlay

package firecracker

import "testing"

func TestL8LiveBootConfigAcceptedAuthorityDependencyGate(t *testing.T) {
	t.Fatal("dependency_unaccepted: truthful D7 HL8E and accepted VerifiedL8Profile/VerifiedL8AssetLease fixture are required")
}
