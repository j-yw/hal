//go:build linux && firecracker_live && network_enforcement_live && l7_linux_network_integration && l8_production_credential_delivery_live

package firecrackerhost

import "testing"

// D7 live proof is still blocked by the four unaccepted closures.
const l8D7PreparedLinuxBlocked = "dependency_unaccepted: D7 prepared-Linux remains blocked by sealed PID1 expected digests, live helper transport, durable handle store, and production L7 session factory"

func TestL8PreparedLinuxCredentialDeliveryPrerequisites(t *testing.T) {
	t.Fatal(l8D7PreparedLinuxBlocked)
}

func TestL8PreparedLinuxCredentialDeliveryE2E(t *testing.T) {
	for _, name := range []string{
		"http_only",
		"file_tmpfs_only",
		"ssh_agent_only",
		"all_modes",
		"failure_recovery_matrix",
	} {
		t.Run(name, func(t *testing.T) {
			t.Fatal(l8D7PreparedLinuxBlocked)
		})
	}
	t.Fatal(l8D7PreparedLinuxBlocked)
}
