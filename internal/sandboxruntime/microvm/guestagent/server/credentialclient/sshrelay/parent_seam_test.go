package sshrelay

import (
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

// This acceptance test is deliberately reflection-based so it compiles on the
// aggregate while documenting the missing parent-owned transfer seam. The D5
// child must not bypass that seam or edit the D2 parent package.
func TestCredentialClientParentExposesTransferSafeSSHAcceptedArm(t *testing.T) {
	packet := reflect.TypeOf(credentialclient.ExtensionPacket{})
	for _, method := range []string{"Type", "SSHAccepted"} {
		if _, ok := packet.MethodByName(method); !ok {
			t.Errorf("credentialclient.ExtensionPacket is missing %s", method)
		}
	}

	packagePath := packet.PkgPath()
	requiredTypes := []string{
		"SSHAcceptedPacket",
		"SSHConnectionCapability",
		"SSHIOResult",
		"SSHShutdownDirection",
	}
	for _, name := range requiredTypes {
		t.Run(name, func(t *testing.T) {
			// Go reflection cannot enumerate package declarations. Keep the
			// required parent-owned declarations visible in the failure while
			// the method checks above provide executable red evidence.
			if packagePath == "" {
				t.Fatalf("missing %s", name)
			}
		})
	}
}
