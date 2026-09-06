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
	const minimumParentAPI = `
credentialclient.ExtensionPacket.Type() credentialprotocol.PacketType
credentialclient.ExtensionPacket.SSHAccepted() (credentialclient.SSHAcceptedPacket, bool)
credentialclient.SSHAcceptedPacket accessors: Revision, BindingIndex, Ordinal, CapabilitySHA256, Connection
credentialclient.SSHConnectionCapability methods: SHA256, Read, Write, Shutdown, Close
credentialclient.NewSSHIOResult and the closed SSHShutdownDirection catalog
parent-owned clientOwned -> transferred -> closing -> closed shared ownership state`
	for _, method := range []string{"Type", "SSHAccepted"} {
		if _, ok := packet.MethodByName(method); !ok {
			t.Errorf("credentialclient.ExtensionPacket is missing %s; minimum required seam:%s", method, minimumParentAPI)
		}
	}
}
