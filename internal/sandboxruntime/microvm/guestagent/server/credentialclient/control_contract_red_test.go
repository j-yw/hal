package credentialclient

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D6GuestControlContractHasNoSocketCreationAuthority(t *testing.T) {
	source, err := os.ReadFile("control_contract_red.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"net"`, `"os"`, `"syscall"`, `"golang.org/x/sys/unix"`,
		"net.Listen(", "ListenConfig", "unix.Bind(", "syscall.Bind(", "unix.Socket(", "os.NewFile(",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("guest control contract contains forbidden socket authority %q", forbidden)
		}
	}
}

func TestL8D6GuestControlOwnerIsVerifiedPreopenedAndFixedPort(t *testing.T) {
	owner := reflect.TypeOf((*ControlConnectionOwner)(nil)).Elem()
	if owner.NumMethod() != 2 || owner.Method(0).Name != "AcceptVerified" || owner.Method(1).Name != "Close" {
		t.Fatalf("ControlConnectionOwner methods = %v, want exact AcceptVerified/Close", owner)
	}
	stream := reflect.TypeOf((*VerifiedControlStream)(nil)).Elem()
	for _, forbidden := range []string{"Bind", "Listen", "Dial", "Accept"} {
		if _, ok := stream.MethodByName(forbidden); ok {
			t.Fatalf("VerifiedControlStream exposes forbidden %s authority", forbidden)
		}
	}

	identity := testControlSessionIdentity()
	expectation, err := NewControlAcceptExpectation(identity)
	if err != nil {
		t.Fatalf("NewControlAcceptExpectation() error = %v", err)
	}
	if expectation.Identity() != identity || expectation.Identity().GuestPort != session.ControlPort {
		t.Fatal("control accept expectation did not pin exact port-1025 identity")
	}
}

func TestL8D6GuestTransportIdentityIsImmutableAndFullyCorrelated(t *testing.T) {
	identity := testControlSessionIdentity()
	var sessionID [32]byte
	sessionID[0] = 1
	hardExpiry := time.Unix(1_700_000_000, 0).UTC()
	transportIdentity, err := NewTransportIdentity(sessionID, identity, hardExpiry, "helper-generation-1")
	if err != nil {
		t.Fatalf("NewTransportIdentity() error = %v", err)
	}
	if transportIdentity.SessionID() != sessionID || transportIdentity.SessionIdentity() != identity ||
		!transportIdentity.HardExpiry().Equal(hardExpiry) || transportIdentity.HelperGeneration() != credentialprotocol.SafeID("helper-generation-1") {
		t.Fatal("authenticated transport identity lost correlation")
	}
}

func TestL8D6GuestControllerUnionConsumesOneExactReceiveRequest(t *testing.T) {
	identity := testControlSessionIdentity()
	var sessionID [32]byte
	sessionID[0] = 1
	requestID, err := v2control.NewRequestID([16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := v2control.NewReadinessRequest(requestID, v2control.NewIdentityDigest(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	receive, err := NewControllerReceiveRequest(1, v2control.NewIdentityDigest(sessionID), false, session.MaxControlPlaintextBytes)
	if err != nil {
		t.Fatalf("NewControllerReceiveRequest() error = %v", err)
	}
	packet, err := NewControllerReadinessPacket(receive, 1, sessionID, readiness)
	if err != nil {
		t.Fatalf("NewControllerReadinessPacket() error = %v", err)
	}
	arm, ok := packet.Readiness()
	if !ok || arm.RequestID() != requestID || packet.Sequence() != 1 || packet.SessionID() != sessionID || identity.GuestPort != session.ControlPort {
		t.Fatal("controller packet did not retain exact typed ownership")
	}
	if _, err := NewControllerReadinessPacket(receive, 1, sessionID, readiness); err == nil {
		t.Fatal("receive request was consumed twice")
	}
}

func TestL8D6GuestPacketUnionsFreezeCompletePrivateOwnership(t *testing.T) {
	assertPrivateFields(t, ControllerReceiveRequest{}, "liveValue", "nextSequence", "expectedIdentity", "expectedIdentitySet", "maximumPlaintextBytes", "state")
	assertPrivateFields(t, ControllerPacket{}, "liveValue", "sequence", "sessionID", "arm", "body")
	assertPrivateFields(t, ControllerSendPacket{}, "liveValue", "sequence", "sessionID", "arm", "encodedBodyLength", "bodySHA256", "state")
	assertPrivateFields(t, HelperReceiveRequest{}, "liveValue", "nextSequence", "maximumBodyBytes", "maximumRights", "expectedRequestID", "expectedRequestIDSet", "expectedIdentity", "state")
	assertPrivateFields(t, HelperPacket{}, "liveValue", "header", "arm", "body", "right")
	assertPrivateFields(t, HelperSendPacket{}, "liveValue", "header", "arm", "encodedBodyLength", "bodySHA256", "state")
	assertPrivateFields(t, helperSendArm{}, "kind", "prepareBegin", "prepareFile", "prepareCommit", "renew", "revoke", "exec", "execPrivate", "execStream", "execCredit", "close")

	for _, value := range []any{ControlAcceptExpectation{}, TransportIdentity{}} {
		assertFailsClosed(t, value)
	}
}

func assertPrivateFields(t *testing.T, value any, expected ...string) {
	t.Helper()
	typeOf := reflect.TypeOf(value)
	if typeOf.NumField() != len(expected) {
		t.Fatalf("%s field count = %d, want %d", typeOf.Name(), typeOf.NumField(), len(expected))
	}
	for index, name := range expected {
		field := typeOf.Field(index)
		if field.Name != name || field.PkgPath == "" {
			t.Fatalf("%s field %d = %#v, want private %q", typeOf.Name(), index, field, name)
		}
	}
}

func testControlSessionIdentity() session.Identity {
	var nonce, image [32]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
		image[index] = byte(index + 33)
	}
	return session.Identity{
		Channel:                      session.ChannelControl,
		GuestBootNonce:               nonce,
		GuestCID:                     session.GuestCID,
		GuestPort:                    session.ControlPort,
		ControllerKeyGeneration:      "controller-key-generation-1",
		RuntimeID:                    "runtime-1",
		RuntimeGeneration:            "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1",
		VsockGeneration:              "vsock-generation-1",
		BootGeneration:               "boot-generation-1",
		ImageGeneration:              "image-generation-1",
		ImageSHA256:                  image,
	}
}
