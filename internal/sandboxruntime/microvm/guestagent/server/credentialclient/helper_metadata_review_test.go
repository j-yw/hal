package credentialclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D7GuestHelperFilePrepareNeverInventsSecondControllerPrepare(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	var receives atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		sequence := receives.Add(1)
		return ControllerPacket{
			sequence:  uint64(sequence),
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}

	err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want file payload dependency unaccepted", err)
	}
	if receives.Load() != 1 {
		t.Fatalf("controller receives = %d, want one logical prepare request", receives.Load())
	}
	packets := decodeHelperDatagrams(t, stream.bytes())
	if len(packets) != 1 || packets[0].header.Type != credentialprotocol.PacketTypePrepareBegin {
		t.Fatalf("file prepare helper packets = %#v, want prepare-begin only", packets)
	}
}

func TestL8D7GuestHelperMetadataOnlyPrepareCommitsSameControllerRequest(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	var receives atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		if receives.Add(1) != 1 {
			return ControllerPacket{}, errors.New("same prepare transaction requested another controller packet")
		}
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}

	err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want helper response dependency unaccepted", err)
	}
	if receives.Load() != 1 {
		t.Fatalf("controller receives = %d, want one logical prepare request", receives.Load())
	}
	packets := decodeHelperDatagrams(t, stream.bytes())
	if len(packets) != 2 {
		t.Fatalf("metadata-only prepare helper packets = %d, want begin plus commit", len(packets))
	}
	requestID := prepare.RequestID().Bytes()
	for index, packet := range packets {
		if packet.header.RequestID != requestID || packet.header.Sequence != uint64(index+1) {
			t.Fatalf("helper packet %d header = %#v", index, packet.header)
		}
	}
	if packets[0].header.Type != credentialprotocol.PacketTypePrepareBegin || packets[1].header.Type != credentialprotocol.PacketTypePrepareCommit {
		t.Fatalf("metadata-only prepare helper packet types = %s/%s", packets[0].header.Type, packets[1].header.Type)
	}
}

func TestL8D7GuestHelperExecPrivateDigestUsesExactFrozenSpelling(t *testing.T) {
	empty := sha256.Sum256(nil)
	emptyHex := strings.Repeat("0", 0) + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got, err := helperExecPrivateDigestFromControl(0, emptyHex); err != nil || got != ([32]byte{}) {
		t.Fatalf("empty private digest = %x, %v", got, err)
	}
	if _, err := helperExecPrivateDigestFromControl(0, strings.Repeat("0", 64)); !errors.Is(err, errInvalidHelperSendPacket) {
		t.Fatalf("wrong empty digest error = %v", err)
	}
	if _, err := helperExecPrivateDigestFromControl(1, strings.ToUpper(emptyHex)); !errors.Is(err, errInvalidHelperSendPacket) {
		t.Fatalf("uppercase private digest error = %v", err)
	}
	if empty != sha256.Sum256(nil) {
		t.Fatal("empty digest fixture changed")
	}
}

func testHTTPOnlyDispatchPrepareRequest(t *testing.T, identity transportIdentity) v2control.CredentialPrepareRequest {
	t.Helper()
	root := testCredentialPacketRoot(identity.sessionID)
	root.BindingIDs = []string{"binding-http"}
	root.DeliveryModes = []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy}
	sessionIdentity, err := v2control.GuestCredentialSessionIdentityFromRoot(identity.sessionID, root)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v2control.NewHTTPBindingManifest("binding-http", "azure-openai-responses-v1")
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := v2control.NewCredentialPrepareRequest(testPacketRequestID(t), sessionIdentity, 1, 1700000001123456789, []v2control.BindingManifest{binding}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return prepare
}
