package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestControllerMonitorConstantsCatalogAndCanonicalReadyVector(t *testing.T) {
	t.Parallel()

	if ControllerMonitorHeaderBytes != 68 || MaxControllerMonitorBodyBytes != 73728 || MaxControllerMonitorDatagramBytes != 73796 || MaxControllerMonitorPacketsPerDirection != 1<<32 {
		t.Fatalf("bounds = header %d body %d datagram %d packets %d", ControllerMonitorHeaderBytes, MaxControllerMonitorBodyBytes, MaxControllerMonitorDatagramBytes, MaxControllerMonitorPacketsPerDirection)
	}
	for value, want := range map[ControllerMonitorPacketType]byte{
		ControllerMonitorPacketTypeMonitorReady:      0x01,
		ControllerMonitorPacketTypePrepareBegin:      0x10,
		ControllerMonitorPacketTypePrepareFile:       0x11,
		ControllerMonitorPacketTypePrepareCommit:     0x12,
		ControllerMonitorPacketTypeCreateSSHEndpoint: 0x13,
		ControllerMonitorPacketTypeRevoke:            0x14,
		ControllerMonitorPacketTypeResponse:          0x20,
		ControllerMonitorPacketTypeMonitorEvent:      0x21,
		ControllerMonitorPacketTypeCloseNotify:       0x7f,
	} {
		if byte(value) != want {
			t.Errorf("packet type %d = %#x, want %#x", value, value, want)
		}
	}
	for value := 0; value <= math.MaxUint8; value++ {
		err := ValidateControllerMonitorPacketType(ControllerMonitorPacketType(value))
		want := value == 0x01 || value >= 0x10 && value <= 0x14 || value == 0x20 || value == 0x21 || value == 0x7f
		if (err == nil) != want {
			t.Errorf("type %#x valid = %t, want %t", value, err == nil, want)
		}
	}

	fixture := controllerMonitorFixture(t)
	wire, err := EncodeControllerMonitorReadyPacket(0, fixture.jobIdentity, fixture.ready)
	if err != nil {
		t.Fatal(err)
	}
	wantHex := "484c384d01010000000000000000000000000000000000000000000000000000" +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"0000008f000000000000000100096a6f622d67656e2d31000d6d6f6e69746f72" +
		"2d67656e2d31000b6d6f756e742d67656e2d31000c6367726f75702d67656e2d" +
		"31001068656c7065722d6c696d6974732d7631202122232425262728292a2b2c" +
		"2d2e2f303132333435363738393a3b3c3d3e3fd1eb1ee5d971de0f1c771fd564" +
		"443c651c176e977ba8da11248b7c7b47f9080b"
	if got := hex.EncodeToString(wire); got != wantHex {
		t.Fatalf("ready wire = %s\nwant = %s", got, wantHex)
	}
	packet, err := DecodeControllerMonitorPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeControllerMonitorPacket(packet)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("reencode error = %v, equal = %t", err, bytes.Equal(reencoded, wire))
	}
	ready, ok := packet.MonitorReady()
	if !ok || ready != fixture.ready {
		t.Fatalf("ready accessor = %#v, %t", ready, ok)
	}
	copyWire := append([]byte(nil), wire...)
	wire[0] ^= 0xff
	reencoded, err = EncodeControllerMonitorPacket(packet)
	if err != nil || !bytes.Equal(reencoded, copyWire) {
		t.Fatal("decoded packet aliases caller wire")
	}
}

func TestEncodeControllerMonitorPacketRejectsForgedInactiveUnionHeaderAndEventCorrelation(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	readyWire := mustControllerMonitorReadyPacket(t, fixture)
	for name, mutate := range map[string]func(*ControllerMonitorPacket){
		"begin": func(packet *ControllerMonitorPacket) {
			packet.begin = credentialprotocol.HelperPrepareBeginBody{Revision: 1, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "b"}}}
		},
		"begin nonnil empty": func(packet *ControllerMonitorPacket) {
			packet.begin.Bindings = []credentialprotocol.HelperBindingManifestRecord{}
		},
		"commit": func(packet *ControllerMonitorPacket) { packet.commit.Revision = 1 },
		"ssh":    func(packet *ControllerMonitorPacket) { packet.ssh.Revision = 1 },
		"revoke": func(packet *ControllerMonitorPacket) { packet.revoke.Revision = 1 },
		"response": func(packet *ControllerMonitorPacket) {
			packet.response, _ = NewControllerMonitorRejectedResponse(ControllerMonitorPacketTypePrepareCommit, 1, ControllerMonitorFailureResourceLimit)
		},
		"event": func(packet *ControllerMonitorPacket) { packet.event.Revision = 1 },
		"close": func(packet *ControllerMonitorPacket) { packet.close.Reason = credentialprotocol.CloseReasonNormal },
	} {
		packet, err := DecodeControllerMonitorPacket(readyWire)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&packet)
		if _, err := EncodeControllerMonitorPacket(packet); !errors.Is(err, ErrControllerMonitorBody) {
			t.Errorf("inactive %s = %v", name, err)
		}
	}

	packet, err := DecodeControllerMonitorPacket(readyWire)
	if err != nil {
		t.Fatal(err)
	}
	packet.header.BodyLength++
	if _, err := EncodeControllerMonitorPacket(packet); !errors.Is(err, ErrControllerMonitorBody) {
		t.Fatalf("forged header = %v", err)
	}

	request := byteRange16(0x33)
	digest, _ := ControllerMonitorEventPostinspectionSHA256(fixture.jobIdentity, ControllerMonitorEventExpired, ControllerMonitorFailureOperationDenied, ControllerMonitorCleanupRetryRequired, 1, request, fixture.ready.MonitorGeneration, fixture.ready.MountGeneration)
	event := ControllerMonitorEventBody{EventCode: ControllerMonitorEventExpired, FailureCode: ControllerMonitorFailureOperationDenied, CleanupCategory: ControllerMonitorCleanupRetryRequired, Revision: 1, EventID: controllerMonitorEventID(request), MountGeneration: fixture.ready.MountGeneration, PostinspectionSHA256: digest}
	eventWire, _ := EncodeControllerMonitorEventPacket(1, request, fixture.jobIdentity, event)
	packet, err = DecodeControllerMonitorPacket(eventWire)
	if err != nil {
		t.Fatal(err)
	}
	packet.header.RequestID[0]++
	if _, err := EncodeControllerMonitorPacket(packet); !errors.Is(err, ErrControllerMonitorEvent) {
		t.Fatalf("event request correlation = %v", err)
	}
}

func TestControllerMonitorExactBodyBoundsAndDelegatedPrepareRevokeCodecs(t *testing.T) {
	t.Parallel()
	fixture := controllerMonitorFixture(t)
	request := byteRange16(1)
	path := strings.Repeat(strings.Repeat("p", 255)+"/", 15) + strings.Repeat("q", 254) + "/r"
	if len(path) != credentialprotocol.MaxRelativePathBytes {
		t.Fatalf("path length = %d", len(path))
	}
	bindings := make([]credentialprotocol.HelperBindingManifestRecord, credentialprotocol.MaxHelperBindings)
	for index := range bindings {
		id := fmt.Sprintf("b%014d", index) + strings.Repeat("x", 113)
		bindings[index] = credentialprotocol.HelperBindingManifestRecord{BindingID: id, Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: path, DeclaredFileBytes: 1, FileSHA256: [32]byte{byte(index + 1)}}
	}
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1, Bindings: bindings}
	helperBegin, err := credentialprotocol.EncodeHelperPrepareBeginBody(begin)
	if err != nil {
		t.Fatal(err)
	}
	if len(helperBegin) != controllerMonitorPrepareBeginMaxBytes {
		t.Fatalf("begin bytes = %d", len(helperBegin))
	}
	wire, err := EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, begin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[ControllerMonitorHeaderBytes:], helperBegin) || len(wire) != ControllerMonitorHeaderBytes+controllerMonitorPrepareBeginMaxBytes {
		t.Fatal("prepare begin did not delegate exact helper bytes")
	}

	commit := credentialprotocol.HelperPrepareCommitBody{Revision: 1, ManifestSHA256: [32]byte{1}}
	helperCommit, _ := credentialprotocol.EncodeHelperPrepareCommitBody(commit)
	wire, _ = EncodeControllerMonitorPrepareCommitPacket(2, request, fixture.jobIdentity, commit)
	if !bytes.Equal(wire[ControllerMonitorHeaderBytes:], helperCommit) {
		t.Fatal("prepare commit did not delegate exact helper bytes")
	}
	revoke := credentialprotocol.HelperRevokeBody{Revision: 1, Reason: credentialprotocol.RevokeReasonRequested}
	helperRevoke, _ := credentialprotocol.EncodeHelperRevokeBody(revoke)
	wire, _ = EncodeControllerMonitorRevokePacket(3, byteRange16(2), fixture.jobIdentity, revoke)
	if !bytes.Equal(wire[ControllerMonitorHeaderBytes:], helperRevoke) {
		t.Fatal("revoke did not delegate exact helper bytes")
	}

	zero := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1}
	if _, err := EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, zero); !errors.Is(err, credentialprotocol.ErrHelperPrepareBindingCount) {
		t.Fatalf("zero binding error = %v", err)
	}
}

func TestControllerMonitorResponseAndEventClosedMatrices(t *testing.T) {
	t.Parallel()
	for _, requestType := range []ControllerMonitorPacketType{ControllerMonitorPacketTypePrepareCommit, ControllerMonitorPacketTypeCreateSSHEndpoint} {
		for failure := ControllerMonitorFailureCode(0); failure <= ControllerMonitorFailureOperationDenied; failure++ {
			_, err := NewControllerMonitorRejectedResponse(requestType, 1, failure)
			want := failure == ControllerMonitorFailureResourceLimit || failure == ControllerMonitorFailureOperationDenied || requestType == ControllerMonitorPacketTypePrepareCommit && failure == ControllerMonitorFailurePrepareFailed || requestType == ControllerMonitorPacketTypeCreateSSHEndpoint && failure == ControllerMonitorFailureSSHEndpointFailed
			if (err == nil) != want {
				t.Errorf("rejected %x/%d valid = %t, want %t", requestType, failure, err == nil, want)
			}
		}
	}
	for event := ControllerMonitorEventCode(1); event <= ControllerMonitorEventCleanupRequired; event++ {
		body := ControllerMonitorEventBody{EventCode: event, Revision: 1, EventID: "AAECAwQFBgcICQoLDA0ODw", MountGeneration: "mount", PostinspectionSHA256: [32]byte{1}}
		switch event {
		case ControllerMonitorEventExpired:
			body.FailureCode, body.CleanupCategory = ControllerMonitorFailureOperationDenied, ControllerMonitorCleanupRetryRequired
		case ControllerMonitorEventMountDrift, ControllerMonitorEventEndpointDrift:
			body.FailureCode, body.CleanupCategory = ControllerMonitorFailureInspectionFailed, ControllerMonitorCleanupStopVMRequired
		case ControllerMonitorEventCleanupRequired:
			body.FailureCode, body.CleanupCategory = ControllerMonitorFailureCleanupIncomplete, ControllerMonitorCleanupRetryRequired
		}
		wire, err := EncodeControllerMonitorEventBody(body)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeControllerMonitorEventBody(wire)
		if err != nil || decoded != body {
			t.Fatalf("event %d round trip = %#v, %v", event, decoded, err)
		}
		mutated := append([]byte(nil), wire...)
		mutated[3] = 1
		if _, err := DecodeControllerMonitorEventBody(mutated); !errors.Is(err, ErrControllerMonitorEvent) {
			t.Fatalf("reserved event error = %v", err)
		}
	}
}

func TestControllerMonitorEveryBodyArmExactLengthsAndRoundTrips(t *testing.T) {
	t.Parallel()
	fixture := controllerMonitorFixture(t)
	manifest := byteRange32(0x40)
	transaction := byteRange32(0x60)
	post, _ := ControllerMonitorPreparePostinspectionSHA256(fixture.jobIdentity, 1, fixture.ready.MonitorGeneration, fixture.ready.MountGeneration, manifest, transaction, 1, 3)
	prepare, _ := NewControllerMonitorPrepareAcceptedResponse(1, ControllerMonitorPrepareResult{MountGeneration: "m", ManifestSHA256: manifest, PrepareTransactionSHA256: transaction, FileCount: 1, AggregateFileBytes: 3, PreparePostinspectionSHA256: post})
	endpointDigest := byteRange32(0x80)
	ssh, _ := NewControllerMonitorSSHEndpointAcceptedResponse(1, ControllerMonitorSSHEndpointResult{BindingIndex: 2, BindingID: "s", EndpointGeneration: "e", EndpointSHA256: endpointDigest})
	cleanup, _ := NewControllerMonitorCleanupCompleteResponse(1, ControllerMonitorRevokeResult{CleanupSHA256: byteRange32(0xa0), EntriesAbsent: true, SocketAbsent: true, MountAbsent: true})
	rejected, _ := NewControllerMonitorRejectedResponse(ControllerMonitorPacketTypePrepareCommit, 1, ControllerMonitorFailureResourceLimit)
	for name, test := range map[string]struct {
		body   ControllerMonitorResponseBody
		length int
	}{
		"failed": {rejected, 11}, "prepare": {prepare, 120}, "ssh": {ssh, 51}, "revoke": {cleanup, 46},
	} {
		wire, err := EncodeControllerMonitorResponseBody(test.body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(wire) != test.length {
			t.Fatalf("%s length = %d, want %d", name, len(wire), test.length)
		}
		decoded, err := DecodeControllerMonitorResponseBody(wire)
		if err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		reencoded, err := EncodeControllerMonitorResponseBody(decoded)
		if err != nil || !bytes.Equal(reencoded, wire) {
			t.Fatalf("%s roundtrip = %x, %v", name, reencoded, err)
		}
	}
	create := ControllerMonitorCreateSSHEndpointBody{Revision: 1, BindingIndex: 0, BindingID: "b", EndpointGeneration: "e", ManifestSHA256: manifest, EndpointConfigSHA256: endpointDigest}
	createWire, err := EncodeControllerMonitorCreateSSHEndpointBody(create)
	if err != nil || len(createWire) != 80 {
		t.Fatalf("create = %d, %v", len(createWire), err)
	}
	eventID := byteRange16(0)
	eventDigest, _ := ControllerMonitorEventPostinspectionSHA256(fixture.jobIdentity, ControllerMonitorEventExpired, ControllerMonitorFailureOperationDenied, ControllerMonitorCleanupRetryRequired, 1, eventID, fixture.ready.MonitorGeneration, "m")
	event := ControllerMonitorEventBody{EventCode: ControllerMonitorEventExpired, FailureCode: ControllerMonitorFailureOperationDenied, CleanupCategory: ControllerMonitorCleanupRetryRequired, Revision: 1, EventID: controllerMonitorEventID(eventID), MountGeneration: "m", PostinspectionSHA256: eventDigest}
	eventWire, err := EncodeControllerMonitorEventBody(event)
	if err != nil || len(eventWire) != 71 {
		t.Fatalf("event = %d, %v", len(eventWire), err)
	}

	for packetType, bounds := range map[ControllerMonitorPacketType][2]int{
		ControllerMonitorPacketTypeMonitorReady: {87, 722}, ControllerMonitorPacketTypePrepareBegin: {60, 68258}, ControllerMonitorPacketTypePrepareFile: {47, 65582},
		ControllerMonitorPacketTypePrepareCommit: {40, 40}, ControllerMonitorPacketTypeCreateSSHEndpoint: {80, 334}, ControllerMonitorPacketTypeRevoke: {9, 9},
		ControllerMonitorPacketTypeResponse: {11, 305}, ControllerMonitorPacketTypeMonitorEvent: {71, 198}, ControllerMonitorPacketTypeCloseNotify: {1, 1},
	} {
		if err := validateControllerMonitorTypeBodyLength(packetType, bounds[0]); err != nil {
			t.Errorf("%x min: %v", packetType, err)
		}
		if err := validateControllerMonitorTypeBodyLength(packetType, bounds[1]); err != nil {
			t.Errorf("%x max: %v", packetType, err)
		}
		if err := validateControllerMonitorTypeBodyLength(packetType, bounds[0]-1); !errors.Is(err, ErrControllerMonitorBodyLength) {
			t.Errorf("%x min-1: %v", packetType, err)
		}
		if err := validateControllerMonitorTypeBodyLength(packetType, bounds[1]+1); !errors.Is(err, ErrControllerMonitorBodyLength) {
			t.Errorf("%x max+1: %v", packetType, err)
		}
	}
}

func TestControllerMonitorDirectionRightsAndUnusedMetadataMatrix(t *testing.T) {
	t.Parallel()
	for _, packetType := range []ControllerMonitorPacketType{ControllerMonitorPacketTypePrepareBegin, ControllerMonitorPacketTypePrepareFile, ControllerMonitorPacketTypePrepareCommit, ControllerMonitorPacketTypeCreateSSHEndpoint, ControllerMonitorPacketTypeRevoke} {
		if err := ValidateControllerMonitorPacketMetadata(packetType, ControllerMonitorDirectionControllerToMonitor, 0, nil); err != nil {
			t.Errorf("request %x: %v", packetType, err)
		}
		if err := ValidateControllerMonitorPacketMetadata(packetType, ControllerMonitorDirectionMonitorToController, 0, nil); !errors.Is(err, ErrControllerMonitorPacketDirection) {
			t.Errorf("reverse %x: %v", packetType, err)
		}
	}
	fixture := controllerMonitorFixture(t)
	packet, _ := DecodeControllerMonitorPacket(mustControllerMonitorReadyPacket(t, fixture))
	metadata := fixture.readyMetadata
	metadata.RightsCount = 1
	metadata.Rights[1] = ControllerMonitorRightMetadata{Index: 99, Generation: "unused"}
	if err := ValidateControllerMonitorReceiveMetadata(packet, metadata, fixture.monitorCredential, fixture.controllerCredential, fixture.agentPID); !errors.Is(err, ErrControllerMonitorRights) {
		t.Fatalf("nonzero unused right = %v", err)
	}
	result := ControllerMonitorSSHEndpointResult{BindingIndex: 0, BindingID: "ssh", EndpointGeneration: "endpoint", EndpointSHA256: byteRange32(0x90)}
	response, _ := NewControllerMonitorSSHEndpointAcceptedResponse(1, result)
	wire, _ := EncodeControllerMonitorResponsePacket(1, byteRange16(0x31), fixture.jobIdentity, response)
	packet, _ = DecodeControllerMonitorPacket(wire)
	metadata = controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController)
	metadata.RightsCount = 1
	metadata.Rights[0] = ControllerMonitorRightMetadata{Index: 0, Kind: ControllerMonitorRightSSHListener, Access: ControllerMonitorRightListenStream, Generation: result.EndpointGeneration, CorrelationSHA256: result.EndpointSHA256}
	if err := ValidateControllerMonitorReceiveMetadata(packet, metadata, fixture.monitorCredential, fixture.controllerCredential, fixture.agentPID); err != nil {
		t.Fatalf("SSH right: %v", err)
	}
	metadata.RightsCount = 0
	metadata.Rights[0] = ControllerMonitorRightMetadata{}
	if err := ValidateControllerMonitorReceiveMetadata(packet, metadata, fixture.monitorCredential, fixture.controllerCredential, fixture.agentPID); !errors.Is(err, ErrControllerMonitorRights) {
		t.Fatalf("missing SSH right: %v", err)
	}
}

func TestControllerMonitorOpaqueFormattingSerializationAndNoMutation(t *testing.T) {
	t.Parallel()
	values := []any{
		ControllerMonitorPacketTypeResponse, ControllerMonitorDirectionMonitorToController, ControllerMonitorRightSSHListener,
		ControllerMonitorRightListenStream, ControllerMonitorFailureOperationDenied, ControllerMonitorEventExpired,
		ControllerMonitorCleanupRetryRequired, ControllerMonitorHeader{Sequence: 99}, ControllerMonitorKernelCredential{PID: 99},
		ControllerMonitorRightMetadata{Generation: "canary"}, ControllerMonitorReceiveMetadata{RightsCount: 2},
		ControllerMonitorReadyBody{JobGeneration: "canary"}, ControllerMonitorCreateSSHEndpointBody{BindingID: "canary"},
		ControllerMonitorPrepareResult{MountGeneration: "canary"}, ControllerMonitorSSHEndpointResult{BindingID: "canary"},
		ControllerMonitorRevokeResult{EntriesAbsent: true}, ControllerMonitorResponseBody{}, ControllerMonitorEventBody{EventID: "canary"},
		ControllerMonitorCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}, ControllerMonitorPacket{},
		ControllerMonitorTransitionContinue, ControllerMonitorPhasePreparing, ControllerMonitorExpected{AgentPID: 99},
		ControllerMonitorLocalObservation{}, ControllerMonitorPendingEvent{}, ControllerMonitorSnapshot{CleanupAttempts: 3},
	}
	for _, value := range values {
		if strings.Contains(fmt.Sprintf("%v %#v %+v", value, value, value), "canary") || strings.Contains(fmt.Sprintf("%v", value), "99") {
			t.Fatalf("format leaked value for %T", value)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Fatalf("JSON %T error = %v", value, err)
		}
		if _, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Fatalf("text %T error = %v", value, err)
		}
		if _, err := value.(encoding.BinaryMarshaler).MarshalBinary(); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Fatalf("binary %T error = %v", value, err)
		}
	}
	seed := ControllerMonitorHeader{Sequence: 77, BodyLength: 44}
	before := seed
	if err := seed.UnmarshalJSON([]byte(`{"canary":true}`)); !errors.Is(err, ErrControllerMonitorSerialization) || seed != before {
		t.Fatalf("unmarshal mutated header: %#v, %v", seed, err)
	}
}

func TestControllerMonitorDigestVectors(t *testing.T) {
	t.Parallel()

	fixture := controllerMonitorFixture(t)
	if got, err := ControllerMonitorReadySHA256(fixture.jobIdentity, fixture.ready); err != nil || got != fixture.ready.MonitorReadySHA256 {
		t.Fatalf("ready digest = %x, %v", got, err)
	}
	manifest := byteRange32(0x40)
	transaction := byteRange32(0x60)
	if got, err := ControllerMonitorPreparePostinspectionSHA256(fixture.jobIdentity, 1, "monitor-gen-1", "mount-gen-1", manifest, transaction, 1, 3); err != nil || hex.EncodeToString(got[:]) != "38f6cff0a56628b30fd7f4127242a45acabd288deac94cb170c99205cbff8918" {
		t.Fatalf("prepare digest = %x, %v", got, err)
	}
	config, err := ControllerMonitorEndpointConfigSHA256(fixture.jobIdentity, 1, 2, "ssh-binding-1", "endpoint-gen-1", "mount-gen-1", manifest)
	if err != nil || hex.EncodeToString(config[:]) != "8791ee5446150ccea1c9f78dd4005a1d0be14053f7bea7d455f9b6f872cc6748" {
		t.Fatalf("config digest = %x, %v", config, err)
	}
	if got, err := ControllerMonitorEndpointSHA256(fixture.jobIdentity, config, "endpoint-gen-1", "monitor-gen-1", "mount-gen-1"); err != nil || hex.EncodeToString(got[:]) != "50a4ae4feeac5718dcfef009f6e994ee38da6c66201f82b14dbacb2e7b71d94d" {
		t.Fatalf("endpoint digest = %x, %v", got, err)
	}
	requestID := byteRange16(0)
	if got, err := ControllerMonitorEventPostinspectionSHA256(fixture.jobIdentity, ControllerMonitorEventExpired, ControllerMonitorFailureOperationDenied, ControllerMonitorCleanupRetryRequired, 1, requestID, "monitor-gen-1", "mount-gen-1"); err != nil || hex.EncodeToString(got[:]) != "f139a2d62a6e9ebdd8d6857e2888b04eed654a151d6a29a6df563ff6e41198e8" {
		t.Fatalf("event digest = %x, %v", got, err)
	}
	if got, err := ControllerMonitorCleanupSHA256(fixture.jobIdentity, 1, credentialprotocol.RevokeReasonRequested, "monitor-gen-1", "mount-gen-1", "endpoint-gen-1", true, true, true); err != nil || hex.EncodeToString(got[:]) != "b9e0cab24180f9cc5ada909e2b6de84a5ab7061e87d634259c701c8dfda51219" {
		t.Fatalf("cleanup digest = %x, %v", got, err)
	}
}

func TestControllerMonitorMetadataRejectsRightsOverflowBeforeIndexing(t *testing.T) {
	t.Parallel()

	fixture := controllerMonitorFixture(t)
	packet, err := DecodeControllerMonitorPacket(mustControllerMonitorReadyPacket(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	metadata := fixture.readyMetadata
	metadata.RightsCount = 3
	metadata.Rights = [2]ControllerMonitorRightMetadata{}
	if err := ValidateControllerMonitorReceiveMetadata(packet, metadata, fixture.monitorCredential, fixture.controllerCredential, fixture.agentPID); !errors.Is(err, ErrControllerMonitorRights) {
		t.Fatalf("rights overflow error = %v", err)
	}
}

type controllerMonitorTestFixture struct {
	jobIdentity          [32]byte
	ready                ControllerMonitorReadyBody
	readyMetadata        ControllerMonitorReceiveMetadata
	monitorCredential    ControllerMonitorKernelCredential
	controllerCredential ControllerMonitorKernelCredential
	agentPID             uint32
}

func controllerMonitorFixture(t *testing.T) controllerMonitorTestFixture {
	t.Helper()
	job := byteRange32(0)
	ready := ControllerMonitorReadyBody{
		Revision: 1, JobGeneration: "job-gen-1", MonitorGeneration: "monitor-gen-1",
		MountGeneration: "mount-gen-1", CgroupGeneration: "cgroup-gen-1", LimitSetID: "helper-limits-v1",
		CreateJobSHA256: byteRange32(0x20),
	}
	digest, err := ControllerMonitorReadySHA256(job, ready)
	if err != nil {
		t.Fatal(err)
	}
	ready.MonitorReadySHA256 = digest
	monitor := ControllerMonitorKernelCredential{PID: 43, UID: 0, GID: 0}
	metadata := ControllerMonitorReceiveMetadata{
		Direction: ControllerMonitorDirectionMonitorToPID1, CredentialCount: 1, Credential: monitor, RightsCount: 2,
		Rights: [2]ControllerMonitorRightMetadata{
			{Index: 0, Kind: ControllerMonitorRightControllerEndpoint, Access: ControllerMonitorRightDuplexSeqpacket, Generation: "monitor-gen-1", CorrelationSHA256: digest},
			{Index: 1, Kind: ControllerMonitorRightMountNamespace, Access: ControllerMonitorRightNamespaceEnter, Generation: "mount-gen-1", CorrelationSHA256: digest},
		},
	}
	return controllerMonitorTestFixture{jobIdentity: job, ready: ready, readyMetadata: metadata, monitorCredential: monitor, controllerCredential: ControllerMonitorKernelCredential{PID: 42, UID: 0, GID: 0}, agentPID: 44}
}

func mustControllerMonitorReadyPacket(t *testing.T, fixture controllerMonitorTestFixture) []byte {
	t.Helper()
	wire, err := EncodeControllerMonitorReadyPacket(0, fixture.jobIdentity, fixture.ready)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func byteRange16(start byte) (value [16]byte) {
	for index := range value {
		value[index] = start + byte(index)
	}
	return value
}

func byteRange32(start byte) (value [sha256.Size]byte) {
	for index := range value {
		value[index] = start + byte(index)
	}
	return value
}
