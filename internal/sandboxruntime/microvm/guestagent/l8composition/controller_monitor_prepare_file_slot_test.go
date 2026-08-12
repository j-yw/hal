package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestControllerMonitorPrepareFileSlotExactMaximumAndFixedWriter(t *testing.T) {
	if ControllerMonitorPrepareFilePrefixBytes != ControllerMonitorHeaderBytes+46 || ControllerMonitorPrepareFileSlotBytes != ControllerMonitorHeaderBytes+controllerMonitorPrepareFileMaxBytes {
		t.Fatalf("slot bounds = prefix %d slot %d", ControllerMonitorPrepareFilePrefixBytes, ControllerMonitorPrepareFileSlotBytes)
	}
	payload := bytes.Repeat([]byte{0xa5}, credentialprotocol.MaxHelperFileBytes)
	slot, received := controllerMonitorPrepareFileSlotFixture(t, 7, 15, payload)
	observation, err := InspectControllerMonitorPrepareFileSlot(&slot, received)
	if err != nil {
		t.Fatal(err)
	}
	if observation.owner == nil || received != ControllerMonitorPrepareFileSlotBytes {
		t.Fatalf("observation/received = %v/%d", observation.owner != nil, received)
	}
	if _, err := InspectControllerMonitorPrepareFileSlot(&slot, received+1); !errors.Is(err, ErrControllerMonitorPrepareFileSlotLength) {
		t.Fatalf("plus one = %v", err)
	}
}

func TestControllerMonitorPrepareFilePrefixWriterRejectsEveryInvalidFixedField(t *testing.T) {
	header := ControllerMonitorHeader{Type: ControllerMonitorPacketTypePrepareFile, Sequence: 1, RequestID: byteRange16(0x21), JobIdentityDigest: byteRange32(0x31), BodyLength: 47}
	digest := sha256.Sum256([]byte("x"))
	for name, test := range map[string]struct {
		header   ControllerMonitorHeader
		revision uint64
		index    uint16
		length   uint32
		digest   [32]byte
	}{
		"type": {func() ControllerMonitorHeader {
			value := header
			value.Type = ControllerMonitorPacketTypePrepareCommit
			return value
		}(), 1, 0, 1, digest},
		"sequence": {func() ControllerMonitorHeader {
			value := header
			value.Sequence = MaxControllerMonitorPacketsPerDirection
			return value
		}(), 1, 0, 1, digest},
		"request":     {func() ControllerMonitorHeader { value := header; value.RequestID = [16]byte{}; return value }(), 1, 0, 1, digest},
		"job":         {func() ControllerMonitorHeader { value := header; value.JobIdentityDigest = [32]byte{}; return value }(), 1, 0, 1, digest},
		"body":        {func() ControllerMonitorHeader { value := header; value.BodyLength++; return value }(), 1, 0, 1, digest},
		"revision":    {header, 2, 0, 1, digest},
		"index":       {header, 1, credentialprotocol.MaxHelperBindings, 1, digest},
		"length zero": {header, 1, 0, 0, digest},
		"length high": {header, 1, 0, credentialprotocol.MaxHelperFileBytes + 1, digest},
		"digest":      {header, 1, 0, 1, [32]byte{}},
	} {
		if _, err := EncodeControllerMonitorPrepareFilePrefix(test.header, test.revision, test.index, test.length, test.digest); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestControllerMonitorPrepareFileSlotRejectsEveryFixedMutation(t *testing.T) {
	payload := []byte("locked-private-value")
	base, received := controllerMonitorPrepareFileSlotFixture(t, 3, 0, payload)
	for name, mutate := range map[string]func(*ControllerMonitorPrepareFileSlot){
		"magic":   func(slot *ControllerMonitorPrepareFileSlot) { slot[0] ^= 1 },
		"version": func(slot *ControllerMonitorPrepareFileSlot) { slot[4]++ },
		"type":    func(slot *ControllerMonitorPrepareFileSlot) { slot[5] = byte(ControllerMonitorPacketTypePrepareCommit) },
		"flags":   func(slot *ControllerMonitorPrepareFileSlot) { slot[7] = 1 },
		"sequence": func(slot *ControllerMonitorPrepareFileSlot) {
			binary.BigEndian.PutUint64(slot[8:16], MaxControllerMonitorPacketsPerDirection)
		},
		"request": func(slot *ControllerMonitorPrepareFileSlot) { clear(slot[16:32]) },
		"job":     func(slot *ControllerMonitorPrepareFileSlot) { clear(slot[32:64]) },
		"body length": func(slot *ControllerMonitorPrepareFileSlot) {
			binary.BigEndian.PutUint32(slot[64:68], uint32(46+len(payload)+1))
		},
		"revision": func(slot *ControllerMonitorPrepareFileSlot) { slot[ControllerMonitorHeaderBytes+7] = 2 },
		"binding index": func(slot *ControllerMonitorPrepareFileSlot) {
			binary.BigEndian.PutUint16(slot[ControllerMonitorHeaderBytes+8:ControllerMonitorHeaderBytes+10], credentialprotocol.MaxHelperBindings)
		},
		"file length": func(slot *ControllerMonitorPrepareFileSlot) {
			binary.BigEndian.PutUint32(slot[ControllerMonitorHeaderBytes+10:ControllerMonitorHeaderBytes+14], uint32(len(payload)+1))
		},
		"zero digest": func(slot *ControllerMonitorPrepareFileSlot) {
			clear(slot[ControllerMonitorHeaderBytes+14 : ControllerMonitorHeaderBytes+46])
		},
		"payload digest": func(slot *ControllerMonitorPrepareFileSlot) { slot[ControllerMonitorPrepareFilePrefixBytes] ^= 1 },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := InspectControllerMonitorPrepareFileSlot(&candidate, received); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := InspectControllerMonitorPrepareFileSlot(nil, received); !errors.Is(err, ErrControllerMonitorPrepareFileSlot) {
		t.Fatalf("nil slot = %v", err)
	}
	if _, err := InspectControllerMonitorPrepareFileSlot(&base, received-1); !errors.Is(err, ErrControllerMonitorPrepareFileSlotLength) {
		t.Fatalf("short receive = %v", err)
	}
}

func TestControllerMonitorPrepareFileEveryFixedByteMutationIsRejectedByInspectionOrState(t *testing.T) {
	payload := []byte("locked-private-value")
	fixture := controllerMonitorFixture(t)
	request := byteRange16(0x29)
	base, received := controllerMonitorPrepareFileSlot(t, 1, request, fixture.jobIdentity, 0, payload)
	for offset := 0; offset < ControllerMonitorPrepareFilePrefixBytes; offset++ {
		candidate := base
		candidate[offset] ^= 1
		observation, inspectErr := InspectControllerMonitorPrepareFileSlot(&candidate, received)
		if inspectErr != nil {
			continue
		}
		state := controllerMonitorPreparedForOneFile(t, fixture, request, payload)
		if _, err := state.AcceptPrepareFile(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), observation); err == nil {
			t.Errorf("fixed byte %d mutation accepted", offset)
		}
	}
}

func TestControllerMonitorPrepareFileObservationOneUseAliasAndStateBinding(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	payload := []byte("locked-private-value")
	digest := sha256.Sum256(payload)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1_900, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "file", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "credential", DeclaredFileBytes: uint32(len(payload)), FileSHA256: digest}}}
	request := byteRange16(0x19)
	wire, _ := EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, begin)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800); err != nil {
		t.Fatal(err)
	}
	slot, received := controllerMonitorPrepareFileSlot(t, 1, request, fixture.jobIdentity, 0, payload)
	observation, err := InspectControllerMonitorPrepareFileSlot(&slot, received)
	if err != nil {
		t.Fatal(err)
	}
	alias := observation
	metadata := controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor)
	if decision, err := state.AcceptPrepareFile(metadata, observation); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("accept = %v/%v", decision, err)
	}
	if got := state.Snapshot(); got.NextControllerSend != 2 || got.Phase != ControllerMonitorPhasePreparing {
		t.Fatalf("snapshot = %#v", got)
	}
	if decision, err := state.AcceptPrepareFile(metadata, alias); !errors.Is(err, ErrControllerMonitorPrepareFileObservationUsed) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("reuse = %v/%v", decision, err)
	}
}

func TestControllerMonitorPrepareFileObservationConcurrentAliasesCommitOnce(t *testing.T) {
	payload := []byte("locked-private-value")
	fixture := controllerMonitorFixture(t)
	request := byteRange16(0x69)
	state := controllerMonitorPreparedForOneFile(t, fixture, request, payload)
	slot, received := controllerMonitorPrepareFileSlot(t, 1, request, fixture.jobIdentity, 0, payload)
	observation, err := InspectControllerMonitorPrepareFileSlot(&slot, received)
	if err != nil {
		t.Fatal(err)
	}
	alias := observation
	metadata := controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor)
	var wait sync.WaitGroup
	decisions := make([]ControllerMonitorTransitionDecision, 2)
	errorsSeen := make([]error, 2)
	for index, value := range []ControllerMonitorPrepareFileObservation{observation, alias} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			decisions[index], errorsSeen[index] = state.AcceptPrepareFile(metadata, value)
		}()
	}
	wait.Wait()
	successes := 0
	for index := range decisions {
		if errorsSeen[index] == nil && decisions[index] == ControllerMonitorTransitionContinue {
			successes++
			continue
		}
		if !errors.Is(errorsSeen[index], ErrControllerMonitorPrepareFileObservationUsed) || decisions[index] != ControllerMonitorTransitionStopVMRequired {
			t.Errorf("result %d = %v/%v", index, decisions[index], errorsSeen[index])
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d", successes)
	}
}

func TestControllerMonitorAcceptPrepareFileRejectsMetadataAndManifestOrder(t *testing.T) {
	payload := []byte("locked-private-value")
	fixture := controllerMonitorFixture(t)
	request := byteRange16(0x39)
	for name, mutate := range map[string]func(*ControllerMonitorReceiveMetadata, *ControllerMonitorPrepareFileSlot){
		"direction": func(metadata *ControllerMonitorReceiveMetadata, _ *ControllerMonitorPrepareFileSlot) {
			metadata.Direction = ControllerMonitorDirectionMonitorToController
			metadata.Credential = fixture.monitorCredential
		},
		"rights": func(metadata *ControllerMonitorReceiveMetadata, _ *ControllerMonitorPrepareFileSlot) {
			metadata.RightsCount = 1
		},
		"message truncation": func(metadata *ControllerMonitorReceiveMetadata, _ *ControllerMonitorPrepareFileSlot) {
			metadata.MessageTruncated = true
		},
		"control truncation": func(metadata *ControllerMonitorReceiveMetadata, _ *ControllerMonitorPrepareFileSlot) {
			metadata.ControlTruncated = true
		},
		"credential": func(metadata *ControllerMonitorReceiveMetadata, _ *ControllerMonitorPrepareFileSlot) {
			metadata.Credential.PID++
		},
		"request":  func(_ *ControllerMonitorReceiveMetadata, slot *ControllerMonitorPrepareFileSlot) { slot[16]++ },
		"job":      func(_ *ControllerMonitorReceiveMetadata, slot *ControllerMonitorPrepareFileSlot) { slot[32]++ },
		"sequence": func(_ *ControllerMonitorReceiveMetadata, slot *ControllerMonitorPrepareFileSlot) { slot[15]++ },
		"manifest order": func(_ *ControllerMonitorReceiveMetadata, slot *ControllerMonitorPrepareFileSlot) {
			slot[ControllerMonitorHeaderBytes+9] = 1
		},
	} {
		state := controllerMonitorPreparedForOneFile(t, fixture, request, payload)
		slot, received := controllerMonitorPrepareFileSlot(t, 1, request, fixture.jobIdentity, 0, payload)
		metadata := controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor)
		mutate(&metadata, &slot)
		observation, err := InspectControllerMonitorPrepareFileSlot(&slot, received)
		if err != nil {
			if name == "manifest order" || name == "request" || name == "job" || name == "sequence" {
				t.Fatalf("%s should remain canonically inspectable: %v", name, err)
			}
			continue
		}
		if decision, err := state.AcceptPrepareFile(metadata, observation); err == nil || decision != ControllerMonitorTransitionStopVMRequired {
			t.Errorf("%s = %v/%v", name, decision, err)
		}
	}
}

func TestControllerMonitorStateOrdinaryAcceptRejectsPrepareFileBeforeGenericDecode(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	header, err := EncodeControllerMonitorHeader(ControllerMonitorHeader{Type: ControllerMonitorPacketTypePrepareFile, Sequence: 0, RequestID: byteRange16(0x41), JobIdentityDigest: fixture.jobIdentity, BodyLength: controllerMonitorPrepareFileMinBytes})
	if err != nil {
		t.Fatal(err)
	}
	wire := append(header[:], make([]byte, controllerMonitorPrepareFileMinBytes)...)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); !errors.Is(err, ErrControllerMonitorPrepareFileSlotRequired) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("ordinary file accept = %v/%v", decision, err)
	}
}

func TestControllerMonitorPrepareFileSlotObservationOpaqueAndRetainsNoSlot(t *testing.T) {
	slotType := reflect.TypeOf(ControllerMonitorPrepareFileSlot{})
	if slotType.Kind() != reflect.Array || slotType.Len() != ControllerMonitorPrepareFileSlotBytes || slotType.Elem().Kind() != reflect.Uint8 {
		t.Fatalf("slot type = %v", slotType)
	}
	typeOf := reflect.TypeOf(ControllerMonitorPrepareFileObservation{})
	if typeOf.NumField() != 1 || typeOf.Field(0).Name != "owner" || typeOf.Field(0).IsExported() || typeOf.Field(0).Type.Kind() != reflect.Pointer || typeOf.Field(0).Tag != "" {
		t.Fatalf("observation layout = %#v", typeOf)
	}
	ownerType := typeOf.Field(0).Type.Elem()
	for index := 0; index < ownerType.NumField(); index++ {
		field := ownerType.Field(index)
		if field.Type == reflect.PointerTo(slotType) || field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.String {
			t.Errorf("owner retains forbidden field %s %v", field.Name, field.Type)
		}
	}
	inspector := reflect.TypeOf(InspectControllerMonitorPrepareFileSlot)
	if inspector.NumIn() != 2 || inspector.In(0) != reflect.PointerTo(slotType) || inspector.In(1).Kind() != reflect.Uint32 || inspector.NumOut() != 2 || inspector.Out(0) != typeOf || !inspector.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		t.Fatalf("inspector signature = %v", inspector)
	}
	encoder := reflect.TypeOf(EncodeControllerMonitorPrepareFilePrefix)
	if encoder.NumIn() != 5 || encoder.In(0) != reflect.TypeOf(ControllerMonitorHeader{}) || encoder.In(1).Kind() != reflect.Uint64 || encoder.In(2).Kind() != reflect.Uint16 || encoder.In(3).Kind() != reflect.Uint32 || encoder.In(4) != reflect.TypeOf([32]byte{}) || encoder.NumOut() != 2 || encoder.Out(0) != reflect.TypeOf([ControllerMonitorPrepareFilePrefixBytes]byte{}) {
		t.Fatalf("prefix encoder signature = %v", encoder)
	}
	payload := []byte("locked-private-value")
	slot, received := controllerMonitorPrepareFileSlotFixture(t, 1, 0, payload)
	observation, err := InspectControllerMonitorPrepareFileSlot(&slot, received)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{observation, &observation} {
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value); got != strings.Repeat("ControllerMonitorPrepareFileObservation|", 4)+"ControllerMonitorPrepareFileObservation" {
			t.Errorf("format = %q", got)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("JSON = %v", err)
		}
		if _, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("text = %v", err)
		}
	}
}

func TestControllerMonitorPrepareFileSlotValueAndPointerFormattingSerializationAreOpaque(t *testing.T) {
	var slot ControllerMonitorPrepareFileSlot
	copy(slot[:], []byte("seeded-private-payload-canary"))
	want := strings.Repeat("ControllerMonitorPrepareFileSlot|", 4) + "ControllerMonitorPrepareFileSlot"
	for _, opaque := range []any{slot, &slot} {
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", opaque, opaque, opaque, opaque, opaque); got != want {
			t.Errorf("%T common formatting = %q", opaque, got)
		}
		for _, verb := range []string{"x", "X", "d", "o", "O", "b", "e", "E", "f", "F", "g", "G", "c", "U", "t"} {
			if got := fmt.Sprintf("%"+verb, opaque); got != "ControllerMonitorPrepareFileSlot" {
				t.Errorf("%T %%%s = %q", opaque, verb, got)
			}
		}
		for _, verb := range []string{"T", "p"} {
			if got := fmt.Sprintf("%"+verb, opaque); strings.Contains(got, "seeded-private-payload-canary") {
				t.Errorf("%T %%%s leaked seeded contents: %q", opaque, verb, got)
			}
		}
		if encoded, err := json.Marshal(opaque); encoded != nil || !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%T JSON marshal = %q/%v", opaque, encoded, err)
		}
		if marshaler, ok := opaque.(encoding.TextMarshaler); !ok {
			t.Errorf("%T lacks text marshaler", opaque)
		} else if encoded, err := marshaler.MarshalText(); encoded != nil || !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%T text marshal = %q/%v", opaque, encoded, err)
		}
		if marshaler, ok := opaque.(encoding.BinaryMarshaler); !ok {
			t.Errorf("%T lacks binary marshaler", opaque)
		} else if encoded, err := marshaler.MarshalBinary(); encoded != nil || !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%T binary marshal = %q/%v", opaque, encoded, err)
		}
	}

	before := slot
	if err := json.Unmarshal([]byte(`[1,2,3]`), &slot); !errors.Is(err, ErrControllerMonitorSerialization) {
		t.Errorf("JSON unmarshal = %v", err)
	}
	if unmarshaler, ok := any(&slot).(encoding.TextUnmarshaler); !ok {
		t.Error("slot pointer lacks text unmarshaler")
	} else if err := unmarshaler.UnmarshalText([]byte("replacement-private-payload")); !errors.Is(err, ErrControllerMonitorSerialization) {
		t.Errorf("text unmarshal = %v", err)
	}
	if unmarshaler, ok := any(&slot).(encoding.BinaryUnmarshaler); !ok {
		t.Error("slot pointer lacks binary unmarshaler")
	} else if err := unmarshaler.UnmarshalBinary([]byte("replacement-private-payload")); !errors.Is(err, ErrControllerMonitorSerialization) {
		t.Errorf("binary unmarshal = %v", err)
	}
	if slot != before {
		t.Fatal("denied unmarshal mutated slot")
	}
}

func TestControllerMonitorPrepareFileSlotAPIHasExactArrayAndNoAccessors(t *testing.T) {
	typeOf := reflect.TypeOf(ControllerMonitorPrepareFileSlot{})
	if typeOf.Kind() != reflect.Array || typeOf.Len() != ControllerMonitorPrepareFileSlotBytes || typeOf.Elem().Kind() != reflect.Uint8 {
		t.Fatalf("slot shape = %v", typeOf)
	}
	allowed := map[string]bool{
		"Format": true, "GoString": true, "MarshalBinary": true, "MarshalJSON": true,
		"MarshalText": true, "String": true, "UnmarshalBinary": true,
		"UnmarshalJSON": true, "UnmarshalText": true,
	}
	for _, candidate := range []reflect.Type{typeOf, reflect.PointerTo(typeOf)} {
		for index := 0; index < candidate.NumMethod(); index++ {
			if method := candidate.Method(index); !allowed[method.Name] {
				t.Errorf("slot exposes method %s", method.Name)
			}
		}
	}

	source, err := os.ReadFile("controller_monitor_prepare_file_slot.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "controller_monitor_prepare_file_slot.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	foundType := false
	for _, declaration := range parsed.Decls {
		switch node := declaration.(type) {
		case *ast.GenDecl:
			for _, specification := range node.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "ControllerMonitorPrepareFileSlot" {
					continue
				}
				foundType = true
				arrayType, ok := typeSpec.Type.(*ast.ArrayType)
				if !ok {
					t.Errorf("slot declaration is not an array: %#v", typeSpec.Type)
					continue
				}
				length, lengthOK := arrayType.Len.(*ast.Ident)
				element, elementOK := arrayType.Elt.(*ast.Ident)
				if !lengthOK || length.Name != "ControllerMonitorPrepareFileSlotBytes" || !elementOK || element.Name != "byte" {
					t.Errorf("slot declaration is not the exact fixed array: %#v", typeSpec.Type)
				}
			}
		case *ast.FuncDecl:
			if node.Recv == nil || len(node.Recv.List) != 1 {
				continue
			}
			receiver := node.Recv.List[0].Type
			if pointer, ok := receiver.(*ast.StarExpr); ok {
				receiver = pointer.X
			}
			identifier, ok := receiver.(*ast.Ident)
			if ok && identifier.Name == "ControllerMonitorPrepareFileSlot" && !allowed[node.Name.Name] {
				t.Errorf("slot source exposes method %s", node.Name.Name)
			}
		}
	}
	if !foundType {
		t.Fatal("fixed slot type declaration missing")
	}
}

func TestControllerMonitorPrepareFileProductionSourceHasNoUnsafeBodyPath(t *testing.T) {
	source, err := os.ReadFile("controller_monitor_state.go")
	if err != nil {
		t.Fatal(err)
	}
	reject := bytes.Index(source, []byte("header.Type == ControllerMonitorPacketTypePrepareFile"))
	genericDecode := bytes.Index(source, []byte("DecodeControllerMonitorPacket(encoded)"))
	if reject < 0 || genericDecode < 0 || reject > genericDecode {
		t.Fatalf("ordinary Accept does not reject file before generic decode: reject=%d decode=%d", reject, genericDecode)
	}
	if _, ok := reflect.TypeOf(ControllerMonitorPacket{}).MethodByName("PrepareFile"); ok {
		t.Fatal("public PrepareFile packet accessor exists")
	}
	packetSource, err := os.ReadFile("controller_monitor_packet.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"func EncodeControllerMonitorPrepareFilePacket(",
		"packet.file",
		"DecodeHelperPrepareFileBody",
		"EncodeHelperPrepareFileBody",
		"Diagnostic generic decoding",
	} {
		if bytes.Contains(packetSource, []byte(forbidden)) {
			t.Errorf("generic packet source retains forbidden prepare-file path %q", forbidden)
		}
	}

	payload := []byte("private-generic-path-must-fail")
	slot, received := controllerMonitorPrepareFileSlot(t, 0, byteRange16(0x31), byteRange32(0x41), 0, payload)
	wire := slot[:received]
	if encoded, err := encodeControllerMonitorTypedPacket(
		ControllerMonitorPacketTypePrepareFile,
		0,
		byteRange16(0x31),
		byteRange32(0x41),
		wire[ControllerMonitorHeaderBytes:],
		nil,
	); !errors.Is(err, ErrControllerMonitorPrepareFileSlotRequired) || encoded != nil {
		t.Fatalf("generic typed encode = %d bytes, %v", len(encoded), err)
	}
	if _, err := DecodeControllerMonitorPacket(wire); !errors.Is(err, ErrControllerMonitorPrepareFileSlotRequired) {
		t.Fatalf("generic decode error = %v", err)
	}
	if _, err := EncodeControllerMonitorPacket(ControllerMonitorPacket{header: ControllerMonitorHeader{
		Type: ControllerMonitorPacketTypePrepareFile,
	}}); !errors.Is(err, ErrControllerMonitorPrepareFileSlotRequired) {
		t.Fatalf("generic encode error = %v", err)
	}
	slotSource, err := os.ReadFile("controller_monitor_prepare_file_slot.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"privateBytes", "DecodeHelperPrepareFileBody", "CopyPrivateBytes", "unsafe.", "runtime."} {
		if bytes.Contains(slotSource, []byte(forbidden)) {
			t.Errorf("slot source contains %q", forbidden)
		}
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "controller_monitor_prepare_file_slot.go", slotSource, 0)
	if err != nil {
		t.Fatal(err)
	}
	foundInspector := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		declaration, ok := node.(*ast.FuncDecl)
		if !ok || declaration.Name.Name != "InspectControllerMonitorPrepareFileSlot" {
			return true
		}
		foundInspector = true
		if declaration.Type.Params == nil || declaration.Type.Params.NumFields() != 2 {
			t.Errorf("inspector params = %#v", declaration.Type.Params)
			return false
		}
		first, ok := declaration.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			t.Errorf("inspector first param = %#v", declaration.Type.Params.List[0].Type)
			return false
		}
		identifier, identifierOK := first.X.(*ast.Ident)
		if !identifierOK || identifier.Name != "ControllerMonitorPrepareFileSlot" {
			t.Errorf("inspector first param = %#v", declaration.Type.Params.List[0].Type)
		}
		return false
	})
	if !foundInspector {
		t.Fatal("fixed-slot inspector declaration missing")
	}
}

func controllerMonitorPreparedForOneFile(t *testing.T, fixture controllerMonitorTestFixture, request [16]byte, payload []byte) *ControllerMonitorState {
	t.Helper()
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	digest := sha256.Sum256(payload)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1_900, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "file", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "credential", DeclaredFileBytes: uint32(len(payload)), FileSHA256: digest}}}
	wire, err := EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, begin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800); err != nil {
		t.Fatal(err)
	}
	return state
}

func controllerMonitorPrepareFileSlotFixture(t *testing.T, sequence uint64, bindingIndex uint16, payload []byte) (ControllerMonitorPrepareFileSlot, uint32) {
	t.Helper()
	return controllerMonitorPrepareFileSlot(t, sequence, byteRange16(0x51), byteRange32(0x61), bindingIndex, payload)
}

func controllerMonitorPrepareFileSlot(t *testing.T, sequence uint64, request [16]byte, job [32]byte, bindingIndex uint16, payload []byte) (ControllerMonitorPrepareFileSlot, uint32) {
	t.Helper()
	digest := sha256.Sum256(payload)
	header := ControllerMonitorHeader{Type: ControllerMonitorPacketTypePrepareFile, Sequence: sequence, RequestID: request, JobIdentityDigest: job, BodyLength: uint32(46 + len(payload))}
	prefix, err := EncodeControllerMonitorPrepareFilePrefix(header, 1, bindingIndex, uint32(len(payload)), digest)
	if err != nil {
		t.Fatal(err)
	}
	var slot ControllerMonitorPrepareFileSlot
	copy(slot[:ControllerMonitorPrepareFilePrefixBytes], prefix[:])
	copy(slot[ControllerMonitorPrepareFilePrefixBytes:], payload)
	return slot, uint32(ControllerMonitorPrepareFilePrefixBytes + len(payload))
}
