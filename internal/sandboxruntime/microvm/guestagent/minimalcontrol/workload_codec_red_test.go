package minimalcontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// Reuses the independently locked old 27-field digest vector, not a new
// encoder's output. Opaque ASCII "opaque" is independently base64 b3BhcXVl.
const workloadCodecGolden = `{"body":{"bindingDigest":"sha256-d5fad705eb18587aef8d89fb21ccad1c61436ece8e07843a350ac5ed1300482d","guestSessionGeneration":"AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","payload":"b3BhcXVl"},"operation":"workload","protocolVersion":"guest-agent-minimal-v1","requestId":"00000000000000000000000000000001"}`

func TestWorkloadCodecIndependentGoldenControl(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	if len(workloadCodecGolden) != 297+8 || MaxWorkloadPayloadBytes != 1048576 ||
		MaxWorkloadMessageBytes != 297+base64.StdEncoding.EncodedLen(MaxWorkloadPayloadBytes) ||
		MaxWorkloadMessageBytes+session.SecureRecordHeaderBytes+session.GCMTagBytes != 1398469 ||
		MaxWorkloadMessageBytes >= session.MaxControlPlaintextBytes || MaxMessageBytes != 8192 {
		t.Fatal("independent operation extents or unchanged readiness bound differ")
	}
	digest, err := binding.Digest(id)
	if err != nil || !strings.Contains(workloadCodecGolden, digest) {
		t.Fatal("new fixture is not bound to the old independent tuple golden")
	}
}

func TestWorkloadCodecCanonicalGoldenAndImmutableBytes(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	payload := []byte("opaque")
	wire, err := binding.EncodeWorkload(payload, 1, id)
	if err != nil || string(wire) != workloadCodecGolden {
		t.Fatalf("canonical workload encoder unavailable: %v", err)
	}
	payload[0] = 'X'
	if string(wire) != workloadCodecGolden {
		t.Fatal("caller payload mutation changed owned encoded bytes")
	}
	for _, response := range []bool{false, true} {
		decoded, err := decodeWorkloadCodec(binding, response, wire, 1, id)
		if err != nil || string(decoded) != "opaque" {
			t.Fatalf("actual canonical workload decoder unavailable: %v", err)
		}
		decoded[0] = 'Y'
		if string(wire) != workloadCodecGolden {
			t.Fatal("caller decoded mutation changed retained wire")
		}
	}
	clear(wire)
	again, err := binding.EncodeWorkload([]byte("opaque"), 1, id)
	if err != nil || string(again) != workloadCodecGolden {
		t.Fatal("caller output mutation changed later encoding")
	}
}

func TestWorkloadCodecOpaqueBoundsAndOrdinals(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	for _, size := range []int{0, 1, 2, 3, MaxWorkloadPayloadBytes - 1, MaxWorkloadPayloadBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// Invalid UTF-8 and non-JSON are deliberately opaque to this codec.
			payload := bytes.Repeat([]byte{0xff}, size)
			for _, ordinal := range []uint64{1, 256, math.MaxUint64} {
				wire, err := binding.EncodeWorkload(payload, ordinal, id)
				if err != nil || len(wire) != 297+base64.StdEncoding.EncodedLen(size) {
					t.Fatalf("bounded opaque payload encoder unavailable: %v", err)
				}
				if !bytes.HasSuffix(wire, []byte(fmt.Sprintf(`"requestId":"%032x"}`, ordinal))) {
					t.Fatal("ordinal lost fixed-width canonical representation")
				}
				for _, response := range []bool{false, true} {
					decoded, err := decodeWorkloadCodec(binding, response, wire, ordinal, id)
					if err != nil || !bytes.Equal(decoded, payload) {
						t.Fatalf("opaque payload changed or could not decode: %v", err)
					}
				}
			}
		})
	}
	if wire, err := binding.EncodeWorkload(make([]byte, MaxWorkloadPayloadBytes+1), 1, id); err == nil || wire != nil {
		t.Fatal("oversized inner payload produced an envelope")
	}
}

func TestWorkloadCodecRejectsCanonicalMutationAndWrongFrames(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	if _, err := binding.DecodeWorkloadRequest(session.FrameTypeControlRequest, []byte(workloadCodecGolden), 1, id); err != nil {
		t.Fatalf("canonical decoder unavailable before mutation matrix: %v", err)
	}
	for name, wire := range map[string]string{
		"unknown":              strings.Replace(workloadCodecGolden, `"operation":`, `"extra":true,"operation":`, 1),
		"duplicate":            strings.Replace(workloadCodecGolden, `"operation":`, `"operation":"workload","operation":`, 1),
		"alias":                strings.Replace(workloadCodecGolden, `"requestId"`, `"RequestId"`, 1),
		"null":                 strings.Replace(workloadCodecGolden, `"b3BhcXVl"`, `null`, 1),
		"number":               strings.Replace(workloadCodecGolden, `"b3BhcXVl"`, `1`, 1),
		"array":                strings.Replace(workloadCodecGolden, `"b3BhcXVl"`, `[]`, 1),
		"depth":                strings.Replace(workloadCodecGolden, `"b3BhcXVl"`, strings.Repeat("[", 40)+strings.Repeat("]", 40), 1),
		"trailing":             workloadCodecGolden + "\n",
		"two roots":            workloadCodecGolden + workloadCodecGolden,
		"order":                strings.Replace(workloadCodecGolden, `"operation":"workload","protocolVersion":"guest-agent-minimal-v1"`, `"protocolVersion":"guest-agent-minimal-v1","operation":"workload"`, 1),
		"escape":               strings.Replace(workloadCodecGolden, `"workload"`, `"work\u006coad"`, 1),
		"inner invalid base64": strings.Replace(workloadCodecGolden, "b3BhcXVl", "b3BhcX!l", 1),
		"inner pad bits":       strings.Replace(workloadCodecGolden, "b3BhcXVl", "Zh==", 1),
		"inner missing pad":    strings.Replace(workloadCodecGolden, "b3BhcXVl", "Zg", 1),
		"inner extra pad":      strings.Replace(workloadCodecGolden, "b3BhcXVl", "Zg===", 1),
		"inner whitespace":     strings.Replace(workloadCodecGolden, "b3BhcXVl", "b3Bh\n cXVl", 1),
		"missing":              strings.Replace(workloadCodecGolden, `,"requestId":"00000000000000000000000000000001"`, "", 1),
		"oversize":             strings.Repeat("x", MaxWorkloadMessageBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			for _, response := range []bool{false, true} {
				if value, err := decodeWorkloadCodec(binding, response, []byte(wire), 1, id); err == nil || value != nil {
					t.Fatal("mutated outer envelope accepted")
				}
			}
		})
	}
	// max+1 and max share a padded base64 length; the outer cap alone is not
	// enough. Decode must independently bound owned inner bytes.
	tooLarge := strings.Replace(workloadCodecGolden, "b3BhcXVl", base64.StdEncoding.EncodeToString(make([]byte, MaxWorkloadPayloadBytes+1)), 1)
	if len(tooLarge) != MaxWorkloadMessageBytes {
		t.Fatal("inner max+1 fixture unexpectedly exceeds outer bound")
	}
	for _, response := range []bool{false, true} {
		if value, err := decodeWorkloadCodec(binding, response, []byte(tooLarge), 1, id); err == nil || value != nil {
			t.Fatal("bounded envelope accepted oversized decoded payload")
		}
	}
	for _, kind := range []session.FrameType{0, session.FrameTypeControlRequest, session.FrameTypeControlResponse, session.FrameTypeControlEvent, session.FrameTypeControlPrivate, session.FrameTypeRelayRequest, session.FrameTypeCloseNotify} {
		if kind != session.FrameTypeControlRequest {
			if value, err := binding.DecodeWorkloadRequest(kind, []byte(workloadCodecGolden), 1, id); err == nil || value != nil {
				t.Fatal("request decoder accepted wrong authenticated frame type")
			}
		}
		if kind != session.FrameTypeControlResponse {
			if value, err := binding.DecodeWorkloadResponse(kind, []byte(workloadCodecGolden), 1, id); err == nil || value != nil {
				t.Fatal("response decoder accepted wrong authenticated frame type")
			}
		}
	}
}

func TestWorkloadCodecPinsAllFieldsSessionOrdinalAndConstructorInput(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	if _, err := binding.DecodeWorkloadResponse(session.FrameTypeControlResponse, []byte(workloadCodecGolden), 1, id); err != nil {
		t.Fatalf("canonical response unavailable before correlation matrix: %v", err)
	}
	for _, field := range bindingFields {
		t.Run(field, func(t *testing.T) {
			identity, fields := testIdentity(), testBindingFields()
			fields[field] += "X"
			switch field {
			case "runtimeId":
				identity.RuntimeID = fields[field]
			case "runtimeGeneration":
				identity.RuntimeGeneration = fields[field]
			case "bootGeneration":
				identity.BootGeneration = fields[field]
			case "imageGeneration":
				identity.ImageGeneration = fields[field]
			case "processGeneration":
				identity.FirecrackerProcessGeneration = fields[field]
			case "vsockGeneration":
				identity.VsockGeneration = fields[field]
			case "imageDigest":
				identity.ImageSHA256[0]++
				fields[field] = "sha256-" + hex.EncodeToString(identity.ImageSHA256[:])
			case "admissionRevision":
				fields[field] = "2"
			case "runtimeDriver":
				fields[field] = "rootless_container"
			}
			other, err := NewBinding(identity, fields)
			if field == "runtimeDriver" {
				if err == nil {
					t.Fatal("fixed driver accepted relabeling")
				}
				return
			}
			if err != nil {
				t.Fatal("changed but independently valid binding fixture rejected", err)
			}
			for _, response := range []bool{false, true} {
				if value, err := decodeWorkloadCodec(other, response, []byte(workloadCodecGolden), 1, id); err == nil || value != nil {
					t.Fatal("cross-binding envelope accepted")
				}
			}
		})
	}
	for _, ordinal := range []uint64{0, 2, math.MaxUint64} {
		if _, err := binding.DecodeWorkloadRequest(session.FrameTypeControlRequest, []byte(workloadCodecGolden), ordinal, id); err == nil {
			t.Fatal("wrong ordinal accepted")
		}
	}
	otherID := id
	otherID[0]++
	for _, changed := range [][32]byte{{}, otherID} {
		if _, err := binding.DecodeWorkloadResponse(session.FrameTypeControlResponse, []byte(workloadCodecGolden), 1, changed); err == nil {
			t.Fatal("wrong session accepted")
		}
	}
	if _, err := (Binding{}).EncodeWorkload(nil, 1, id); err == nil {
		t.Fatal("zero binding accepted")
	}
	if _, err := binding.EncodeWorkload(nil, 0, id); err == nil {
		t.Fatal("zero ordinal accepted")
	}
	if _, err := binding.EncodeWorkload(nil, 1, [32]byte{}); err == nil {
		t.Fatal("zero session accepted")
	}
	fields := testBindingFields()
	retained, err := NewBinding(testIdentity(), fields)
	if err != nil {
		t.Fatal(err)
	}
	fields["workerId"] = "replaced"
	wire, err := retained.EncodeWorkload([]byte("opaque"), 1, id)
	if err != nil || string(wire) != workloadCodecGolden {
		t.Fatal("caller mutation changed retained binding")
	}
}

func decodeWorkloadCodec(binding Binding, response bool, wire []byte, ordinal uint64, id [32]byte) ([]byte, error) {
	if response {
		return binding.DecodeWorkloadResponse(session.FrameTypeControlResponse, wire, ordinal, id)
	}
	return binding.DecodeWorkloadRequest(session.FrameTypeControlRequest, wire, ordinal, id)
}
