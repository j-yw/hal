package firecrackerhost

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Independently laid out from the approved offset table, not from the codec.
// Public fixture bytes only: config 01..20, supervisor base64(01 repeated 32),
// process fc-handle-7, counter 0102030405060708, session 21..40, binding 41..60.
const minimalReadinessGoldenHex = "484c4d494e524431000100000000000000010000000000000002" +
	"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"41514542415145424151454241514542415145424151454241514542415145424151454241514542415145" +
	"0b66632d68616e646c652d37" + "0102030405060708" +
	"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" +
	"4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"

func minimalReadinessGolden(t *testing.T) ([]byte, minimalControlReadinessEventV1) {
	t.Helper()
	wire, err := hex.DecodeString(minimalReadinessGoldenHex)
	if err != nil {
		t.Fatal(err)
	}
	value := minimalControlReadinessEventV1{supervisorGeneration: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
		processGeneration: "fc-handle-7", transportGeneration: 0x0102030405060708}
	for i := range 32 {
		value.configSHA256[i], value.sessionID[i], value.readinessBindingSHA256[i] = byte(i+1), byte(i+33), byte(i+65)
	}
	return wire, value
}

func TestMinimalReadinessEventGoldenLayoutControl(t *testing.T) {
	wire, value := minimalReadinessGolden(t)
	if len(wire) != 185 || string(wire[:8]) != "HLMINRD1" || binary.BigEndian.Uint16(wire[8:10]) != 1 ||
		binary.BigEndian.Uint64(wire[10:18]) != 1 || binary.BigEndian.Uint64(wire[18:26]) != 2 ||
		!bytes.Equal(wire[26:58], value.configSHA256[:]) || string(wire[58:101]) != value.supervisorGeneration ||
		wire[101] != 11 || string(wire[102:113]) != value.processGeneration ||
		binary.BigEndian.Uint64(wire[113:121]) != value.transportGeneration ||
		!bytes.Equal(wire[121:153], value.sessionID[:]) || !bytes.Equal(wire[153:185], value.readinessBindingSHA256[:]) {
		t.Fatal("independent golden fixture does not match approved offsets")
	}
	supervisor, err := base64.RawURLEncoding.DecodeString(value.supervisorGeneration)
	if err != nil || !bytes.Equal(supervisor, bytes.Repeat([]byte{1}, 32)) || !validL8RuntimeOwnerToken(value.supervisorGeneration) ||
		!validL8RuntimeOwnerSafeID(value.processGeneration) || l8RuntimeOwnerPacketLimit != 512 {
		t.Fatal("existing token/transport prerequisite changed")
	}
}

func TestMinimalReadinessEventEncodesIndependentGolden(t *testing.T) {
	want, value := minimalReadinessGolden(t)
	got, err := encodeMinimalControlReadinessEvent(value)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("approved readiness event encoder unavailable or differs from golden: %v", err)
	}
}

func TestMinimalReadinessEventDecodesIndependentGolden(t *testing.T) {
	wire, want := minimalReadinessGolden(t)
	got, err := decodeMinimalControlReadinessEvent(wire)
	if err != nil || got != want {
		t.Fatalf("approved readiness event decoder unavailable or differs from golden: %v", err)
	}
}

func TestMinimalReadinessEventLegacyWireControl(t *testing.T) {
	// Existing revision-2 bootstrap reply, independently fixed legacy bytes.
	want, err := hex.DecodeString("484c384f574e5231000100020000000800000000000000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapPublished, Body: []byte{0, 0, 0, 0, 0, 0, 0, 2}}
	wire, err := encodeL8RuntimeOwnerPacket(packet)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatal("existing bootstrap reply bytes changed", err)
	}
	decoded, err := decodeL8RuntimeOwnerPacket(want)
	if err != nil || !reflect.DeepEqual(decoded, packet) || validateL8RuntimeOwnerPacketRole(decoded, true, 0) != nil {
		t.Fatal("existing bootstrap reply decode/role changed", err)
	}
	gold, _ := minimalReadinessGolden(t)
	if _, err := decodeL8RuntimeOwnerPacket(gold); !errors.Is(err, errL8RuntimeOwnerProtocol) {
		t.Fatal("legacy packet decoder accepted selected event")
	}
	if got, err := decodeMinimalControlReadinessEvent(want); !errors.Is(err, errL8RuntimeOwnerProtocol) || got != (minimalControlReadinessEventV1{}) {
		t.Fatal("selected decoder accepted legacy cleanup packet")
	}
}

func TestMinimalReadinessEventMalformedWireAndBounds(t *testing.T) {
	wire, want := minimalReadinessGolden(t)
	if got, err := decodeMinimalControlReadinessEvent(wire); err != nil || got != want {
		t.Fatal("valid decoder prerequisite; later negative matrix not reached", err)
	}
	for size := 0; size < len(wire); size++ {
		minimalReadinessRejectWire(t, wire[:size])
	}
	for _, bad := range [][]byte{append(bytes.Clone(wire), 0), append(bytes.Clone(wire), wire...), make([]byte, 239), make([]byte, 513)} {
		minimalReadinessRejectWire(t, bad)
	}
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"magic", func(b []byte) { b[0] ^= 1 }},
		{"version", func(b []byte) { binary.BigEndian.PutUint16(b[8:10], 2) }},
		{"version_little_endian", func(b []byte) { binary.LittleEndian.PutUint16(b[8:10], 1) }},
		{"sequence_zero", func(b []byte) { clear(b[10:18]) }},
		{"sequence_two", func(b []byte) { binary.BigEndian.PutUint64(b[10:18], 2) }},
		{"sequence_little_endian", func(b []byte) { binary.LittleEndian.PutUint64(b[10:18], 1) }},
		{"revision_one", func(b []byte) { binary.BigEndian.PutUint64(b[18:26], 1) }},
		{"revision_little_endian", func(b []byte) { binary.LittleEndian.PutUint64(b[18:26], 2) }},
		{"config_zero", func(b []byte) { clear(b[26:58]) }},
		{"supervisor_zero", func(b []byte) { copy(b[58:101], strings.Repeat("A", 43)) }},
		{"supervisor_alias_bits", func(b []byte) { b[100] = 'F' }},
		{"supervisor_padding", func(b []byte) { b[100] = '=' }},
		{"supervisor_alphabet", func(b []byte) { b[58] = '+' }},
		{"length_zero", func(b []byte) { b[101] = 0 }},
		{"length_mismatch", func(b []byte) { b[101] = 10 }},
		{"length_65", func(b []byte) { b[101] = 65 }},
		{"length_255", func(b []byte) { b[101] = 255 }},
		{"process_leading_punctuation", func(b []byte) { b[102] = '-' }},
		{"process_colon", func(b []byte) { b[104] = ':' }},
		{"process_nul", func(b []byte) { b[104] = 0 }},
		{"process_non_ascii", func(b []byte) { b[104] = 0xff }},
		{"transport_zero", func(b []byte) { clear(b[113:121]) }},
		{"session_zero", func(b []byte) { clear(b[121:153]) }},
		{"binding_zero", func(b []byte) { clear(b[153:185]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bytes.Clone(wire)
			tc.edit(bad)
			minimalReadinessRejectWire(t, bad)
		})
	}
}

func minimalReadinessRejectWire(t *testing.T, wire []byte) {
	t.Helper()
	before := bytes.Clone(wire)
	got, err := decodeMinimalControlReadinessEvent(wire)
	if !errors.Is(err, errL8RuntimeOwnerProtocol) || err.Error() != errL8RuntimeOwnerProtocol.Error() ||
		got != (minimalControlReadinessEventV1{}) || !bytes.Equal(wire, before) {
		t.Fatal("invalid event did not fail with sanitized zero result and immutable input")
	}
}

func TestMinimalReadinessEventValueVocabularyAndExtents(t *testing.T) {
	wire, value := minimalReadinessGolden(t)
	if got, err := encodeMinimalControlReadinessEvent(value); err != nil || !bytes.Equal(got, wire) {
		t.Fatal("valid encoder prerequisite; later value matrix not reached", err)
	}
	for _, process := range []string{"a", "0", "Z.a_-9", strings.Repeat("a", 64)} {
		t.Run("valid_"+process, func(t *testing.T) {
			current := value
			current.processGeneration = process
			got, err := encodeMinimalControlReadinessEvent(current)
			if err != nil || len(got) != 174+len(process) || got[101] != byte(len(process)) {
				t.Fatal("exact 1..64 process extent rejected", err)
			}
			decoded, err := decodeMinimalControlReadinessEvent(got)
			if err != nil || decoded != current {
				t.Fatal("valid exact extent did not decode", err)
			}
		})
	}
	for _, process := range []string{"", strings.Repeat("a", 65), ".a", "_a", "-a", "a:b", "a/b", " a", "a ", "a\n", "a\x00", "é"} {
		bad := value
		bad.processGeneration = process
		minimalReadinessRejectValue(t, bad)
	}
	for _, change := range []func(*minimalControlReadinessEventV1){
		func(e *minimalControlReadinessEventV1) { e.configSHA256 = [32]byte{} },
		func(e *minimalControlReadinessEventV1) { e.supervisorGeneration = strings.Repeat("A", 43) },
		func(e *minimalControlReadinessEventV1) { e.supervisorGeneration += "=" },
		func(e *minimalControlReadinessEventV1) { e.supervisorGeneration = e.supervisorGeneration[:42] + "F" },
		func(e *minimalControlReadinessEventV1) { e.transportGeneration = 0 },
		func(e *minimalControlReadinessEventV1) { e.sessionID = [32]byte{} },
		func(e *minimalControlReadinessEventV1) { e.readinessBindingSHA256 = [32]byte{} },
	} {
		bad := value
		change(&bad)
		minimalReadinessRejectValue(t, bad)
	}
}

func minimalReadinessRejectValue(t *testing.T, value minimalControlReadinessEventV1) {
	t.Helper()
	got, err := encodeMinimalControlReadinessEvent(value)
	if !errors.Is(err, errL8RuntimeOwnerProtocol) || err.Error() != errL8RuntimeOwnerProtocol.Error() || got != nil {
		t.Fatal("invalid value did not produce sanitized unavailable bytes")
	}
}

func TestMinimalReadinessEventOwnedBytesAndStatelessScope(t *testing.T) {
	wire, want := minimalReadinessGolden(t)
	got, err := decodeMinimalControlReadinessEvent(wire)
	if err != nil || got != want {
		t.Fatal("valid decoder prerequisite; ownership/stateless checks not reached", err)
	}
	clear(wire)
	if got != want {
		t.Fatal("decoded event aliases caller bytes")
	}
	first, err := encodeMinimalControlReadinessEvent(got)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeMinimalControlReadinessEvent(got)
	if err != nil {
		t.Fatal(err)
	}
	clear(first)
	for i := 0; i < 2; i++ {
		if decoded, err := decodeMinimalControlReadinessEvent(second); err != nil || decoded != want {
			t.Fatal("fresh output aliases other encoding or codec invented replay state", err)
		}
	}
	// Valid field substitutions are metadata, not codec authentication errors.
	for _, offset := range []int{26, 102, 121, 153} {
		changed := bytes.Clone(second)
		changed[offset] ^= 1
		if decoded, err := decodeMinimalControlReadinessEvent(changed); err != nil || decoded == want {
			t.Fatal("syntactically valid substituted value did not decode distinctly", err)
		}
	}
	changed := bytes.Clone(second)
	binary.LittleEndian.PutUint64(changed[113:121], want.transportGeneration)
	decoded, err := decodeMinimalControlReadinessEvent(changed)
	if err != nil || decoded.transportGeneration != 0x0807060504030201 {
		t.Fatal("counter must decode in network order; expected-counter comparison is stateful", err)
	}
}
