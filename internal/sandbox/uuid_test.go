package sandbox

import (
	"bytes"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestUUIDSourceNewV7_FormatVersionAndVariant(t *testing.T) {
	source := NewUUIDSource(
		func() time.Time { return time.UnixMilli(1_742_554_800_123) },
		bytes.NewReader([]byte{0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}),
	)

	got, err := source.NewV7()
	if err != nil {
		t.Fatalf("NewV7() unexpected error: %v", err)
	}

	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !pattern.MatchString(got) {
		t.Fatalf("NewV7() = %q, want canonical 8-4-4-4-12 lowercase hex", got)
	}

	raw := decodeUUID(t, got)

	if version := raw[6] >> 4; version != 0x7 {
		t.Fatalf("version nibble = 0x%x, want 0x7", version)
	}

	if variant := raw[8] >> 6; variant != 0b10 {
		t.Fatalf("variant bits = 0b%b, want 0b10", variant)
	}
}

func TestUUIDSourceNewV7_MonotonicOrdering(t *testing.T) {
	source := NewUUIDSource(
		func() time.Time { return time.UnixMilli(1_742_554_800_123) },
		bytes.NewReader([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	)

	first, err := source.NewV7()
	if err != nil {
		t.Fatalf("first NewV7() error: %v", err)
	}
	second, err := source.NewV7()
	if err != nil {
		t.Fatalf("second NewV7() error: %v", err)
	}
	third, err := source.NewV7()
	if err != nil {
		t.Fatalf("third NewV7() error: %v", err)
	}

	if !(first < second && second < third) {
		t.Fatalf("UUIDs are not monotonic: %q, %q, %q", first, second, third)
	}
}

func TestUUIDSourceNewV7_RandomFailure(t *testing.T) {
	source := NewUUIDSource(
		func() time.Time { return time.UnixMilli(1_742_554_800_123) },
		errorReader{err: errors.New("rand failed")},
	)

	_, err := source.NewV7()
	if err == nil {
		t.Fatal("NewV7() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "generate uuid v7 random bytes") {
		t.Fatalf("error %q does not contain expected context", err.Error())
	}
}

func decodeUUID(t *testing.T, value string) [16]byte {
	t.Helper()

	hexValue := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(hexValue)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	if len(decoded) != 16 {
		t.Fatalf("decoded UUID length = %d, want 16", len(decoded))
	}

	var raw [16]byte
	copy(raw[:], decoded)
	return raw
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}
