//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8RuntimeOwnerProcStatParserUsesExactField22(t *testing.T) {
	fields := []string{"S"}
	for index := 0; index < 18; index++ {
		fields = append(fields, strconv.Itoa(index+1))
	}
	fields = append(fields, "424242")
	payload := []byte("123 (firecracker ) helper) " + strings.Join(fields, " ") + "\n")
	startTime, state, err := parseL8RuntimeOwnerProcStat(payload, 123)
	if err != nil || startTime != 424242 || state != 'S' {
		t.Fatalf("parsed proc stat = %d %q, %v", startTime, state, err)
	}
	for _, malformed := range [][]byte{
		payload[:len(payload)-8],
		[]byte("124 (firecracker) " + strings.Join(fields, " ") + "\n"),
		[]byte("123 firecracker " + strings.Join(fields, " ") + "\n"),
		[]byte("123 (firecracker) S 1 2\n"),
	} {
		if _, _, err := parseL8RuntimeOwnerProcStat(malformed, 123); !errors.Is(err, errL8RuntimeOwnerInvalid) {
			t.Errorf("malformed proc stat = %v", err)
		}
	}
}

func TestL8RuntimeOwnerStoreRejectsDirectoryModeAndHardlinks(t *testing.T) {
	bootID, err := readL8RuntimeOwnerHostBootID()
	if err != nil {
		t.Fatal(err)
	}
	seed := l8RuntimeOwnerTestSeed()
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, record, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("write through broad directory = %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, record, seed, bootID); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, record, seed, bootID); err != nil {
		t.Fatalf("idempotent record replay: %v", err)
	}
	stale := record
	stale.Revision--
	if err := writeL8RuntimeOwnerRecord(directory, stale, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("stale record replay = %v", err)
	}
	next := record
	next.Revision++
	if err := writeL8RuntimeOwnerRecord(directory, next, seed, bootID); err != nil {
		t.Fatalf("next revision write: %v", err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, record, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("old revision replay after advance = %v", err)
	}
	recordPath := filepath.Join(directory, l8RuntimeOwnerRecordName)
	if err := os.Link(recordPath, filepath.Join(directory, "record-hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readL8RuntimeOwnerRecord(directory, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("read hardlinked record = %v", err)
	}
}
