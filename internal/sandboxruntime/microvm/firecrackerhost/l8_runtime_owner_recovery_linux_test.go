//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
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
	genesis := l8RuntimeOwnerTestGenesis(record)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("write through broad directory = %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); err != nil {
		t.Fatalf("idempotent record replay: %v", err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, record, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("revision jump = %v", err)
	}
	next := record
	next.Revision = 1
	if err := writeL8RuntimeOwnerRecord(directory, next, seed, bootID); err != nil {
		t.Fatalf("next revision write: %v", err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("old revision replay after advance = %v", err)
	}
	nextAgain := next
	nextAgain.Revision = 2
	if err := writeL8RuntimeOwnerRecord(directory, nextAgain, seed, bootID); err != nil {
		t.Fatalf("second revision write: %v", err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, next, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("old revision-one replay = %v", err)
	}
	recordPath := filepath.Join(directory, l8RuntimeOwnerRecordName)
	if err := os.Link(recordPath, filepath.Join(directory, "record-hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readL8RuntimeOwnerRecord(directory, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("read hardlinked record = %v", err)
	}
}

func TestL8RuntimeOwnerProcessInspectionPinsPidfdBeforeProcReads(t *testing.T) {
	payload, err := os.ReadFile("l8_runtime_owner_recovery_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	pidfdOpen := strings.Index(source, "unix.PidfdOpen")
	procOpen := strings.Index(source, "unix.Openat(procfd")
	if pidfdOpen < 0 || procOpen < 0 || pidfdOpen > procOpen {
		t.Fatalf("pidfd/proc inspection order is unsafe: pidfd=%d proc=%d", pidfdOpen, procOpen)
	}
	if count := strings.Count(source, "l8RuntimeOwnerProcessAlive(pidfd)"); count < 2 {
		t.Fatalf("pidfd liveness barriers = %d, want at least two", count)
	}
}

func TestL8RuntimeOwnerStoreRequiresGenesisAndExclusiveCAS(t *testing.T) {
	bootID, err := readL8RuntimeOwnerHostBootID()
	if err != nil {
		t.Fatal(err)
	}
	seed := l8RuntimeOwnerTestSeed()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	nonGenesis := l8RuntimeOwnerTestRecord(t, seed, bootID)
	if err := writeL8RuntimeOwnerRecord(directory, nonGenesis, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("missing-record non-genesis write = %v", err)
	}

	genesis := nonGenesis
	genesis.Revision, genesis.State = 0, "starting"
	genesis.FirecrackerPID, genesis.FirecrackerStartTime = 0, 0
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	if err := unix.Flock(directoryFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("write while directory lock held = %v", err)
	}
	if err := unix.Flock(directoryFD, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); err != nil {
		t.Fatalf("genesis write: %v", err)
	}

	const writers = 16
	start := make(chan struct{})
	results := make(chan error, writers)
	var ready sync.WaitGroup
	ready.Add(writers)
	for index := 0; index < writers; index++ {
		index := index
		go func() {
			ready.Done()
			<-start
			next := genesis
			next.Revision = 1
			next.FirecrackerPID, next.FirecrackerStartTime = 303, 404
			next.ReconnectSecret = l8RuntimeOwnerTestToken(byte(index + 10))
			results <- writeL8RuntimeOwnerRecord(directory, next, seed, bootID)
		}()
	}
	ready.Wait()
	close(start)
	successes := 0
	for index := 0; index < writers; index++ {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, errL8RuntimeOwnerInvalid) {
			t.Fatalf("concurrent writer error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent revision-one successes = %d, want exactly one", successes)
	}
}

func TestL8RuntimeOwnerDirectoryRejectsSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	realOwner := filepath.Join(realParent, "owner")
	if err := os.MkdirAll(realOwner, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(root, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	fd, err := openL8RuntimeOwnerDirectory(filepath.Join(linkParent, "owner"))
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("owner directory accepted a symlinked ancestor")
	}
	if !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("symlinked ancestor error = %v", err)
	}
}
