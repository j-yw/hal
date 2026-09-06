//go:build linux && microvm_assets_integration

package minimalprofile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The creation event is emitted after the final debugfs inspection, while
// publication still owns only its private temporary output. Cancellation is
// asserted before the final destination exists, not after a completed build.
func TestMinimalImageRejectsLateCancellation(t *testing.T) {
	requireImageTools(t)
	archive, pins := stagedFixture(t, nil)
	dir := privateDir(t)
	output := filepath.Join(dir, "late.ext4")
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_CREATE); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	digest := fileHash(t, archive)
	go func() {
		_, err := BuildImage(ctx, ImageRequest{Archive: archive, ArchiveSHA256: digest, Output: output, Epoch: 1700000000, Pins: pins})
		done <- err
	}()
	finished := false
	defer func() {
		if !finished {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("cancelled fixture did not stop")
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	var events [4096]byte
	for {
		n, err := unix.Read(fd, events[:])
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			t.Fatal(err)
		}
		if n > 0 && bytes.Contains(events[:n], []byte(".minimal-")) {
			cancel()
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("missed pre-publication cancellation window")
			}
			break
		}
		select {
		case err := <-done:
			finished = true
			t.Fatalf("build ended before publication event: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("publication event did not arrive")
		}
		time.Sleep(time.Millisecond)
	}
	err = <-done
	finished = true
	if err == nil {
		t.Fatal("late cancellation returned successful image")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("late cancellation published output")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled publication leaked temporary output: %v %v", entries, err)
	}
}
