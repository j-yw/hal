//go:build !windows

package compound

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHashUntrackedFilesInDirRecordsSpecialFilesWithoutReading(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "input.fifo")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Skipf("Mkfifo() unavailable: %v", err)
	}

	got, err := hashUntrackedFilesInDir(dir, "input.fifo\x00")
	if err != nil {
		t.Fatalf("hashUntrackedFilesInDir() error = %v", err)
	}
	if !strings.Contains(got, "input.fifo\x00") || !strings.Contains(got, "special:") {
		t.Fatalf("hashUntrackedFilesInDir() = %q, want special file metadata", got)
	}
	if strings.Contains(got, "file:") {
		t.Fatalf("hashUntrackedFilesInDir() = %q, should not hash FIFO content", got)
	}
}
