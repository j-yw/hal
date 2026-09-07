//go:build linux || darwin

package sandboxworker

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO is an unprivileged local filesystem fixture, not a runtime IPC
// channel. A controlled writer exists only to quiesce the old blocking RED.
func TestMinimalLaunchFIFOReadbackCannotBlockCancellationAndClose(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	s := f.service(t)
	original := s.jobs.store.minimalOps.rename
	created := make(chan string, 1)
	s.jobs.store.minimalOps.rename = func(old, new string) error {
		if err := original(old, new); err != nil {
			return err
		}
		path := filepath.Join(f.stateDir, new)
		if err := os.Rename(path, path+".original"); err != nil {
			return err
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			return err
		}
		created <- path
		return nil
	}
	requestDone, closeDone := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(requestDone)
		_ = s.HandleAuthenticatedRequest(ctx, f.principal, f.request)
	}()
	var path string
	select {
	case path = <-created:
	case <-requestDone:
		// Fast nonblocking rejection may complete with the earlier FIFO event
		// still buffered. Completion alone does not mean setup was bypassed.
		select {
		case path = <-created:
		default:
			t.Fatal("actual readback FIFO seam was not reached")
		}
	case <-time.After(time.Second):
		t.Fatal("readback fixture did not reach rename")
	}
	cancel()
	go func() { s.Close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(250 * time.Millisecond):
		t.Error("FIFO readback blocked cancellation and joined Close under manager mutex")
	}
	// Always quiesce the failing implementation. Opening this fixture read-
	// write/nonblocking wakes its old read-only open, whose Stat then rejects.
	writer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, done := range []<-chan struct{}{requestDone, closeDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("FIFO regression did not quiesce")
		}
	}
	if f.provider.startCalls != 0 || !s.jobs.minimalPoisoned || len(s.jobs.minimalLive) != 1 {
		t.Fatal("nonregular readback lost uncertain ownership or entered provider")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("uncertain FIFO entry was removed or replaced")
	}
	if _, err := os.Stat(path + ".original"); err != nil {
		t.Fatal("original published record was not retained")
	}
}
