//go:build linux

package vsock

import (
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestL5LinuxConnectionConcurrentCancellationIsRaceSafe(t *testing.T) {
	socketFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socketpair() error = %v", err)
	}
	if err := unix.SetNonblock(socketFDs[0], true); err != nil {
		t.Fatalf("SetNonblock() error = %v", err)
	}
	connection := &linuxConnection{
		file: os.NewFile(uintptr(socketFDs[0]), "guest-stream-test"),
		fd:   socketFDs[0],
	}
	peer := os.NewFile(uintptr(socketFDs[1]), "guest-stream-peer-test")
	defer peer.Close()

	readStarted := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		close(readStarted)
		var buffer [1]byte
		_, _ = connection.Read(buffer[:])
	}()
	<-readStarted

	var operations sync.WaitGroup
	operations.Add(3)
	go func() {
		defer operations.Done()
		_, _ = connection.Write([]byte("x"))
	}()
	go func() {
		defer operations.Done()
		_ = connection.CloseWrite()
	}()
	go func() {
		defer operations.Done()
		_ = connection.Close()
		_ = connection.Close()
	}()
	operations.Wait()

	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("concurrent close did not release blocked stream read")
	}
}
