//go:build linux

package vsock

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestL5LinuxConnectionDistinguishesPeerHalfCloseFromFullClose(t *testing.T) {
	socketFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socketpair() error = %v", err)
	}
	connection := &linuxConnection{
		file: os.NewFile(uintptr(socketFDs[0]), "guest-stream-peer-close-test"),
		fd:   socketFDs[0],
	}
	t.Cleanup(func() { _ = connection.Close() })
	peer := os.NewFile(uintptr(socketFDs[1]), "guest-stream-peer-close-fixture")
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- connection.WaitPeerClosed(ctx)
	}()
	if err := unix.Shutdown(socketFDs[1], unix.SHUT_WR); err != nil {
		t.Fatalf("peer half-close error = %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("peer half-close was treated as full close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("peer full close error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitPeerClosed() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer full close was not detected")
	}
}

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
