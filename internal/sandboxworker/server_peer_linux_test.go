//go:build linux

package sandboxworker

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateWorkerPeerUID(t *testing.T) {
	currentUID := uint32(os.Geteuid())
	if err := validateWorkerPeerUID(currentUID, currentUID); err != nil {
		t.Fatalf("validateWorkerPeerUID(same user) error: %v", err)
	}
	err := validateWorkerPeerUID(currentUID+1, currentUID)
	if err == nil {
		t.Fatal("validateWorkerPeerUID(different user) error = nil")
	}
	if strings.Contains(err.Error(), "uid") || strings.Contains(err.Error(), "UID") {
		t.Fatalf("validateWorkerPeerUID() exposed identity detail: %v", err)
	}
}

func TestValidateWorkerPeerIdentityRequiresExactUIDAndGID(t *testing.T) {
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())
	if err := validateWorkerPeerIdentity(workerPeerIdentity{uid: currentUID, gid: currentGID}, currentUID, currentGID); err != nil {
		t.Fatalf("validateWorkerPeerIdentity(exact owner) error: %v", err)
	}
	for _, peer := range []workerPeerIdentity{
		{uid: currentUID + 1, gid: currentGID},
		{uid: currentUID, gid: currentGID + 1},
	} {
		err := validateWorkerPeerIdentity(peer, currentUID, currentGID)
		if err == nil {
			t.Fatalf("validateWorkerPeerIdentity(%#v) error = nil", peer)
		}
		if strings.Contains(strings.ToLower(err.Error()), "uid") || strings.Contains(strings.ToLower(err.Error()), "gid") {
			t.Fatalf("validateWorkerPeerIdentity() exposed identity detail: %v", err)
		}
	}
}

func TestValidateWorkerPeerCredentialsAcceptsSameUser(t *testing.T) {
	parent := filepath.Join(resolvedWorkerTempDir(t), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir(parent) error: %v", err)
	}
	socketPath := filepath.Join(parent, "peer.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix) error: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial(unix) error: %v", err)
	}
	defer client.Close()

	select {
	case err := <-acceptErr:
		t.Fatalf("Accept() error: %v", err)
	case conn := <-accepted:
		defer conn.Close()
		if err := validateWorkerPeerCredentials(conn, true); err != nil {
			t.Fatalf("validateWorkerPeerCredentials(same user) error: %v", err)
		}
	}
}
