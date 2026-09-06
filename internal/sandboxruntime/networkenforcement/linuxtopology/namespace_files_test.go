package linuxtopology

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxTopologyBorrowedNamespaceFilesAreLiveOnlyAndCloseExactly(t *testing.T) {
	root := t.TempDir()
	user, err := os.OpenFile(filepath.Join(root, "user"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	network, err := os.OpenFile(filepath.Join(root, "network"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := NewNamespaceHandle(user, network)
	if err != nil {
		t.Fatal(err)
	}
	files, err := handle.BorrowFiles()
	if err != nil {
		t.Fatal(err)
	}
	childUser, childNetwork, err := files.DuplicateForCommand()
	if err != nil {
		t.Fatal(err)
	}
	if childUser.Fd() == user.Fd() || childNetwork.Fd() == network.Fd() || childUser.Fd() == childNetwork.Fd() {
		t.Fatal("command namespace descriptors were not independent")
	}
	_ = childUser.Close()
	_ = childNetwork.Close()
	payload, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "{}" {
		t.Fatalf("NamespaceFiles JSON = %s", payload)
	}
	if err := files.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := files.DuplicateForCommand(); !errors.Is(err, ErrStopped) {
		t.Fatalf("DuplicateForCommand() after close = %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
}
