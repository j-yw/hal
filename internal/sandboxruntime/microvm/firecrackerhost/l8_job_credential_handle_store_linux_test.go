//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

func TestL8JobCredentialLinuxHandleStorePersistsMetadataBesideOwnerDirectory(t *testing.T) {
	directory := l8JobCredentialHandleStoreTestDir(t)
	store, err := NewProductionL8JobCredentialHandleStore(directory)
	if err != nil || store == nil {
		t.Fatalf("NewProductionL8JobCredentialHandleStore = %#v, %v", store, err)
	}

	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, httpProxy, tmpfs, nil)
	runtime.deps.HandleStore = store
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preflight.PrepareJobCredentials(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, l8JobCredentialHandleRecordName(digest))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %o, want 0600", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-bytes", "tmpfs-canary", "/tmp/", "/private/", "sk_live", directory} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("linux handle record leaked %q: %s", forbidden, payload)
		}
	}

	loaded, present, err := store.Load(context.Background(), identity)
	if err != nil || !present || loaded.Revision != 1 || loaded.Bindings[0].ServiceID != "azure-openai-responses-v1" {
		t.Fatalf("linux load = %#v present=%t err=%v", loaded, present, err)
	}

	proof, recoverErr := runtime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if recoverErr != nil {
		t.Fatal(recoverErr)
	}
	if err := sandboxruntime.ValidateJobCredentialCleanupProof(proof, identity, 2, now.Add(2*time.Second)); err != nil {
		t.Fatalf("linux recover proof: %v", err)
	}
}

func TestL8JobCredentialLinuxHandleStoreRejectsBroadDirectoryAndHardlinks(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if store, err := NewProductionL8JobCredentialHandleStore(directory); store != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("0755 directory = %#v, %v", store, err)
	}

	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewProductionL8JobCredentialHandleStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	now := l8JobCredentialRuntimeNow()
	_, identity, _ := l8JobCredentialRuntimePrepareFixture(t, now)
	record, err := l8JobCredentialHandleRecordFromManifests(identity, 1, []l8JobCredentialGuestBindingManifest{
		{BindingID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeHTTPProxy, ServiceID: "azure-openai-responses-v1"},
		{BindingID: identity.BindingIDs[1], Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, TargetPath: identity.BindingIDs[1], DeclaredFileBytes: 4, FileSHA256: "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, l8JobCredentialHandleRecordName(digest))
	if err := os.Link(path, filepath.Join(directory, "handle-hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, present, err := store.Load(context.Background(), identity); present || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("hardlinked record load present=%t err=%v", present, err)
	}
}

func TestL8JobCredentialLinuxHandleStoreDoesNotFollowSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if store, err := NewProductionL8JobCredentialHandleStore(link); store != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("symlink directory = %#v, %v", store, err)
	}
	entries, err := os.ReadDir(realDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink constructor created files: %d", len(entries))
	}
}

func TestL8JobCredentialLinuxHandleStoreRedactsAndDeniesSerialization(t *testing.T) {
	store, err := NewProductionL8JobCredentialHandleStore(l8JobCredentialHandleStoreTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if encoded, marshalErr := json.Marshal(store); marshalErr == nil || encoded != nil || !errors.Is(marshalErr, ErrL8JobCredentialRuntimeSerialization) {
		t.Fatalf("json.Marshal(linux store) = %q, %v", encoded, marshalErr)
	}
	for _, rendered := range []string{fmt.Sprint(store), fmt.Sprintf("%#v", store), fmt.Sprintf("%+v", store)} {
		if rendered != l8JobCredentialHandleStoreValuePlaceholder {
			t.Fatalf("format linux store = %q", rendered)
		}
	}
}

func TestL8JobCredentialLinuxHandleStoreLockContentionFailsClosed(t *testing.T) {
	directory := l8JobCredentialHandleStoreTestDir(t)
	store, err := NewProductionL8JobCredentialHandleStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	if err := unix.Flock(directoryFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	now := l8JobCredentialRuntimeNow()
	_, identity, _ := l8JobCredentialRuntimePrepareFixture(t, now)
	record, err := l8JobCredentialHandleRecordFromManifests(identity, 1, []l8JobCredentialGuestBindingManifest{
		{BindingID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeHTTPProxy, ServiceID: "azure-openai-responses-v1"},
		{BindingID: identity.BindingIDs[1], Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, TargetPath: identity.BindingIDs[1], DeclaredFileBytes: 4, FileSHA256: "aa" + "bb" + "cc" + "dd" + "ee" + "ff" + "01" + "23" + "45" + "67" + "89" + "ab" + "cd" + "ef" + "01" + "23" + "aa" + "bb" + "cc" + "dd" + "ee" + "ff" + "01" + "23" + "45" + "67" + "89" + "ab" + "cd" + "ef" + "01" + "23"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), record); !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("save while directory lock held = %v", err)
	}
}

func l8JobCredentialHandleStoreTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

var _ l8JobCredentialHandleStore = (*l8JobCredentialLinuxHandleStore)(nil)
