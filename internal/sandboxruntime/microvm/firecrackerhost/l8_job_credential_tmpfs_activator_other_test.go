//go:build !linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialFileTmpfsActivatorNonLinuxFailsClosedBeforeFiles(t *testing.T) {
	root := t.TempDir()
	activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: root})
	if activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("production constructor = %#v, %v", activator, err)
	}
	if files := l8JobCredentialFileTmpfsOtherFiles(t, root); len(files) != 0 {
		t.Fatalf("non-Linux constructor created files: %d", len(files))
	}

	identity, binding := l8JobCredentialFileTmpfsOtherIdentity(t)
	direct := &L8JobCredentialFileTmpfsActivator{rootDir: root}
	handle, materializeErr := direct.Materialize(context.Background(), identity, binding, &l8JobCredentialFileTmpfsOtherSource{payload: []byte("tmpfs-canary-secret")})
	if handle != nil || !errors.Is(materializeErr, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("non-Linux Materialize = %#v, %v", handle, materializeErr)
	}
	if files := l8JobCredentialFileTmpfsOtherFiles(t, root); len(files) != 0 {
		t.Fatalf("non-Linux Materialize created files: %d", len(files))
	}
}

func l8JobCredentialFileTmpfsOtherIdentity(t *testing.T) (sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest) {
	t.Helper()
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	return identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, SourceReferenceID: "source-file",
	}
}

func l8JobCredentialFileTmpfsOtherFiles(t *testing.T, root string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

type l8JobCredentialFileTmpfsOtherSource struct {
	payload []byte
}

func (source *l8JobCredentialFileTmpfsOtherSource) FillSecret(context.Context, sandboxruntime.JobCredentialSecretSink) error {
	return errors.New("non-linux source must not be filled")
}
