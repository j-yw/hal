//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestL8JobCredentialFileTmpfsActivatorLinuxConstructorRequiresScratchRoot(t *testing.T) {
	if l8JobCredentialFileTmpfsMaxBytes != credentialprotocol.MaxHelperFileBytes {
		t.Fatalf("host file-tmpfs max = %d, want helper bound %d", l8JobCredentialFileTmpfsMaxBytes, credentialprotocol.MaxHelperFileBytes)
	}
	root := t.TempDir()
	activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: root})
	if err != nil || activator == nil || activator.rootDir == "" {
		t.Fatalf("NewProductionL8JobCredentialFileTmpfsActivator = %#v, %v", activator, err)
	}

	missing := filepath.Join(root, "missing")
	if activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: missing}); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("missing root = %#v, %v", activator, err)
	}
	if activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{}); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("empty root = %#v, %v", activator, err)
	}
	if activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: "relative-scratch"}); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("relative root = %#v, %v", activator, err)
	}

	halDir := filepath.Join(root, ".hal")
	if err := os.Mkdir(halDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: halDir}); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf(".hal root = %#v, %v", activator, err)
	}
	link := filepath.Join(root, "scratch-link")
	if err := os.Symlink(halDir, link); err != nil {
		t.Fatal(err)
	}
	if activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: link}); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("symlink into .hal = %#v, %v", activator, err)
	}
}

func TestL8JobCredentialFileTmpfsActivatorMaterializeFillsHashAndGuestPath(t *testing.T) {
	activator := l8JobCredentialFileTmpfsActivatorForTest(t)
	identity, binding := l8JobCredentialFileTmpfsIdentity(t)
	payload := []byte("tmpfs-canary-secret")
	source := &l8JobCredentialFileTmpfsSource{payload: append([]byte(nil), payload...)}

	handle, err := activator.Materialize(context.Background(), identity, binding, source)
	if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
		t.Fatalf("Materialize = %#v, %v", handle, err)
	}
	if source.fills != 1 {
		t.Fatalf("FillSecret calls = %d, want 1", source.fills)
	}
	source.payload = []byte("mutated-after-fill")
	source = nil

	sum := sha256.Sum256(payload)
	if handle.TargetPath() != binding.ID {
		t.Fatalf("TargetPath = %q, want binding ID %q", handle.TargetPath(), binding.ID)
	}
	if filepath.IsAbs(handle.TargetPath()) {
		t.Fatalf("TargetPath used a host absolute path: %q", handle.TargetPath())
	}
	if handle.DeclaredFileBytes() != uint32(len(payload)) || handle.FileSHA256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("file metadata = %d %q", handle.DeclaredFileBytes(), handle.FileSHA256())
	}

	root := activator.rootDir
	if strings.Contains(handle.TargetPath(), root) {
		t.Fatalf("TargetPath leaked host root %q", handle.TargetPath())
	}
	files := l8JobCredentialFileTmpfsRegularFiles(t, root)
	if len(files) != 1 {
		t.Fatalf("host materialization files = %d, want 1", len(files))
	}
	got, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("host materialization payload mismatch")
	}
	if handle.TargetPath() == files[0] {
		t.Fatal("TargetPath returned the host materialization path")
	}

	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if leftover := l8JobCredentialFileTmpfsRegularFiles(t, root); len(leftover) != 0 {
		t.Fatalf("revoke left host files: %d", len(leftover))
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("idempotent Revoke: %v", err)
	}
}

func TestL8JobCredentialFileHandleFailedRevokeKeepsOwnership(t *testing.T) {
	activator := l8JobCredentialFileTmpfsActivatorForTest(t)
	identity, binding := l8JobCredentialFileTmpfsIdentity(t)
	handle, err := activator.Materialize(context.Background(), identity, binding, &l8JobCredentialFileTmpfsSource{payload: []byte("tmpfs-canary-secret")})
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := os.ReadDir(activator.rootDir)
	if err != nil || len(dirs) != 1 || !dirs[0].IsDir() {
		t.Fatalf("materialization dirs = %v, %v", dirs, err)
	}
	uniqueDir := filepath.Join(activator.rootDir, dirs[0].Name())
	if err := os.Chmod(uniqueDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(uniqueDir, 0o700) })

	revokeErr := handle.Revoke(context.Background())
	if revokeErr == nil {
		t.Fatal("Revoke succeeded while unlink was denied")
	}
	l8JobCredentialRuntimeAssertSafeError(t, revokeErr)
	if leftover := l8JobCredentialFileTmpfsRegularFiles(t, activator.rootDir); len(leftover) != 1 {
		t.Fatalf("failed revoke dropped host file ownership: leftover=%d", len(leftover))
	}

	if err := os.Chmod(uniqueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("retry Revoke: %v", err)
	}
	if leftover := l8JobCredentialFileTmpfsRegularFiles(t, activator.rootDir); len(leftover) != 0 {
		t.Fatalf("retry revoke left host files: %d", len(leftover))
	}
}

func TestL8JobCredentialFileTmpfsActivatorFailClosedOnOversizeEmptyNilSourceCancelAndIdentity(t *testing.T) {
	activator := l8JobCredentialFileTmpfsActivatorForTest(t)
	identity, binding := l8JobCredentialFileTmpfsIdentity(t)
	canary := []byte("sk_live_tmpfs_canary")

	oversize := bytes.Repeat([]byte("x"), l8JobCredentialFileTmpfsMaxBytes+1)
	oversize[0] = 's'
	copy(oversize[1:], canary)
	handle, err := activator.Materialize(context.Background(), identity, binding, &l8JobCredentialFileTmpfsSource{payload: oversize, ignoreMax: true})
	if !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("oversize = %#v, %v", handle, err)
	}
	l8JobCredentialFileTmpfsAssertSafeError(t, err, canary)
	if files := l8JobCredentialFileTmpfsRegularFiles(t, activator.rootDir); len(files) != 0 {
		t.Fatal("oversize created host files")
	}

	if handle, err := activator.Materialize(context.Background(), identity, binding, &l8JobCredentialFileTmpfsSource{}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("empty = %#v, %v", handle, err)
	}
	if handle, err := activator.Materialize(context.Background(), identity, binding, &l8JobCredentialFileTmpfsSource{skipWrite: true}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("empty-when-required = %#v, %v", handle, err)
	}

	var typedNil *l8JobCredentialFileTmpfsSource
	var nilSource sandboxruntime.LiveSecretSource = typedNil
	if handle, err := activator.Materialize(context.Background(), identity, binding, nil); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("nil source = %#v, %v", handle, err)
	}
	if handle, err := activator.Materialize(context.Background(), identity, binding, nilSource); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("typed-nil source = %#v, %v", handle, err)
	}

	var ctx context.Context
	if handle, err := activator.Materialize(ctx, identity, binding, &l8JobCredentialFileTmpfsSource{payload: canary}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("nil context = %#v, %v", handle, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if handle, err := activator.Materialize(canceled, identity, binding, &l8JobCredentialFileTmpfsSource{payload: canary}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %#v, %v", handle, err)
	}

	wrongMode := binding
	wrongMode.Mode = sandboxruntime.JobCredentialDeliveryModeHTTPProxy
	if handle, err := activator.Materialize(context.Background(), identity, wrongMode, &l8JobCredentialFileTmpfsSource{payload: canary}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("wrong mode = %#v, %v", handle, err)
	}

	unknown := binding
	unknown.ID = "binding-unknown"
	if handle, err := activator.Materialize(context.Background(), identity, unknown, &l8JobCredentialFileTmpfsSource{payload: canary}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("unknown binding = %#v, %v", handle, err)
	}

	httpIdentity := identity
	httpIdentity.DeliveryModes = []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy}
	httpIdentity.NetworkPlanID = "network-plan-runtime"
	httpIdentity.PolicySnapshotID = "policy-snapshot-runtime"
	httpIdentity.ProxySessionID = "proxy-session-runtime"
	httpIdentity.ProxyGenerationID = "proxy-generation-runtime"
	httpIdentity.TopologyGenerationID = "topology-generation-runtime"
	httpIdentity.RuleGenerationID = "rule-generation-runtime"
	if handle, err := activator.Materialize(context.Background(), httpIdentity, binding, &l8JobCredentialFileTmpfsSource{payload: canary}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("mode mismatch identity = %#v, %v", handle, err)
	}

	partial := identity
	partial.SandboxID = ""
	if handle, err := activator.Materialize(context.Background(), partial, binding, &l8JobCredentialFileTmpfsSource{payload: canary}); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("partial identity = %#v, %v", handle, err)
	}

	if files := l8JobCredentialFileTmpfsRegularFiles(t, activator.rootDir); len(files) != 0 {
		t.Fatal("fail-closed paths created host files")
	}
}

func TestL8JobCredentialFileTmpfsActivatorSanitizesSourceErrors(t *testing.T) {
	activator := l8JobCredentialFileTmpfsActivatorForTest(t)
	identity, binding := l8JobCredentialFileTmpfsIdentity(t)
	canary := []byte("sk_live_tmpfs_canary path=/private/secret.sock")
	handle, err := activator.Materialize(context.Background(), identity, binding, &l8JobCredentialFileTmpfsSource{err: errors.New(string(canary))})
	if !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeUnavailable) {
		t.Fatalf("source error = %#v, %v", handle, err)
	}
	l8JobCredentialFileTmpfsAssertSafeError(t, err, canary)
}

func TestL8JobCredentialFileTmpfsActivatorMaterializeMetadataReachesGuestPrepare(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	request := l8JobCredentialRuntimePrepareRequest(t, identity)
	payload := []byte("secret-bytes-" + identity.BindingIDs[0])
	request.AuthorizedSources[0].Source = &l8JobCredentialFileTmpfsSource{payload: append([]byte(nil), payload...)}
	tmpfs := l8JobCredentialFileTmpfsActivatorForTest(t)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, nil, tmpfs, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil || l8JobCredentialRuntimeValueIsNil(session) {
		t.Fatalf("PrepareJobCredentials = %#v, %v", session, err)
	}
	if len(guest.lastManifests) != 1 {
		t.Fatalf("guest manifests = %d, want 1", len(guest.lastManifests))
	}
	sum := sha256.Sum256(payload)
	manifest := guest.lastManifests[0]
	if manifest.TargetPath != identity.BindingIDs[0] || filepath.IsAbs(manifest.TargetPath) || strings.Contains(manifest.TargetPath, tmpfs.rootDir) {
		t.Fatalf("guest TargetPath = %q", manifest.TargetPath)
	}
	if manifest.DeclaredFileBytes != uint32(len(payload)) || manifest.FileSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("guest file metadata = %d %q", manifest.DeclaredFileBytes, manifest.FileSHA256)
	}
	if _, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested")); err != nil {
		t.Fatal(err)
	}
	if leftover := l8JobCredentialFileTmpfsRegularFiles(t, tmpfs.rootDir); len(leftover) != 0 {
		t.Fatalf("session revoke left host files: %d", len(leftover))
	}
}

func l8JobCredentialFileTmpfsActivatorForTest(t *testing.T) *L8JobCredentialFileTmpfsActivator {
	t.Helper()
	activator, err := NewProductionL8JobCredentialFileTmpfsActivator(L8JobCredentialFileTmpfsActivatorOptions{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return activator
}

func l8JobCredentialFileTmpfsIdentity(t *testing.T) (sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest) {
	t.Helper()
	now := time.Date(2026, time.August, 28, 1, 2, 3, 0, time.UTC)
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	return identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, SourceReferenceID: "source-file",
	}
}

func l8JobCredentialFileTmpfsRegularFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func l8JobCredentialFileTmpfsAssertSafeError(t *testing.T, err error, canary []byte) {
	t.Helper()
	l8JobCredentialRuntimeAssertSafeError(t, err)
	if err == nil {
		return
	}
	text := err.Error()
	if strings.Contains(text, string(canary)) || strings.Contains(text, "sk_live") || strings.Contains(text, "/private/") {
		t.Fatalf("error leaked canary: %v", err)
	}
}

type l8JobCredentialFileTmpfsSource struct {
	mu        sync.Mutex
	payload   []byte
	fills     int
	skipWrite bool
	ignoreMax bool
	err       error
}

func (source *l8JobCredentialFileTmpfsSource) FillSecret(ctx context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.fills++
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if source.err != nil {
		return source.err
	}
	if source.skipWrite {
		return nil
	}
	if !source.ignoreMax && len(source.payload) > sink.MaxCredentialBytes() {
		return ErrL8JobCredentialRuntimeInvalid
	}
	return sink.WriteCredential(source.payload)
}
