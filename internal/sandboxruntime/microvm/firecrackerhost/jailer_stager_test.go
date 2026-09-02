package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStageStrictJailerResourcesCreatesExactPrivateTree(t *testing.T) {
	request := validJailerStagingRequest()
	filesystem := newFakeJailerStagingFilesystem()

	result, err := stageStrictJailerResources(filesystem, request)
	if err != nil {
		t.Fatalf("stageStrictJailerResources() error = %v, want nil", err)
	}
	if filesystem.createCalls != 1 || filesystem.root == nil {
		t.Fatalf("root creation = %d/%#v, want one owned root", filesystem.createCalls, filesystem.root)
	}
	if filesystem.root.hostRoot != request.Authority.JailRootHostPath ||
		filesystem.root.mode != 0o700 || filesystem.root.uid != 1001 || filesystem.root.gid != 1002 {
		t.Fatalf("root authority = %#v, want exact private owner", filesystem.root)
	}

	wantDirectories := []string{"boot", "drives", "etc", filepath.Join("etc", "hal"), "run", filepath.Join("run", "fc-run-alpha")}
	if !reflect.DeepEqual(filesystem.root.directories, wantDirectories) {
		t.Fatalf("directories = %#v, want %#v", filesystem.root.directories, wantDirectories)
	}
	for _, directory := range wantDirectories {
		metadata := filesystem.root.directoryMetadata[directory]
		if metadata.mode != 0o700 || metadata.uid != 1001 || metadata.gid != 1002 {
			t.Fatalf("directory %q metadata = %#v, want 0700/1001/1002", directory, metadata)
		}
	}

	correlations := result.pathCorrelations()
	if len(correlations) != 4 {
		t.Fatalf("correlations = %#v, want kernel/rootfs/config/support", correlations)
	}
	for _, correlation := range correlations {
		relative := strings.TrimPrefix(correlation.jailPath, "/")
		wantHost := filepath.Join(request.Authority.JailRootHostPath, filepath.FromSlash(relative))
		if correlation.hostPath != wantHost {
			t.Fatalf("%s host path = %q, want %q", correlation.role, correlation.hostPath, wantHost)
		}
		file := filesystem.root.files[filepath.FromSlash(relative)]
		if file == nil {
			t.Fatalf("%s staged file is missing", correlation.role)
		}
		if file.mode != correlation.mode || file.uid != 1001 || file.gid != 1002 || file.syncCalls != 2 || file.verifyCalls != 1 || !file.closed {
			t.Fatalf("%s staged metadata = %#v, correlation %#v", correlation.role, file, correlation)
		}
		if int64(len(file.data)) != correlation.sizeBytes || sha256Hex(file.data) != correlation.sha256 {
			t.Fatalf("%s staged measurement does not match correlation", correlation.role)
		}
	}
	if inherited := result.processInheritedFiles(); inherited == nil || len(inherited) != 0 {
		t.Fatalf("inherited files = %#v, want explicit empty list", inherited)
	}
	if filesystem.root.verifyCalls != 1 || filesystem.root.removeCalls != 0 || filesystem.root.closeCalls != 0 {
		t.Fatalf("successful root verify/remove/close calls = %d/%d/%d, want 1/0/0 retained", filesystem.root.verifyCalls, filesystem.root.removeCalls, filesystem.root.closeCalls)
	}
	if err := result.verifyOwnedRoot(); err != nil {
		t.Fatalf("verifyOwnedRoot() error = %v, want nil", err)
	}
	if filesystem.root.verifyCalls != 2 {
		t.Fatalf("root verify calls = %d, want staging plus pre-launch verification", filesystem.root.verifyCalls)
	}
	if err := result.releaseOwnedRoot(); err != nil {
		t.Fatalf("releaseOwnedRoot() error = %v, want nil", err)
	}
	if err := result.releaseOwnedRoot(); err != nil {
		t.Fatalf("second releaseOwnedRoot() error = %v, want idempotent nil", err)
	}
	if filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 1 {
		t.Fatalf("terminal root remove/close calls = %d/%d, want exactly 1/1", filesystem.root.removeCalls, filesystem.root.closeCalls)
	}
}

func TestStageStrictJailerResourcesRejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*jailerStagingRequest)
	}{
		{name: "root uid", edit: func(request *jailerStagingRequest) { request.Authority.UID = 0 }},
		{name: "root gid", edit: func(request *jailerStagingRequest) { request.Authority.GID = 0 }},
		{name: "public root mode", edit: func(request *jailerStagingRequest) { request.Authority.DirectoryMode = 0o755 }},
		{name: "cross generation root", edit: func(request *jailerStagingRequest) {
			request.Authority.JailRootHostPath = filepath.Join(request.Authority.ChrootBaseDir, "firecracker", "run-beta", "root")
		}},
		{name: "jail path escape", edit: func(request *jailerStagingRequest) {
			request.Config.JailPath = "/run/fc-run-alpha/../outside/firecracker-config.json"
		}},
		{name: "relative jail path", edit: func(request *jailerStagingRequest) { request.Kernel.JailPath = "boot/vmlinux" }},
		{name: "duplicate path", edit: func(request *jailerStagingRequest) { request.Rootfs.JailPath = request.Kernel.JailPath }},
		{name: "duplicate support id", edit: func(request *jailerStagingRequest) {
			request.Support = append(request.Support, request.Support[0])
			request.Support[1].JailPath = "/etc/hal/other.json"
		}},
		{name: "unsafe mode", edit: func(request *jailerStagingRequest) { request.Rootfs.Mode = 0o644 }},
		{name: "missing source", edit: func(request *jailerStagingRequest) { request.Kernel.Source = nil }},
		{name: "malformed digest", edit: func(request *jailerStagingRequest) { request.Config.SHA256 = "/private/digest" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validJailerStagingRequest()
			tt.edit(&request)
			filesystem := newFakeJailerStagingFilesystem()

			_, err := stageStrictJailerResources(filesystem, request)
			if !errors.Is(err, errJailerStagingInvalid) {
				t.Fatalf("error = %v, want errJailerStagingInvalid", err)
			}
			if filesystem.createCalls != 0 {
				t.Fatalf("root create calls = %d, want validation before filesystem mutation", filesystem.createCalls)
			}
			assertJailerStagingErrorRedacted(t, err)
		})
	}
}

func TestStageStrictJailerResourcesRejectsSymlinkAndReplacementAttempts(t *testing.T) {
	t.Run("symlink in parent directory", func(t *testing.T) {
		request := validJailerStagingRequest()
		filesystem := newFakeJailerStagingFilesystem()
		filesystem.failDirectoryPath = "drives"
		filesystem.failure = errors.New("symlink /Users/alice/private/parent-secret")

		_, err := stageStrictJailerResources(filesystem, request)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("error = %v, want errJailerStagingFailed", err)
		}
		if filesystem.root == nil || filesystem.root.removeCalls != 1 {
			t.Fatalf("owned partial root removal = %#v, want exactly once", filesystem.root)
		}
		assertJailerStagingErrorRedacted(t, err)
	})

	t.Run("symlink at destination", func(t *testing.T) {
		request := validJailerStagingRequest()
		filesystem := newFakeJailerStagingFilesystem()
		filesystem.failCreatePath = filepath.FromSlash("drives/rootfs.ext4")
		filesystem.failure = errors.New("symlink /Users/alice/private/rootfs-secret")

		_, err := stageStrictJailerResources(filesystem, request)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("error = %v, want errJailerStagingFailed", err)
		}
		if filesystem.root == nil || filesystem.root.removeCalls != 1 {
			t.Fatalf("owned partial root removal = %#v, want exactly once", filesystem.root)
		}
		assertJailerStagingErrorRedacted(t, err)
	})

	t.Run("file replaced through boundary", func(t *testing.T) {
		request := validJailerStagingRequest()
		filesystem := newFakeJailerStagingFilesystem()
		filesystem.replacePath = filepath.FromSlash("boot/vmlinux")

		_, err := stageStrictJailerResources(filesystem, request)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("error = %v, want errJailerStagingFailed", err)
		}
		if filesystem.root == nil || filesystem.root.removeCalls != 1 {
			t.Fatalf("owned partial root removal = %#v, want exactly once", filesystem.root)
		}
		assertJailerStagingErrorRedacted(t, err)
	})

	t.Run("directory entry replaced", func(t *testing.T) {
		request := validJailerStagingRequest()
		filesystem := newFakeJailerStagingFilesystem()
		filesystem.replaceIdentityPath = filepath.FromSlash("boot/vmlinux")

		_, err := stageStrictJailerResources(filesystem, request)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("error = %v, want errJailerStagingFailed", err)
		}
		if filesystem.root == nil || filesystem.root.removeCalls != 1 {
			t.Fatalf("owned partial root removal = %#v, want exactly once", filesystem.root)
		}
		assertJailerStagingErrorRedacted(t, err)
	})

	t.Run("root generation replaced", func(t *testing.T) {
		request := validJailerStagingRequest()
		filesystem := newFakeJailerStagingFilesystem()
		filesystem.replaceRoot = true

		_, err := stageStrictJailerResources(filesystem, request)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("error = %v, want errJailerStagingFailed", err)
		}
		if filesystem.root == nil || filesystem.root.removeCalls != 1 {
			t.Fatalf("owned partial root removal = %#v, want exactly once", filesystem.root)
		}
		assertJailerStagingErrorRedacted(t, err)
	})
}

func TestStageStrictJailerResourcesRetainsUncertainPartialCleanup(t *testing.T) {
	request := validJailerStagingRequest()
	filesystem := newFakeJailerStagingFilesystem()
	filesystem.failCreatePath = filepath.FromSlash("run/fc-run-alpha/firecracker-config.json")
	filesystem.failure = errors.New("write failed at /srv/private/config-secret")
	filesystem.removeErr = errors.New("cleanup failed at /srv/private/jail-secret")

	result, err := stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingFailed) || !errors.Is(err, errJailerStagingCleanupIncomplete) {
		t.Fatalf("error = %v, want staging and cleanup sentinels", err)
	}
	if filesystem.root == nil || filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 0 {
		t.Fatalf("partial root cleanup = %#v, want failed remove and retained handle", filesystem.root)
	}
	if !result.retainsOwnedRoot() || result.rootReleaseTerminal() {
		t.Fatalf("partial staging result = %#v, want retryable retained authority", result)
	}
	if verifyErr := result.verifyOwnedRoot(); !errors.Is(verifyErr, errJailerStagingCleanupIncomplete) {
		t.Fatalf("verify uncertain root = %v, want cleanup incomplete", verifyErr)
	}
	filesystem.root.removeErr = nil
	if retryErr := result.releaseOwnedRoot(); retryErr != nil {
		t.Fatalf("releaseOwnedRoot() retry error = %v, want nil", retryErr)
	}
	if filesystem.root.removeCalls != 2 || filesystem.root.closeCalls != 1 || !result.rootReleaseTerminal() || result.retainsOwnedRoot() {
		t.Fatalf("terminal root cleanup = %#v, want one exact retry and close", filesystem.root)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func TestStageStrictJailerResourcesClosesFileReturnedWithCreateError(t *testing.T) {
	for _, tt := range []struct {
		name       string
		closeError error
		wantClose  bool
	}{
		{name: "close succeeds", wantClose: false},
		{name: "close fails", closeError: errors.New("close failed at /srv/private/file-secret"), wantClose: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := validJailerStagingRequest()
			filesystem := newFakeJailerStagingFilesystem()
			filesystem.failCreatePath = filepath.FromSlash("boot/vmlinux")
			filesystem.returnFileWithCreateError = true
			filesystem.fileCloseErr = tt.closeError

			_, err := stageStrictJailerResources(filesystem, request)
			if !errors.Is(err, errJailerStagingFailed) {
				t.Fatalf("error = %v, want staging failure", err)
			}
			if errors.Is(err, errJailerStagingCleanupIncomplete) != tt.wantClose {
				t.Fatalf("cleanup incomplete = %t, want %t: %v", errors.Is(err, errJailerStagingCleanupIncomplete), tt.wantClose, err)
			}
			file := filesystem.root.files[filesystem.failCreatePath]
			if file == nil || !file.closed || file.closeCalls != 1 {
				t.Fatalf("returned file = %#v, want closed exactly once", file)
			}
			if filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 1 {
				t.Fatalf("root cleanup calls = %d/%d, want 1/1", filesystem.root.removeCalls, filesystem.root.closeCalls)
			}
			assertJailerStagingErrorRedacted(t, err)
		})
	}
}

func TestJailerStagingLeaseRetainsAuthorityAndRetriesUncertainCleanup(t *testing.T) {
	filesystem := newFakeJailerStagingFilesystem()
	filesystem.removeErr = errors.New("cleanup failed at /srv/private/jail-secret")
	result, err := stageStrictJailerResources(filesystem, validJailerStagingRequest())
	if err != nil {
		t.Fatalf("stageStrictJailerResources() error = %v, want nil", err)
	}

	first := result.releaseOwnedRoot()
	if !errors.Is(first, errJailerStagingCleanupIncomplete) {
		t.Fatalf("releaseOwnedRoot() error = %v, want cleanup incomplete", first)
	}
	if filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 0 {
		t.Fatalf("uncertain cleanup remove/close calls = %d/%d, want retained 1/0", filesystem.root.removeCalls, filesystem.root.closeCalls)
	}
	if verifyErr := result.verifyOwnedRoot(); !errors.Is(verifyErr, errJailerStagingCleanupIncomplete) {
		t.Fatalf("verify after uncertain release = %v, want cleanup incomplete", verifyErr)
	}
	filesystem.root.removeErr = nil
	if second := result.releaseOwnedRoot(); second != nil {
		t.Fatalf("retry release error = %v, want nil", second)
	}
	if third := result.releaseOwnedRoot(); third != nil {
		t.Fatalf("terminal idempotent release error = %v, want nil", third)
	}
	if filesystem.root.removeCalls != 2 || filesystem.root.closeCalls != 1 {
		t.Fatalf("retried cleanup remove/close calls = %d/%d, want 2/1", filesystem.root.removeCalls, filesystem.root.closeCalls)
	}
	assertJailerStagingErrorRedacted(t, first)
}

func TestJailerStagingLeaseCachesTerminalCloseFailureAfterRemoval(t *testing.T) {
	filesystem := newFakeJailerStagingFilesystem()
	filesystem.rootCloseErr = errors.New("close failed at /srv/private/root-secret")
	result, err := stageStrictJailerResources(filesystem, validJailerStagingRequest())
	if err != nil {
		t.Fatalf("stageStrictJailerResources() error = %v, want nil", err)
	}
	first := result.releaseOwnedRoot()
	if !errors.Is(first, errJailerStagingCleanupIncomplete) {
		t.Fatalf("release error = %v, want cleanup incomplete", first)
	}
	second := result.releaseOwnedRoot()
	if second == nil || second.Error() != first.Error() {
		t.Fatalf("second release error = %v, want cached %v", second, first)
	}
	if filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 1 {
		t.Fatalf("terminal cleanup remove/close calls = %d/%d, want 1/1", filesystem.root.removeCalls, filesystem.root.closeCalls)
	}
	assertJailerStagingErrorRedacted(t, first)
}

func TestStageStrictJailerResourcesSurfacesFilesystemCloseFailureBeforeTransfer(t *testing.T) {
	filesystem := newFakeJailerStagingFilesystem()
	filesystem.closeErr = errors.New("close failed at /srv/private/common-secret")
	request := validJailerStagingRequest()
	request.Kernel.Source = nil

	_, err := stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingInvalid) || !errors.Is(err, errJailerStagingCleanupIncomplete) {
		t.Fatalf("stage error = %v, want invalid plus cleanup incomplete", err)
	}
	if filesystem.closeCalls != 1 || filesystem.createCalls != 0 {
		t.Fatalf("filesystem close/create calls = %d/%d, want 1/0", filesystem.closeCalls, filesystem.createCalls)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func TestStageStrictJailerResourcesRejectsDigestAndSizeMismatch(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*jailerStagingRequest)
	}{
		{name: "digest", edit: func(request *jailerStagingRequest) { request.Kernel.SHA256 = strings.Repeat("0", 64) }},
		{name: "size", edit: func(request *jailerStagingRequest) { request.Rootfs.SizeBytes-- }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := validJailerStagingRequest()
			tt.edit(&request)
			filesystem := newFakeJailerStagingFilesystem()

			_, err := stageStrictJailerResources(filesystem, request)
			if !errors.Is(err, errJailerStagingFailed) {
				t.Fatalf("error = %v, want errJailerStagingFailed", err)
			}
			if filesystem.root == nil || filesystem.root.removeCalls != 1 {
				t.Fatalf("mismatch cleanup = %#v, want exactly once", filesystem.root)
			}
			assertJailerStagingErrorRedacted(t, err)
		})
	}
}

func TestStageStrictJailerResourcesDoesNotRemoveUnownedDuplicateRoot(t *testing.T) {
	filesystem := newFakeJailerStagingFilesystem()
	filesystem.createErr = errors.New("root already exists at /srv/private/cross-generation")

	_, err := stageStrictJailerResources(filesystem, validJailerStagingRequest())
	if !errors.Is(err, errJailerStagingFailed) {
		t.Fatalf("error = %v, want errJailerStagingFailed", err)
	}
	if filesystem.root != nil {
		t.Fatalf("filesystem returned owned root %#v after exclusive creation failure", filesystem.root)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func TestJailerStagingResultReturnsDefensiveCopiesAndNoJSON(t *testing.T) {
	result, err := stageStrictJailerResources(newFakeJailerStagingFilesystem(), validJailerStagingRequest())
	if err != nil {
		t.Fatalf("stageStrictJailerResources() error = %v, want nil", err)
	}
	first := result.pathCorrelations()
	first[0].hostPath = "/Users/alice/private/mutated"
	first = append(first, jailerStagingPathCorrelation{hostPath: "/private/extra"})
	second := result.pathCorrelations()
	if len(second) != 4 || strings.Contains(second[0].hostPath, "mutated") {
		t.Fatalf("correlations were mutated through returned copy: %#v", second)
	}
	inherited := result.processInheritedFiles()
	inherited = append(inherited, nil)
	if got := result.processInheritedFiles(); got == nil || len(got) != 0 {
		t.Fatalf("inherited files were mutated through returned copy: %#v", got)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(result) error = %v", err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("json.Marshal(result) = %s, want no durable shape", encoded)
	}
	if err := result.releaseOwnedRoot(); err != nil {
		t.Fatalf("releaseOwnedRoot() error = %v, want nil", err)
	}
}

func TestJailerStagingErrorSanitizesDirectLiteral(t *testing.T) {
	raw := errors.New("raw failure at /srv/private/direct-secret")
	stagingErr := &jailerStagingError{
		kind: raw,
		code: "root",
	}
	err := stagingErr.Error()
	if err != "strict Jailer resource staging failed: root" {
		t.Fatalf("direct staging error = %q, want sanitized kind and safe code", err)
	}
	if errors.Is(stagingErr, raw) || !errors.Is(stagingErr, errJailerStagingFailed) {
		t.Fatalf("direct staging unwrap exposed raw kind: %#v", errors.Unwrap(stagingErr))
	}
}

func validJailerStagingRequest() jailerStagingRequest {
	chrootBase := filepath.Join(string(filepath.Separator), "srv", "hal", "private", "jailer")
	jailRoot := filepath.Join(chrootBase, "firecracker", "run-alpha", "root")
	resource := func(id, jailPath string, data []byte, mode os.FileMode) jailerStagingResourceInput {
		return jailerStagingResourceInput{
			ID: id, JailPath: jailPath, Source: bytes.NewReader(data),
			SizeBytes: int64(len(data)), SHA256: sha256Hex(data), Mode: mode,
		}
	}
	return jailerStagingRequest{
		Authority: jailerStagingAuthority{
			RuntimeID: "run-alpha", CanonicalFirecrackerPath: filepath.Join(string(filepath.Separator), "opt", "hal", "bin", "firecracker"),
			ChrootBaseDir: chrootBase, JailRootHostPath: jailRoot,
			UID: 1001, GID: 1002, DirectoryMode: 0o700,
		},
		Kernel: resource("kernel", "/boot/vmlinux", []byte("sealed-kernel"), 0o400),
		Rootfs: resource("rootfs", "/drives/rootfs.ext4", []byte("sealed-rootfs"), 0o600),
		Config: resource("config", "/run/fc-run-alpha/firecracker-config.json", []byte(`{"boot-source":"/boot/vmlinux"}`), 0o400),
		Support: []jailerStagingResourceInput{
			resource("support-runtime", "/etc/hal/runtime.json", []byte(`{"profile":"strict"}`), 0o400),
		},
	}
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func assertJailerStagingErrorRedacted(t *testing.T, err error) {
	t.Helper()
	text := err.Error()
	for _, forbidden := range []string{"/Users/", "/srv/", "/opt/", "private", "secret", "rootfs.ext4", "firecracker-config.json"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("error leaked %q in %q", forbidden, text)
		}
	}
}

type fakeJailerStagingFilesystem struct {
	createCalls               int
	createErr                 error
	failDirectoryPath         string
	failCreatePath            string
	returnFileWithCreateError bool
	fileCloseErr              error
	replacePath               string
	replaceIdentityPath       string
	replaceRoot               bool
	failure                   error
	removeErr                 error
	rootCloseErr              error
	closeErr                  error
	closeCalls                int
	root                      *fakeJailerStagingRoot
}

func newFakeJailerStagingFilesystem() *fakeJailerStagingFilesystem {
	return &fakeJailerStagingFilesystem{}
}

func (filesystem *fakeJailerStagingFilesystem) createExclusiveRoot(request jailerStagingRootRequest) (jailerStagingRoot, error) {
	filesystem.createCalls++
	if filesystem.createErr != nil {
		return nil, filesystem.createErr
	}
	root := &fakeJailerStagingRoot{
		hostRoot: request.HostRoot, mode: request.Mode, uid: request.UID, gid: request.GID,
		directoryMetadata: map[string]fakeJailerStagingMetadata{}, files: map[string]*fakeJailerStagingFile{},
		failDirectoryPath: filesystem.failDirectoryPath, failCreatePath: filesystem.failCreatePath, replacePath: filesystem.replacePath,
		replaceIdentityPath: filesystem.replaceIdentityPath, replaceRoot: filesystem.replaceRoot,
		returnFileWithCreateError: filesystem.returnFileWithCreateError, fileCloseErr: filesystem.fileCloseErr,
		failure: filesystem.failure, removeErr: filesystem.removeErr, closeErr: filesystem.rootCloseErr,
	}
	filesystem.root = root
	return root, nil
}

func (filesystem *fakeJailerStagingFilesystem) close() error {
	filesystem.closeCalls++
	return filesystem.closeErr
}

type fakeJailerStagingMetadata struct {
	mode os.FileMode
	uid  uint32
	gid  uint32
}

type fakeJailerStagingRoot struct {
	hostRoot                  string
	mode                      os.FileMode
	uid                       uint32
	gid                       uint32
	directories               []string
	directoryMetadata         map[string]fakeJailerStagingMetadata
	files                     map[string]*fakeJailerStagingFile
	failDirectoryPath         string
	failCreatePath            string
	returnFileWithCreateError bool
	fileCloseErr              error
	replacePath               string
	replaceIdentityPath       string
	replaceRoot               bool
	failure                   error
	removeErr                 error
	removeCalls               int
	closeCalls                int
	closeErr                  error
	verifyCalls               int
}

func (root *fakeJailerStagingRoot) createDirectory(relative string, mode os.FileMode, uid, gid uint32) error {
	if relative == root.failDirectoryPath {
		return root.failure
	}
	if _, exists := root.directoryMetadata[relative]; exists {
		return fmt.Errorf("duplicate directory: %s", relative)
	}
	root.directories = append(root.directories, relative)
	root.directoryMetadata[relative] = fakeJailerStagingMetadata{mode: mode, uid: uid, gid: gid}
	return nil
}

func (root *fakeJailerStagingRoot) createFileExclusive(relative string) (jailerStagingFile, error) {
	if relative == root.failCreatePath {
		if root.returnFileWithCreateError {
			file := &fakeJailerStagingFile{closeErr: root.fileCloseErr}
			root.files[relative] = file
			return file, errors.New("fake create failure at /srv/private/file-secret")
		}
		if root.failure != nil {
			return nil, root.failure
		}
		return nil, errors.New("fake create failure")
	}
	if _, exists := root.files[relative]; exists {
		return nil, errors.New("duplicate file")
	}
	file := &fakeJailerStagingFile{
		replaceOnVerify: relative == root.replacePath,
		identityChanged: relative == root.replaceIdentityPath,
	}
	root.files[relative] = file
	return file, nil
}

func (root *fakeJailerStagingRoot) verifyOwned() error {
	root.verifyCalls++
	if root.replaceRoot {
		return errors.New("root generation replaced at /srv/private/root-secret")
	}
	return nil
}

func (root *fakeJailerStagingRoot) removeOwned() error {
	root.removeCalls++
	return root.removeErr
}

func (root *fakeJailerStagingRoot) close() error {
	root.closeCalls++
	return root.closeErr
}

type fakeJailerStagingFile struct {
	data            []byte
	offset          int64
	mode            os.FileMode
	uid             uint32
	gid             uint32
	syncCalls       int
	closed          bool
	replaceOnVerify bool
	replaced        bool
	identityChanged bool
	verifyCalls     int
	closeCalls      int
	closeErr        error
}

func (file *fakeJailerStagingFile) Read(output []byte) (int, error) {
	if file.offset >= int64(len(file.data)) {
		return 0, io.EOF
	}
	n := copy(output, file.data[file.offset:])
	file.offset += int64(n)
	return n, nil
}

func (file *fakeJailerStagingFile) Write(input []byte) (int, error) {
	end := file.offset + int64(len(input))
	if end > int64(len(file.data)) {
		file.data = append(file.data, make([]byte, end-int64(len(file.data)))...)
	}
	copy(file.data[file.offset:end], input)
	file.offset = end
	return len(input), nil
}

func (file *fakeJailerStagingFile) Seek(offset int64, whence int) (int64, error) {
	if file.replaceOnVerify && !file.replaced && whence == io.SeekStart && offset == 0 && len(file.data) > 0 {
		file.data[0] ^= 0xff
		file.replaced = true
	}
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = file.offset + offset
	case io.SeekEnd:
		next = int64(len(file.data)) + offset
	default:
		return 0, errors.New("invalid seek")
	}
	if next < 0 {
		return 0, errors.New("negative seek")
	}
	file.offset = next
	return next, nil
}

func (file *fakeJailerStagingFile) sync() error {
	file.syncCalls++
	return nil
}

func (file *fakeJailerStagingFile) setOwnership(uid, gid uint32) error {
	file.uid = uid
	file.gid = gid
	return nil
}

func (file *fakeJailerStagingFile) setMode(mode os.FileMode) error {
	file.mode = mode
	return nil
}

func (file *fakeJailerStagingFile) verifyIdentity() error {
	file.verifyCalls++
	if file.identityChanged {
		return errors.New("file identity replaced at /srv/private/file-secret")
	}
	return nil
}

func (file *fakeJailerStagingFile) close() error {
	file.closed = true
	file.closeCalls++
	return file.closeErr
}
