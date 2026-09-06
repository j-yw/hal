package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInspectStrictJailerHostBindsConfiguredPair(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()

	result, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	if err != nil {
		t.Fatalf("inspectStrictJailerHostWithFilesystem() error = %v, want nil", err)
	}
	if result.canonicalJailerPath != request.jailerPath ||
		result.canonicalFirecrackerPath != request.firecrackerPath ||
		result.jailerSHA256 != request.expectedJailerSHA256 ||
		result.firecrackerSHA256 != request.expectedFirecrackerSHA256 {
		t.Fatalf("binary binding = %#v, want configured canonical pair", result)
	}
	if result.runtimeUID != request.runtimeUID || result.runtimeGID != request.runtimeGID ||
		result.canonicalChrootBaseDir != request.chrootBaseDir {
		t.Fatalf("host binding = %#v, want configured identity and chroot", result)
	}
	if !filesystem.SameFile(result.jailerInfo, filesystem.infos[request.jailerPath]) ||
		!filesystem.SameFile(result.firecrackerInfo, filesystem.infos[request.firecrackerPath]) ||
		!filesystem.SameFile(result.chrootInfo, filesystem.infos[request.chrootBaseDir]) {
		t.Fatal("inspection result did not retain the inspected file identity snapshots")
	}
}

func TestInspectStrictJailerHostBindsExactTrustedFilesystemAnchor(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()
	request.trustedFilesystemAnchor = "/opt/hal"
	request.chrootBaseDir = "/opt/hal/jailer-root"
	filesystem.infos[request.chrootBaseDir] = fakeStrictJailerHostFileInfo{
		name: request.chrootBaseDir, mode: os.ModeDir | 0o755, identity: "anchored-chroot",
	}

	result, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	if err != nil {
		t.Fatalf("inspectStrictJailerHostWithFilesystem() error = %v, want nil", err)
	}
	if result.canonicalTrustedFilesystemAnchor != request.trustedFilesystemAnchor ||
		!filesystem.SameFile(result.trustedFilesystemAnchorInfo, filesystem.infos[request.trustedFilesystemAnchor]) {
		t.Fatalf("trusted filesystem anchor = %#v, want exact inspected %q", result, request.trustedFilesystemAnchor)
	}
}

func TestInspectStrictJailerHostDefaultsTrustedFilesystemAnchorToRoot(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()

	result, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	if err != nil {
		t.Fatalf("inspectStrictJailerHostWithFilesystem() error = %v, want nil", err)
	}
	if result.canonicalTrustedFilesystemAnchor != "/" ||
		!filesystem.SameFile(result.trustedFilesystemAnchorInfo, filesystem.infos["/"]) {
		t.Fatalf("trusted filesystem anchor = %#v, want exact inspected filesystem root", result)
	}
}

func TestInspectStrictJailerHostRejectsPathsOutsideTrustedFilesystemAnchor(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*strictJailerHostInspectionRequest)
	}{
		{name: "jailer sibling prefix", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest) {
			request.jailerPath = "/opt/hal-untrusted/jailer"
		}},
		{name: "Firecracker sibling prefix", field: "firecrackerPath", edit: func(request *strictJailerHostInspectionRequest) {
			request.firecrackerPath = "/opt/hal-untrusted/firecracker"
		}},
		{name: "chroot outside", field: "chrootBaseDir", edit: func(*strictJailerHostInspectionRequest) {}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filesystem, request := validStrictJailerHostInspectionFixture()
			request.trustedFilesystemAnchor = "/opt/hal"
			tt.edit(&request)

			_, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
			assertStrictJailerHostInspectionError(t, err, tt.field)
		})
	}
}

func TestInspectStrictJailerHostRejectsUnmatchedTrustedFilesystemAnchorIdentity(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()
	request.trustedFilesystemAnchor = "/opt/hal"
	request.chrootBaseDir = "/opt/hal/jailer-root"
	filesystem.infos[request.chrootBaseDir] = fakeStrictJailerHostFileInfo{
		name: request.chrootBaseDir, mode: os.ModeDir | 0o755, identity: "anchored-chroot",
	}
	anchor := filesystem.infos[request.trustedFilesystemAnchor].(fakeStrictJailerHostFileInfo)
	anchor.identity = ""
	filesystem.infos[request.trustedFilesystemAnchor] = anchor

	_, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	assertStrictJailerHostInspectionError(t, err, "chrootBaseDir")
}

func TestInspectStrictJailerHostRejectsUnsafeTrustedFilesystemAnchor(t *testing.T) {
	tests := []struct {
		name string
		edit func(*strictJailerHostInspectionRequest, *fakeStrictJailerHostInspectionFilesystem)
	}{
		{name: "relative", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "opt/hal"
		}},
		{name: "unclean", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal/../hal"
		}},
		{name: "symlink canonical drift", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal"
			filesystem.resolved[request.trustedFilesystemAnchor] = "/opt/hal-release"
		}},
		{name: "symlink entry", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal"
			filesystem.infos[request.trustedFilesystemAnchor] = fakeStrictJailerHostFileInfo{
				name: "hal", mode: os.ModeSymlink | 0o777, identity: "unsafe-anchor",
			}
		}},
		{name: "group writable", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal"
			filesystem.infos[request.trustedFilesystemAnchor] = fakeStrictJailerHostFileInfo{
				name: "hal", mode: os.ModeDir | 0o775, identity: "unsafe-anchor",
			}
		}},
		{name: "world writable", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal"
			filesystem.infos[request.trustedFilesystemAnchor] = fakeStrictJailerHostFileInfo{
				name: "hal", mode: os.ModeDir | 0o757, identity: "unsafe-anchor",
			}
		}},
		{name: "untrusted owner", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal"
			filesystem.infos[request.trustedFilesystemAnchor] = fakeStrictJailerHostFileInfo{
				name: "hal", mode: os.ModeDir | 0o755, identity: "unsafe-anchor", ownerUID: 1000,
			}
		}},
		{name: "not directory", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			request.trustedFilesystemAnchor = "/opt/hal"
			filesystem.infos[request.trustedFilesystemAnchor] = fakeStrictJailerHostFileInfo{
				name: "hal", mode: 0o755, identity: "unsafe-anchor",
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filesystem, request := validStrictJailerHostInspectionFixture()
			tt.edit(&request, filesystem)

			_, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
			assertStrictJailerHostInspectionError(t, err, "trustedFilesystemAnchor")
		})
	}
}

func TestInspectStrictJailerHostRejectsUnsafeBinaryInputs(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*strictJailerHostInspectionRequest, *fakeStrictJailerHostInspectionFilesystem)
	}{
		{name: "relative jailer", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.jailerPath = "bin/jailer"
		}},
		{name: "root jailer", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.jailerPath = "/"
		}},
		{name: "unclean Firecracker", field: "firecrackerPath", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.firecrackerPath = "/opt/hal/bin/../bin/firecracker"
		}},
		{name: "jailer symlink", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.resolved[request.jailerPath] = "/opt/hal/releases/jailer"
		}},
		{name: "Firecracker symlink", field: "firecrackerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.resolved[request.firecrackerPath] = "/opt/hal/releases/firecracker"
		}},
		{name: "jailer directory", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos[request.jailerPath] = fakeStrictJailerHostFileInfo{name: "jailer", mode: os.ModeDir | 0o755, identity: "jailer"}
		}},
		{name: "Firecracker not executable", field: "firecrackerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.firecrackerPath].(fakeStrictJailerHostFileInfo)
			info.mode = 0o644
			filesystem.infos[request.firecrackerPath] = info
		}},
		{name: "group writable jailer", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.jailerPath].(fakeStrictJailerHostFileInfo)
			info.mode = 0o775
			filesystem.infos[request.jailerPath] = info
		}},
		{name: "world writable Firecracker", field: "firecrackerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.firecrackerPath].(fakeStrictJailerHostFileInfo)
			info.mode = 0o757
			filesystem.infos[request.firecrackerPath] = info
		}},
		{name: "root only Firecracker", field: "firecrackerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.firecrackerPath].(fakeStrictJailerHostFileInfo)
			info.mode = 0o700
			filesystem.infos[request.firecrackerPath] = info
		}},
		{name: "setuid jailer", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.jailerPath].(fakeStrictJailerHostFileInfo)
			info.mode = os.ModeSetuid | 0o755
			filesystem.infos[request.jailerPath] = info
		}},
		{name: "untrusted binary owner", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.jailerPath].(fakeStrictJailerHostFileInfo)
			info.ownerUID = 1000
			filesystem.infos[request.jailerPath] = info
		}},
		{name: "writable binary parent", field: "jailerPath", edit: func(_ *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos["/opt/hal/bin"] = fakeStrictJailerHostFileInfo{name: "bin", mode: os.ModeDir | 0o775, identity: "bin"}
		}},
		{name: "untrusted binary parent owner", field: "jailerPath", edit: func(_ *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos["/opt/hal/bin"] = fakeStrictJailerHostFileInfo{name: "bin", mode: os.ModeDir | 0o755, identity: "bin", ownerUID: 1000}
		}},
		{name: "symlink binary parent", field: "jailerPath", edit: func(_ *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos["/opt/hal"] = fakeStrictJailerHostFileInfo{name: "hal", mode: os.ModeSymlink | 0o777, identity: "hal"}
		}},
		{name: "non-directory binary parent", field: "jailerPath", edit: func(_ *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos["/opt/hal"] = fakeStrictJailerHostFileInfo{name: "hal", mode: 0o755, identity: "hal"}
		}},
		{name: "missing jailer identity", field: "jailerIdentity", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.expectedJailerSHA256 = [sha256.Size]byte{}
		}},
		{name: "missing Firecracker identity", field: "firecrackerIdentity", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.expectedFirecrackerSHA256 = [sha256.Size]byte{}
		}},
		{name: "jailer identity mismatch", field: "jailerIdentity", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.expectedJailerSHA256 = sha256.Sum256([]byte("other jailer"))
		}},
		{name: "Firecracker identity mismatch", field: "firecrackerIdentity", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.expectedFirecrackerSHA256 = sha256.Sum256([]byte("other Firecracker"))
		}},
		{name: "same path", field: "binaryPair", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.firecrackerPath = request.jailerPath
			request.expectedFirecrackerSHA256 = request.expectedJailerSHA256
		}},
		{name: "same configured identity", field: "binaryPair", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.expectedFirecrackerSHA256 = request.expectedJailerSHA256
		}},
		{name: "same file", field: "binaryPair", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.firecrackerPath].(fakeStrictJailerHostFileInfo)
			info.identity = "jailer-file"
			filesystem.infos[request.firecrackerPath] = info
		}},
		{name: "file changed before open", field: "jailerPath", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			info := filesystem.infos[request.jailerPath].(fakeStrictJailerHostFileInfo)
			info.identity = "jailer-path-file"
			filesystem.infos[request.jailerPath] = info
			filesystem.openInfos[request.jailerPath] = fakeStrictJailerHostFileInfo{name: "jailer", mode: 0o755, identity: "replacement-file"}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filesystem, request := validStrictJailerHostInspectionFixture()
			tt.edit(&request, filesystem)

			_, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
			assertStrictJailerHostInspectionError(t, err, tt.field)
		})
	}
}

func TestInspectStrictJailerHostRejectsUnsafeRuntimeIdentityAndChroot(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*strictJailerHostInspectionRequest, *fakeStrictJailerHostInspectionFilesystem)
	}{
		{name: "root uid", field: "uid", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.runtimeUID = 0
		}},
		{name: "root gid", field: "gid", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.runtimeGID = 0
		}},
		{name: "root chroot", field: "chrootBaseDir", edit: func(request *strictJailerHostInspectionRequest, _ *fakeStrictJailerHostInspectionFilesystem) {
			request.chrootBaseDir = "/"
		}},
		{name: "chroot symlink", field: "chrootBaseDir", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.resolved[request.chrootBaseDir] = "/srv/hal/real-jailer"
		}},
		{name: "chroot not directory", field: "chrootBaseDir", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos[request.chrootBaseDir] = fakeStrictJailerHostFileInfo{name: "jailer", mode: 0o700, identity: "chroot"}
		}},
		{name: "chroot world writable", field: "chrootBaseDir", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos[request.chrootBaseDir] = fakeStrictJailerHostFileInfo{name: "jailer", mode: os.ModeDir | 0o707, identity: "chroot"}
		}},
		{name: "chroot writable parent", field: "chrootBaseDir", edit: func(_ *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos["/srv/hal"] = fakeStrictJailerHostFileInfo{name: "hal", mode: os.ModeDir | 0o770, identity: "srv-hal"}
		}},
		{name: "chroot untrusted owner", field: "chrootBaseDir", edit: func(request *strictJailerHostInspectionRequest, filesystem *fakeStrictJailerHostInspectionFilesystem) {
			filesystem.infos[request.chrootBaseDir] = fakeStrictJailerHostFileInfo{name: "jailer", mode: os.ModeDir | 0o700, identity: "chroot", ownerUID: 1000}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filesystem, request := validStrictJailerHostInspectionFixture()
			tt.edit(&request, filesystem)

			_, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
			assertStrictJailerHostInspectionError(t, err, tt.field)
		})
	}
}

func TestStrictJailerHostInspectionErrorsAreSanitized(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()
	filesystem.openErrors[request.jailerPath] = errors.New("open /Users/alice/private/jailer: token=secret")

	_, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	assertStrictJailerHostInspectionError(t, err, "jailerPath")
	for _, unsafe := range []string{"/Users/alice", request.jailerPath, "token=secret"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("error leaked %q in %q", unsafe, err)
		}
	}

	direct := &strictJailerHostInspectionError{field: "/Users/alice/private"}
	if got := direct.Error(); got != errStrictJailerHostInspectionInvalid.Error() {
		t.Fatalf("direct error = %q, want sanitized sentinel", got)
	}

	filesystem, request = validStrictJailerHostInspectionFixture()
	request.trustedFilesystemAnchor = "/opt/hal"
	filesystem.resolveErrs[request.trustedFilesystemAnchor] = errors.New("resolve /Users/alice/private/anchor: token=secret")
	_, err = inspectStrictJailerHostWithFilesystem(request, filesystem)
	assertStrictJailerHostInspectionError(t, err, "trustedFilesystemAnchor")
	for _, unsafe := range []string{"/Users/alice", request.trustedFilesystemAnchor, "token=secret"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("anchor error leaked %q in %q", unsafe, err)
		}
	}
}

func TestStrictJailerHostInspectionHasNoDurableJSONShape(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()
	result, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	if err != nil {
		t.Fatalf("inspectStrictJailerHostWithFilesystem() error = %v, want nil", err)
	}
	for name, value := range map[string]any{"request": request, "result": result} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		if got := string(encoded); got != "{}" {
			t.Fatalf("json.Marshal(%s) = %s, want no durable shape", name, got)
		}
	}
}

func validStrictJailerHostInspectionFixture() (*fakeStrictJailerHostInspectionFilesystem, strictJailerHostInspectionRequest) {
	jailerPath := "/opt/hal/bin/jailer"
	firecrackerPath := "/opt/hal/bin/firecracker"
	chrootBaseDir := "/srv/hal/jailer"
	jailerPayload := []byte("configured jailer bytes")
	firecrackerPayload := []byte("configured Firecracker bytes")
	filesystem := &fakeStrictJailerHostInspectionFilesystem{
		resolved:    map[string]string{},
		resolveErrs: map[string]error{},
		infos:       map[string]os.FileInfo{},
		openInfos:   map[string]os.FileInfo{},
		payloads:    map[string][]byte{jailerPath: jailerPayload, firecrackerPath: firecrackerPayload},
		openErrors:  map[string]error{},
	}
	for _, path := range []string{"/", "/opt", "/opt/hal", "/opt/hal/bin", "/srv", "/srv/hal", chrootBaseDir} {
		filesystem.infos[path] = fakeStrictJailerHostFileInfo{name: path, mode: os.ModeDir | 0o755, identity: path}
	}
	filesystem.infos[jailerPath] = fakeStrictJailerHostFileInfo{name: "jailer", mode: 0o755, size: int64(len(jailerPayload)), identity: "jailer-file"}
	filesystem.infos[firecrackerPath] = fakeStrictJailerHostFileInfo{name: "firecracker", mode: 0o755, size: int64(len(firecrackerPayload)), identity: "firecracker-file"}

	return filesystem, strictJailerHostInspectionRequest{
		jailerPath:                jailerPath,
		firecrackerPath:           firecrackerPath,
		expectedJailerSHA256:      sha256.Sum256(jailerPayload),
		expectedFirecrackerSHA256: sha256.Sum256(firecrackerPayload),
		runtimeUID:                1001,
		runtimeGID:                1002,
		chrootBaseDir:             chrootBaseDir,
	}
}

func assertStrictJailerHostInspectionError(t *testing.T, err error, field string) {
	t.Helper()
	if !errors.Is(err, errStrictJailerHostInspectionInvalid) {
		t.Fatalf("error = %v, want errStrictJailerHostInspectionInvalid", err)
	}
	var inspectionErr *strictJailerHostInspectionError
	if !errors.As(err, &inspectionErr) || inspectionErr.field != field {
		t.Fatalf("error = %#v, want field %q", err, field)
	}
}

type fakeStrictJailerHostInspectionFilesystem struct {
	resolved    map[string]string
	resolveErrs map[string]error
	infos       map[string]os.FileInfo
	openInfos   map[string]os.FileInfo
	payloads    map[string][]byte
	openErrors  map[string]error
}

func (filesystem *fakeStrictJailerHostInspectionFilesystem) EvalSymlinks(path string) (string, error) {
	if err := filesystem.resolveErrs[path]; err != nil {
		return "", err
	}
	if resolved := filesystem.resolved[path]; resolved != "" {
		return resolved, nil
	}
	return path, nil
}

func (filesystem *fakeStrictJailerHostInspectionFilesystem) Lstat(path string) (os.FileInfo, error) {
	info, ok := filesystem.infos[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return info, nil
}

func (filesystem *fakeStrictJailerHostInspectionFilesystem) OpenNoFollow(path string) (strictJailerHostInspectionFile, error) {
	if err := filesystem.openErrors[path]; err != nil {
		return nil, err
	}
	info := filesystem.openInfos[path]
	if info == nil {
		info = filesystem.infos[path]
	}
	return &fakeStrictJailerHostInspectionFile{Reader: bytes.NewReader(filesystem.payloads[path]), info: info}, nil
}

func (*fakeStrictJailerHostInspectionFilesystem) SameFile(left, right os.FileInfo) bool {
	leftInfo, leftOK := left.(fakeStrictJailerHostFileInfo)
	rightInfo, rightOK := right.(fakeStrictJailerHostFileInfo)
	return leftOK && rightOK && leftInfo.identity != "" && leftInfo.identity == rightInfo.identity
}

func (*fakeStrictJailerHostInspectionFilesystem) OwnerUID(info os.FileInfo) (uint32, bool) {
	fake, ok := info.(fakeStrictJailerHostFileInfo)
	return fake.ownerUID, ok
}

type fakeStrictJailerHostInspectionFile struct {
	io.Reader
	info os.FileInfo
}

func (file *fakeStrictJailerHostInspectionFile) Stat() (os.FileInfo, error) { return file.info, nil }
func (*fakeStrictJailerHostInspectionFile) Close() error                    { return nil }

type fakeStrictJailerHostFileInfo struct {
	name     string
	size     int64
	mode     os.FileMode
	identity string
	ownerUID uint32
}

func (info fakeStrictJailerHostFileInfo) Name() string      { return info.name }
func (info fakeStrictJailerHostFileInfo) Size() int64       { return info.size }
func (info fakeStrictJailerHostFileInfo) Mode() os.FileMode { return info.mode }
func (fakeStrictJailerHostFileInfo) ModTime() time.Time     { return time.Time{} }
func (info fakeStrictJailerHostFileInfo) IsDir() bool       { return info.mode.IsDir() }
func (fakeStrictJailerHostFileInfo) Sys() any               { return nil }
