package firecrackerhost

import (
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// errStrictJailerHostInspectionInvalid is deliberately detail-free. Host
// paths and filesystem errors must not cross this private pre-launch boundary.
var errStrictJailerHostInspectionInvalid = errors.New("strict Jailer host inspection is invalid")

type strictJailerHostInspectionError struct {
	field string
}

func (err *strictJailerHostInspectionError) Error() string {
	if err == nil {
		return errStrictJailerHostInspectionInvalid.Error()
	}
	field := safeStrictJailerHostInspectionField(err.field)
	if field == "" {
		return errStrictJailerHostInspectionInvalid.Error()
	}
	return errStrictJailerHostInspectionInvalid.Error() + ": " + field
}

func (*strictJailerHostInspectionError) Unwrap() error {
	return errStrictJailerHostInspectionInvalid
}

// strictJailerHostInspectionRequest remains private and has no durable JSON
// shape. Expected digests must come from prepared-host configuration; this
// inspector does not infer a released pair from names, directories, or output.
type strictJailerHostInspectionRequest struct {
	jailerPath                string
	firecrackerPath           string
	expectedJailerSHA256      [sha256.Size]byte
	expectedFirecrackerSHA256 [sha256.Size]byte
	// A later prepared-host identity authority must prove that this non-root
	// pair is dedicated to the run. Numeric input alone cannot prove that.
	runtimeUID    uint32
	runtimeGID    uint32
	chrootBaseDir string
}

// strictJailerHostInspectionResult binds the inspected values for the next
// private preparation step. It is not launch evidence: stable symlinks are
// rejected and the leaf is opened without following links, but pathnames are
// not retained or pinned across a later exec by this read-only slice.
type strictJailerHostInspectionResult struct {
	canonicalJailerPath      string
	canonicalFirecrackerPath string
	jailerSHA256             [sha256.Size]byte
	firecrackerSHA256        [sha256.Size]byte
	jailerInfo               os.FileInfo
	firecrackerInfo          os.FileInfo
	chrootInfo               os.FileInfo
	runtimeUID               uint32
	runtimeGID               uint32
	canonicalChrootBaseDir   string
}

type strictJailerHostInspectionFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
}

// strictJailerHostInspectionFilesystem is the narrow read-only path and file
// identity seam used by deterministic tests and the OS adapter below.
type strictJailerHostInspectionFilesystem interface {
	EvalSymlinks(string) (string, error)
	Lstat(string) (os.FileInfo, error)
	OpenNoFollow(string) (strictJailerHostInspectionFile, error)
	SameFile(os.FileInfo, os.FileInfo) bool
	OwnerUID(os.FileInfo) (uint32, bool)
}

type osStrictJailerHostInspectionFilesystem struct{}

func (osStrictJailerHostInspectionFilesystem) EvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func (osStrictJailerHostInspectionFilesystem) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func (osStrictJailerHostInspectionFilesystem) SameFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right)
}

// inspectStrictJailerHost performs a read-only inspection through the real OS.
// It is intentionally not wired to process start or strict selection.
func inspectStrictJailerHost(request strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
	return inspectStrictJailerHostWithFilesystem(request, osStrictJailerHostInspectionFilesystem{})
}

func inspectStrictJailerHostWithFilesystem(request strictJailerHostInspectionRequest, filesystem strictJailerHostInspectionFilesystem) (strictJailerHostInspectionResult, error) {
	if filesystem == nil {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("filesystem")
	}
	if request.runtimeUID == 0 {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("uid")
	}
	if request.runtimeGID == 0 {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("gid")
	}
	if request.expectedJailerSHA256 == ([sha256.Size]byte{}) {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("jailerIdentity")
	}
	if request.expectedFirecrackerSHA256 == ([sha256.Size]byte{}) {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("firecrackerIdentity")
	}
	if request.expectedJailerSHA256 == request.expectedFirecrackerSHA256 {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("binaryPair")
	}

	jailerPath, err := strictJailerHostConfiguredPath(request.jailerPath, "jailerPath")
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}
	firecrackerPath, err := strictJailerHostConfiguredPath(request.firecrackerPath, "firecrackerPath")
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}
	if jailerPath == firecrackerPath {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("binaryPair")
	}
	chrootBaseDir, err := strictJailerHostConfiguredPath(request.chrootBaseDir, "chrootBaseDir")
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}
	chrootInfo, err := inspectStrictJailerTrustedDirectory(filesystem, chrootBaseDir, "chrootBaseDir")
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}

	jailer, err := inspectStrictJailerHostBinary(filesystem, jailerPath, request.expectedJailerSHA256, "jailerPath", "jailerIdentity")
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}
	firecrackerBinary, err := inspectStrictJailerHostBinary(filesystem, firecrackerPath, request.expectedFirecrackerSHA256, "firecrackerPath", "firecrackerIdentity")
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}
	if filesystem.SameFile(jailer.info, firecrackerBinary.info) {
		return strictJailerHostInspectionResult{}, newStrictJailerHostInspectionError("binaryPair")
	}

	return strictJailerHostInspectionResult{
		canonicalJailerPath:      jailerPath,
		canonicalFirecrackerPath: firecrackerPath,
		jailerSHA256:             jailer.digest,
		firecrackerSHA256:        firecrackerBinary.digest,
		jailerInfo:               jailer.info,
		firecrackerInfo:          firecrackerBinary.info,
		chrootInfo:               chrootInfo,
		runtimeUID:               request.runtimeUID,
		runtimeGID:               request.runtimeGID,
		canonicalChrootBaseDir:   chrootBaseDir,
	}, nil
}

type strictJailerHostInspectedBinary struct {
	info   os.FileInfo
	digest [sha256.Size]byte
}

func inspectStrictJailerHostBinary(filesystem strictJailerHostInspectionFilesystem, path string, expected [sha256.Size]byte, pathField, identityField string) (strictJailerHostInspectedBinary, error) {
	resolved, err := filesystem.EvalSymlinks(path)
	if err != nil || resolved != path || !filepathIsCleanAbsolute(resolved) || cleanupFilesystemRoot(resolved) {
		return strictJailerHostInspectedBinary{}, newStrictJailerHostInspectionError(pathField)
	}
	if _, err := inspectStrictJailerTrustedDirectoryChain(filesystem, filepath.Dir(path), pathField); err != nil {
		return strictJailerHostInspectedBinary{}, err
	}

	pathInfo, err := filesystem.Lstat(path)
	if err != nil || !validStrictJailerHostBinaryInfo(filesystem, pathInfo) {
		return strictJailerHostInspectedBinary{}, newStrictJailerHostInspectionError(pathField)
	}
	file, err := filesystem.OpenNoFollow(path)
	if err != nil || file == nil {
		return strictJailerHostInspectedBinary{}, newStrictJailerHostInspectionError(pathField)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil || !validStrictJailerHostBinaryInfo(filesystem, openedInfo) || !filesystem.SameFile(pathInfo, openedInfo) {
		return strictJailerHostInspectedBinary{}, newStrictJailerHostInspectionError(pathField)
	}
	digest, err := strictJailerHostFileSHA256(file)
	if err != nil || digest != expected {
		return strictJailerHostInspectedBinary{}, newStrictJailerHostInspectionError(identityField)
	}
	return strictJailerHostInspectedBinary{info: openedInfo, digest: digest}, nil
}

func strictJailerHostFileSHA256(reader io.Reader) ([sha256.Size]byte, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, reader); err != nil {
		return [sha256.Size]byte{}, err
	}
	return strictJailerHostHashSum(hasher), nil
}

func strictJailerHostHashSum(hasher hash.Hash) [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func inspectStrictJailerTrustedDirectory(filesystem strictJailerHostInspectionFilesystem, path, field string) (os.FileInfo, error) {
	resolved, err := filesystem.EvalSymlinks(path)
	if err != nil || resolved != path || !filepathIsCleanAbsolute(resolved) || cleanupFilesystemRoot(resolved) {
		return nil, newStrictJailerHostInspectionError(field)
	}
	return inspectStrictJailerTrustedDirectoryChain(filesystem, path, field)
}

func inspectStrictJailerTrustedDirectoryChain(filesystem strictJailerHostInspectionFilesystem, path, field string) (os.FileInfo, error) {
	var inspected os.FileInfo
	for current := path; ; current = filepath.Dir(current) {
		info, err := filesystem.Lstat(current)
		if err != nil || !validStrictJailerHostDirectoryInfo(filesystem, info) {
			return nil, newStrictJailerHostInspectionError(field)
		}
		if inspected == nil {
			inspected = info
		}
		if cleanupFilesystemRoot(current) {
			return inspected, nil
		}
		next := filepath.Dir(current)
		if next == current {
			return nil, newStrictJailerHostInspectionError(field)
		}
	}
}

func validStrictJailerHostBinaryInfo(filesystem strictJailerHostInspectionFilesystem, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	ownerUID, ownerKnown := filesystem.OwnerUID(info)
	permissions := info.Mode().Perm()
	// Requiring every execute bit is conservative but keeps the future runtime
	// UID/GID able to exec Firecracker without trusting uninspected file groups.
	return ownerKnown && ownerUID == 0 && permissions&0o111 == 0o111 && permissions&0o022 == 0 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0
}

func validStrictJailerHostDirectoryInfo(filesystem strictJailerHostInspectionFilesystem, info os.FileInfo) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	ownerUID, ownerKnown := filesystem.OwnerUID(info)
	permissions := info.Mode().Perm()
	return ownerKnown && ownerUID == 0 && permissions&0o100 != 0 && permissions&0o022 == 0
}

func strictJailerHostConfiguredPath(path, field string) (string, error) {
	if strings.TrimSpace(path) != path || !filepathIsCleanAbsolute(path) || cleanupFilesystemRoot(path) {
		return "", newStrictJailerHostInspectionError(field)
	}
	return path, nil
}

func newStrictJailerHostInspectionError(field string) *strictJailerHostInspectionError {
	return &strictJailerHostInspectionError{field: safeStrictJailerHostInspectionField(field)}
}

func safeStrictJailerHostInspectionField(field string) string {
	switch strings.TrimSpace(field) {
	case "filesystem", "jailerPath", "firecrackerPath", "jailerIdentity", "firecrackerIdentity",
		"binaryPair", "uid", "gid", "chrootBaseDir":
		return strings.TrimSpace(field)
	default:
		return ""
	}
}
