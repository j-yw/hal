package firecrackerhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

var (
	errJailerStagingInvalid           = errors.New("strict Jailer resource staging is invalid")
	errJailerStagingFailed            = errors.New("strict Jailer resource staging failed")
	errJailerStagingCleanupIncomplete = errors.New("strict Jailer resource staging cleanup is incomplete")
)

const maxJailerStagingSupportFiles = 16

type jailerStagingResourceRole string

const (
	jailerStagingRoleKernel  jailerStagingResourceRole = "kernel"
	jailerStagingRoleRootfs  jailerStagingResourceRole = "rootfs"
	jailerStagingRoleConfig  jailerStagingResourceRole = "config"
	jailerStagingRoleSupport jailerStagingResourceRole = "support"
)

// jailerStagingAuthority is produced only after a later host inspector has
// pinned the chroot base, canonical Firecracker executable, generation, and
// dedicated non-root ownership. This slice validates their correlation but
// does not claim to perform that inspection.
type jailerStagingAuthority struct {
	RuntimeID                string
	CanonicalFirecrackerPath string
	ChrootBaseDir            string
	JailRootHostPath         string
	UID                      uint32
	GID                      uint32
	DirectoryMode            os.FileMode
}

// jailerStagingResourceInput carries an already-opened source and its expected
// immutable measurement. The caller retains and closes Source. No host source
// path crosses this boundary.
type jailerStagingResourceInput struct {
	ID        string
	JailPath  string
	Source    io.ReadSeeker
	SizeBytes int64
	SHA256    string
	Mode      os.FileMode
}

type jailerStagingRequest struct {
	Authority jailerStagingAuthority
	Kernel    jailerStagingResourceInput
	Rootfs    jailerStagingResourceInput
	Config    jailerStagingResourceInput
	Support   []jailerStagingResourceInput
}

// jailerStagingFilesystem is a capability boundary rooted in an already
// inspected chroot authority. A real implementation must create the exact
// precreated Jailer HostRoot exclusively and resolve every component relative
// to retained directory file descriptors without following symlinks. It must
// return nil on any creation error. This slice intentionally supplies no
// path-based os adapter because Lstat followed by path mutation would not
// satisfy that contract.
//
// A later lifecycle slice must also prove that Jailer consumes this same root
// generation without replacing it before calling the coordinator production
// capable.
type jailerStagingFilesystem interface {
	createExclusiveRoot(jailerStagingRootRequest) (jailerStagingRoot, error)
}

type jailerStagingRootRequest struct {
	HostRoot string
	Mode     os.FileMode
	UID      uint32
	GID      uint32
}

// jailerStagingRoot represents exactly the newly created generation. All
// relative operations must remain handle-bound, reject symlinks and existing
// entries, and verify that the retained root generation has not changed.
type jailerStagingRoot interface {
	createDirectory(relative string, mode os.FileMode, uid, gid uint32) error
	createFileExclusive(relative string) (jailerStagingFile, error)
	verifyOwned() error
	removeOwned() error
	close() error
}

// jailerStagingFile is an exclusively created, retained file handle. Reads,
// writes, ownership, mode, and sync operations apply to that same handle, so a
// path replacement cannot redirect verification to a different object.
type jailerStagingFile interface {
	io.Reader
	io.Writer
	io.Seeker
	sync() error
	setOwnership(uid, gid uint32) error
	setMode(os.FileMode) error
	verifyIdentity() error
	close() error
}

type jailerStagingPathCorrelation struct {
	role      jailerStagingResourceRole
	id        string
	hostPath  string
	jailPath  string
	sizeBytes int64
	sha256    string
	mode      os.FileMode
}

// jailerStagingResult has no durable or public JSON shape. The exact private
// correlations are for the future atomic lifecycle consumer only.
type jailerStagingResult struct {
	correlations []jailerStagingPathCorrelation
}

func (result jailerStagingResult) pathCorrelations() []jailerStagingPathCorrelation {
	return append([]jailerStagingPathCorrelation(nil), result.correlations...)
}

// processInheritedFiles is deliberately empty: Jailer closes inherited asset
// descriptors, so the staged path generation replaces that launch mechanism.
func (jailerStagingResult) processInheritedFiles() []*os.File {
	return []*os.File{}
}

type validatedJailerStagingResource struct {
	role      jailerStagingResourceRole
	id        string
	jailPath  string
	relative  string
	hostPath  string
	source    io.ReadSeeker
	sizeBytes int64
	sha256    string
	mode      os.FileMode
}

// stageStrictJailerResources is only an injected staging coordinator. It
// creates one private resource tree through the supplied handle-oriented
// filesystem; this package does not yet provide a production filesystem
// implementation. It performs no process launch, runtime selection, security
// projection, network operation, or credential delivery.
func stageStrictJailerResources(filesystem jailerStagingFilesystem, request jailerStagingRequest) (jailerStagingResult, error) {
	if interfaceValueIsNil(filesystem) {
		return jailerStagingResult{}, newJailerStagingError(errJailerStagingInvalid, "filesystem")
	}
	authority, err := validateJailerStagingAuthority(request.Authority)
	if err != nil {
		return jailerStagingResult{}, err
	}
	resources, err := validateJailerStagingResources(authority, request)
	if err != nil {
		return jailerStagingResult{}, err
	}

	root, createErr := filesystem.createExclusiveRoot(jailerStagingRootRequest{
		HostRoot: authority.JailRootHostPath,
		Mode:     authority.DirectoryMode,
		UID:      authority.UID,
		GID:      authority.GID,
	})
	if createErr != nil || interfaceValueIsNil(root) {
		return jailerStagingResult{}, newJailerStagingError(errJailerStagingFailed, "root")
	}

	result, stageErr := stageJailerOwnedRoot(root, authority, resources)
	if stageErr != nil {
		return jailerStagingResult{}, cleanupFailedJailerStagingRoot(root, stageErr)
	}
	if closeErr := root.close(); closeErr != nil {
		primary := newJailerStagingError(errJailerStagingFailed, "root_close")
		if removeErr := root.removeOwned(); removeErr != nil {
			return jailerStagingResult{}, errors.Join(primary, newJailerStagingError(errJailerStagingCleanupIncomplete, "root"))
		}
		return jailerStagingResult{}, errors.Join(primary, newJailerStagingError(errJailerStagingCleanupIncomplete, "root_close"))
	}
	return result, nil
}

func validateJailerStagingAuthority(authority jailerStagingAuthority) (jailerStagingAuthority, error) {
	authority.RuntimeID = strings.TrimSpace(authority.RuntimeID)
	authority.CanonicalFirecrackerPath = strings.TrimSpace(authority.CanonicalFirecrackerPath)
	authority.ChrootBaseDir = strings.TrimSpace(authority.ChrootBaseDir)
	authority.JailRootHostPath = strings.TrimSpace(authority.JailRootHostPath)
	if !validStrictJailerRuntimeID(authority.RuntimeID) ||
		!filepathIsCleanAbsolute(authority.CanonicalFirecrackerPath) || cleanupFilesystemRoot(authority.CanonicalFirecrackerPath) ||
		!filepathIsCleanAbsolute(authority.ChrootBaseDir) || cleanupFilesystemRoot(authority.ChrootBaseDir) ||
		!filepathIsCleanAbsolute(authority.JailRootHostPath) || cleanupFilesystemRoot(authority.JailRootHostPath) ||
		authority.UID == 0 || authority.GID == 0 || authority.DirectoryMode != 0o700 {
		return jailerStagingAuthority{}, newJailerStagingError(errJailerStagingInvalid, "authority")
	}
	wantRoot := filepath.Join(
		authority.ChrootBaseDir,
		filepath.Base(authority.CanonicalFirecrackerPath),
		authority.RuntimeID,
		"root",
	)
	if authority.JailRootHostPath != wantRoot {
		return jailerStagingAuthority{}, newJailerStagingError(errJailerStagingInvalid, "authority")
	}
	return authority, nil
}

func validateJailerStagingResources(authority jailerStagingAuthority, request jailerStagingRequest) ([]validatedJailerStagingResource, error) {
	if len(request.Support) > maxJailerStagingSupportFiles {
		return nil, newJailerStagingError(errJailerStagingInvalid, "resources")
	}
	type candidate struct {
		role     jailerStagingResourceRole
		input    jailerStagingResourceInput
		required string
	}
	candidates := []candidate{
		{role: jailerStagingRoleKernel, input: request.Kernel, required: "kernel"},
		{role: jailerStagingRoleRootfs, input: request.Rootfs, required: "rootfs"},
		{role: jailerStagingRoleConfig, input: request.Config, required: "config"},
	}
	for _, support := range request.Support {
		candidates = append(candidates, candidate{role: jailerStagingRoleSupport, input: support})
	}

	seenIDs := make(map[string]struct{}, len(candidates))
	seenPaths := make(map[string]struct{}, len(candidates))
	resources := make([]validatedJailerStagingResource, 0, len(candidates))
	for _, candidate := range candidates {
		input := candidate.input
		input.ID = strings.TrimSpace(input.ID)
		input.SHA256 = strings.TrimSpace(input.SHA256)
		if candidate.required != "" && input.ID != candidate.required ||
			candidate.role == jailerStagingRoleSupport && (!strings.HasPrefix(input.ID, "support-") || !validStrictJailerRuntimeID(input.ID)) ||
			interfaceValueIsNil(input.Source) || input.SizeBytes < 0 || input.SizeBytes == math.MaxInt64 ||
			!validJailerStagingDigest(input.SHA256) || !validJailerStagingFileMode(input.Mode) {
			return nil, newJailerStagingError(errJailerStagingInvalid, "resources")
		}
		jailPath, relative, pathErr := validateJailerStagingPath(input.JailPath)
		if pathErr != nil {
			return nil, newJailerStagingError(errJailerStagingInvalid, "resources")
		}
		if _, duplicate := seenIDs[input.ID]; duplicate {
			return nil, newJailerStagingError(errJailerStagingInvalid, "resources")
		}
		if _, duplicate := seenPaths[jailPath]; duplicate {
			return nil, newJailerStagingError(errJailerStagingInvalid, "resources")
		}
		seenIDs[input.ID] = struct{}{}
		seenPaths[jailPath] = struct{}{}
		hostPath := filepath.Join(authority.JailRootHostPath, filepath.FromSlash(relative))
		if !pathWithin(authority.JailRootHostPath, hostPath) {
			return nil, newJailerStagingError(errJailerStagingInvalid, "resources")
		}
		resources = append(resources, validatedJailerStagingResource{
			role: candidate.role, id: input.ID, jailPath: jailPath, relative: filepath.FromSlash(relative),
			hostPath: hostPath, source: input.Source, sizeBytes: input.SizeBytes, sha256: input.SHA256, mode: input.Mode,
		})
	}
	return resources, nil
}

func validateJailerStagingPath(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	cleaned := path.Clean(value)
	if value == "" || cleaned != value || !path.IsAbs(value) || value == "/" ||
		strings.Contains(value, `\`) || hasOSExecProcessControl(value) {
		return "", "", errJailerStagingInvalid
	}
	relative := strings.TrimPrefix(value, "/")
	if relative == "" || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", "", errJailerStagingInvalid
	}
	return value, relative, nil
}

func validJailerStagingDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validJailerStagingFileMode(mode os.FileMode) bool {
	return mode == mode.Perm() && mode != 0 && mode&0o077 == 0 && mode&0o400 != 0
}

func stageJailerOwnedRoot(
	root jailerStagingRoot,
	authority jailerStagingAuthority,
	resources []validatedJailerStagingResource,
) (jailerStagingResult, error) {
	directories := jailerStagingDirectories(resources)
	for _, directory := range directories {
		if err := root.createDirectory(directory, authority.DirectoryMode, authority.UID, authority.GID); err != nil {
			return jailerStagingResult{}, newJailerStagingError(errJailerStagingFailed, "directory")
		}
	}

	correlations := make([]jailerStagingPathCorrelation, 0, len(resources))
	for _, resource := range resources {
		if err := stageJailerResource(root, authority, resource); err != nil {
			return jailerStagingResult{}, err
		}
		correlations = append(correlations, jailerStagingPathCorrelation{
			role: resource.role, id: resource.id, hostPath: resource.hostPath, jailPath: resource.jailPath,
			sizeBytes: resource.sizeBytes, sha256: resource.sha256, mode: resource.mode,
		})
	}
	if err := root.verifyOwned(); err != nil {
		return jailerStagingResult{}, newJailerStagingError(errJailerStagingFailed, "root_verify")
	}
	return jailerStagingResult{correlations: correlations}, nil
}

func jailerStagingDirectories(resources []validatedJailerStagingResource) []string {
	seen := make(map[string]struct{})
	for _, resource := range resources {
		directory := path.Dir(resource.jailPath)
		for directory != "/" && directory != "." {
			relative := strings.TrimPrefix(directory, "/")
			seen[filepath.FromSlash(relative)] = struct{}{}
			directory = path.Dir(directory)
		}
	}
	directories := make([]string, 0, len(seen))
	for directory := range seen {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	return directories
}

func stageJailerResource(root jailerStagingRoot, authority jailerStagingAuthority, resource validatedJailerStagingResource) error {
	file, err := root.createFileExclusive(resource.relative)
	if err != nil || interfaceValueIsNil(file) {
		return newJailerStagingError(errJailerStagingFailed, "file")
	}
	stageErr := writeAndVerifyJailerResource(file, authority, resource)
	closeErr := file.close()
	if stageErr != nil {
		if closeErr != nil {
			return errors.Join(stageErr, newJailerStagingError(errJailerStagingCleanupIncomplete, "file_close"))
		}
		return stageErr
	}
	if closeErr != nil {
		return errors.Join(
			newJailerStagingError(errJailerStagingFailed, "file_close"),
			newJailerStagingError(errJailerStagingCleanupIncomplete, "file_close"),
		)
	}
	return nil
}

func writeAndVerifyJailerResource(file jailerStagingFile, authority jailerStagingAuthority, resource validatedJailerStagingResource) error {
	if _, err := resource.source.Seek(0, io.SeekStart); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "source")
	}
	writtenHash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, writtenHash), io.LimitReader(resource.source, resource.sizeBytes+1))
	if err != nil || written != resource.sizeBytes || hex.EncodeToString(writtenHash.Sum(nil)) != resource.sha256 {
		return newJailerStagingError(errJailerStagingFailed, "write")
	}
	if _, err := resource.source.Seek(0, io.SeekStart); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "source")
	}
	if err := file.sync(); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "sync")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "verify")
	}
	verifiedHash := sha256.New()
	verified, err := io.Copy(verifiedHash, io.LimitReader(file, resource.sizeBytes+1))
	if err != nil || verified != resource.sizeBytes || hex.EncodeToString(verifiedHash.Sum(nil)) != resource.sha256 {
		return newJailerStagingError(errJailerStagingFailed, "verify")
	}
	if err := file.setOwnership(authority.UID, authority.GID); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "ownership")
	}
	if err := file.setMode(resource.mode); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "mode")
	}
	if err := file.sync(); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "sync")
	}
	if err := file.verifyIdentity(); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "file_verify")
	}
	return nil
}

func cleanupFailedJailerStagingRoot(root jailerStagingRoot, primary error) error {
	removeErr := root.removeOwned()
	closeErr := root.close()
	if removeErr != nil || closeErr != nil {
		return errors.Join(primary, newJailerStagingError(errJailerStagingCleanupIncomplete, "root"))
	}
	return primary
}

type jailerStagingError struct {
	kind error
	code string
}

func (err *jailerStagingError) Error() string {
	if err == nil || safeJailerStagingErrorCode(err.code) == "" || err.kind == nil {
		return errJailerStagingFailed.Error()
	}
	return err.kind.Error() + ": " + safeJailerStagingErrorCode(err.code)
}

func (err *jailerStagingError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.kind
}

func newJailerStagingError(kind error, code string) *jailerStagingError {
	return &jailerStagingError{kind: safeJailerStagingErrorKind(kind), code: safeJailerStagingErrorCode(code)}
}

func safeJailerStagingErrorKind(kind error) error {
	switch kind {
	case errJailerStagingInvalid, errJailerStagingFailed, errJailerStagingCleanupIncomplete:
		return kind
	default:
		return errJailerStagingFailed
	}
}

func safeJailerStagingErrorCode(code string) string {
	switch strings.TrimSpace(code) {
	case "filesystem", "authority", "resources", "root", "root_close", "root_verify", "directory", "file", "file_close",
		"file_verify", "source", "write", "verify", "ownership", "mode", "sync":
		return strings.TrimSpace(code)
	default:
		return ""
	}
}
