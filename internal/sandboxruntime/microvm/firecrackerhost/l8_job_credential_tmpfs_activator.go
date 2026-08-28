package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	l8JobCredentialFileTmpfsValuePlaceholder = "[firecracker-l8-job-credential-file-tmpfs]"
	// Per-file fill bound matches the guest helper private-file ceiling without
	// importing the helper protocol into this host activator.
	l8JobCredentialFileTmpfsMaxBytes = 64 * 1024
	l8JobCredentialFileTmpfsDirMode  = 0o700
	l8JobCredentialFileTmpfsFileMode = 0o600
)

// L8JobCredentialFileTmpfsActivatorOptions selects the host scratch root for
// one explicit production file-tmpfs activator. Callers must inject a
// non-project directory; the constructor never defaults to `.hal/`.
type L8JobCredentialFileTmpfsActivatorOptions struct {
	RootDir string
}

// L8JobCredentialFileTmpfsActivator is the default-off host file-tmpfs
// materializer. It is never constructed by sandboxd, run/auto/factory, worker
// defaults, or NewProductionL8JobCredentialRuntime unless a caller injects it.
type L8JobCredentialFileTmpfsActivator struct {
	rootDir string
}

type l8JobCredentialFileHandleProduction struct {
	mu         sync.Mutex
	targetPath string
	size       uint32
	digest     string
	dir        string
	filePath   string
	file       *os.File
	owned      bool
}

type l8JobCredentialFileTmpfsSink struct {
	max     int
	payload []byte
}

func NewProductionL8JobCredentialFileTmpfsActivator(options L8JobCredentialFileTmpfsActivatorOptions) (*L8JobCredentialFileTmpfsActivator, error) {
	if !l8JobCredentialRuntimePlatformSupported() {
		return nil, ErrL8JobCredentialRuntimeUnsupported
	}
	rootDir, err := validateL8JobCredentialFileTmpfsRoot(options.RootDir)
	if err != nil {
		return nil, err
	}
	return &L8JobCredentialFileTmpfsActivator{rootDir: rootDir}, nil
}

func (activator *L8JobCredentialFileTmpfsActivator) Materialize(ctx context.Context, identity sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest, source sandboxruntime.LiveSecretSource) (handle l8JobCredentialFileHandle, err error) {
	if activator == nil || activator.rootDir == "" {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if !l8JobCredentialRuntimePlatformSupported() {
		return nil, ErrL8JobCredentialRuntimeUnsupported
	}
	if l8JobCredentialRuntimeValueIsNil(ctx) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if binding.Mode != sandboxruntime.JobCredentialDeliveryModeFileTmpfs {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if err := matchL8JobCredentialFileTmpfsIdentity(identity, binding); err != nil {
		return nil, err
	}
	targetPath, err := l8JobCredentialFileTmpfsGuestTargetPath(binding)
	if err != nil {
		return nil, err
	}
	if l8JobCredentialRuntimeValueIsNil(source) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}

	sink := &l8JobCredentialFileTmpfsSink{max: l8JobCredentialFileTmpfsMaxBytes}
	fillErr := source.FillSecret(ctx, sink)
	source = nil
	if fillErr != nil {
		sink.wipe()
		return nil, sanitizeL8JobCredentialFileTmpfsError(fillErr)
	}
	if err := ctx.Err(); err != nil {
		sink.wipe()
		return nil, err
	}
	payload := sink.payload
	sink.payload = nil
	defer clear(payload)
	if len(payload) == 0 || len(payload) > l8JobCredentialFileTmpfsMaxBytes {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}

	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	dir, filePath, file, err := materializeL8JobCredentialFileTmpfsPayload(activator.rootDir, payload)
	if err != nil {
		return nil, sanitizeL8JobCredentialFileTmpfsError(err)
	}
	return &l8JobCredentialFileHandleProduction{
		targetPath: targetPath,
		size:       uint32(len(payload)),
		digest:     digest,
		dir:        dir,
		filePath:   filePath,
		file:       file,
		owned:      true,
	}, nil
}

func (handle *l8JobCredentialFileHandleProduction) TargetPath() string {
	if handle == nil {
		return ""
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.targetPath
}

func (handle *l8JobCredentialFileHandleProduction) DeclaredFileBytes() uint32 {
	if handle == nil {
		return 0
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.size
}

func (handle *l8JobCredentialFileHandleProduction) FileSHA256() string {
	if handle == nil {
		return ""
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.digest
}

func (handle *l8JobCredentialFileHandleProduction) Revoke(context.Context) error {
	if handle == nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if !handle.owned {
		return nil
	}
	file, err := wipeL8JobCredentialFileTmpfsMaterialization(handle.file, handle.filePath, handle.dir, handle.size)
	handle.file = file
	if err != nil {
		// Keep owned so a later retry can still wipe and unlink.
		return sanitizeL8JobCredentialFileTmpfsError(err)
	}
	handle.owned = false
	handle.file = nil
	handle.filePath = ""
	handle.dir = ""
	return nil
}

func matchL8JobCredentialFileTmpfsIdentity(identity sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest) error {
	if sandboxruntime.ValidateJobCredentialIdentity(identity) != nil {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	for index, bindingID := range identity.BindingIDs {
		if bindingID != binding.ID {
			continue
		}
		if identity.DeliveryModes[index] != sandboxruntime.JobCredentialDeliveryModeFileTmpfs {
			return sandboxruntime.ErrJobCredentialIdentityMismatch
		}
		return nil
	}
	return sandboxruntime.ErrJobCredentialIdentityMismatch
}

func l8JobCredentialFileTmpfsGuestTargetPath(binding sandboxruntime.JobCredentialBindingRequest) (string, error) {
	// The guest path is the binding's already-safe identity token. Host absolute
	// scratch paths must never become TargetPath.
	if !validL8JobCredentialRuntimeToken(binding.ID) {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	if strings.Contains(binding.ID, "/") || strings.Contains(binding.ID, "\\") || strings.HasPrefix(binding.ID, ".") {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	return binding.ID, nil
}

func validateL8JobCredentialFileTmpfsRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	cleaned := filepath.Clean(root)
	if !filepath.IsAbs(cleaned) || l8JobCredentialFileTmpfsPathHasHalDir(cleaned) {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() || l8JobCredentialFileTmpfsPathHasHalDir(resolved) {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	return resolved, nil
}

func l8JobCredentialFileTmpfsPathHasHalDir(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".hal" {
			return true
		}
	}
	return false
}

func sanitizeL8JobCredentialFileTmpfsError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch):
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	case errors.Is(err, ErrL8JobCredentialRuntimeUnsupported):
		return ErrL8JobCredentialRuntimeUnsupported
	case errors.Is(err, ErrL8JobCredentialRuntimeInvalid):
		return ErrL8JobCredentialRuntimeInvalid
	default:
		return ErrL8JobCredentialRuntimeUnavailable
	}
}

func (sink *l8JobCredentialFileTmpfsSink) MaxCredentialBytes() int {
	if sink == nil || sink.max <= 0 {
		return 0
	}
	return sink.max
}

func (sink *l8JobCredentialFileTmpfsSink) WriteCredential(value []byte) error {
	if sink == nil || sink.max <= 0 || sink.payload != nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	if len(value) == 0 || len(value) > sink.max {
		return ErrL8JobCredentialRuntimeInvalid
	}
	sink.payload = append([]byte(nil), value...)
	return nil
}

func (sink *l8JobCredentialFileTmpfsSink) wipe() {
	if sink == nil {
		return
	}
	clear(sink.payload)
	sink.payload = nil
}

func (*L8JobCredentialFileTmpfsActivator) String() string {
	return l8JobCredentialFileTmpfsValuePlaceholder
}
func (*L8JobCredentialFileTmpfsActivator) GoString() string {
	return l8JobCredentialFileTmpfsValuePlaceholder
}
func (*L8JobCredentialFileTmpfsActivator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialFileTmpfsValuePlaceholder)
}
func (*L8JobCredentialFileTmpfsActivator) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*L8JobCredentialFileTmpfsActivator) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*L8JobCredentialFileTmpfsActivator) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}

func (*l8JobCredentialFileHandleProduction) String() string {
	return l8JobCredentialFileTmpfsValuePlaceholder
}
func (*l8JobCredentialFileHandleProduction) GoString() string {
	return l8JobCredentialFileTmpfsValuePlaceholder
}
func (*l8JobCredentialFileHandleProduction) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialFileTmpfsValuePlaceholder)
}
func (*l8JobCredentialFileHandleProduction) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*l8JobCredentialFileHandleProduction) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*l8JobCredentialFileHandleProduction) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}

var (
	_ l8JobCredentialFileTmpfsActivator      = (*L8JobCredentialFileTmpfsActivator)(nil)
	_ l8JobCredentialFileHandle              = (*l8JobCredentialFileHandleProduction)(nil)
	_ sandboxruntime.JobCredentialSecretSink = (*l8JobCredentialFileTmpfsSink)(nil)
	_ fmt.Stringer                           = (*L8JobCredentialFileTmpfsActivator)(nil)
	_ fmt.Stringer                           = (*l8JobCredentialFileHandleProduction)(nil)
)
