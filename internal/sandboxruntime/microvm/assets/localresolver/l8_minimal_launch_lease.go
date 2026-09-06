package localresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
)

// VerifiedL8MinimalLaunchLease owns files transferred from exactly one verified
// minimal distribution. It issues no L7/legacy L8 seal or runtime-ready claim.
// Copies share close state. The caller must Close after staging/start returns.
type VerifiedL8MinimalLaunchLease struct{ state *minimalDistributionState }

// L8MinimalLaunchAsset is a callback-scoped read-only source with verified
// measurements. The consumer must hash the actual bytes copied and its staged
// output: a retained regular file is not an immutable snapshot.
type L8MinimalLaunchAsset struct {
	Source    io.ReadSeeker
	SizeBytes int64
	SHA256    string
}

func (*VerifiedL8MinimalLaunchLease) String() string   { return "<minimal launch ownership>" }
func (*VerifiedL8MinimalLaunchLease) GoString() string { return "<minimal launch ownership>" }
func (*VerifiedL8MinimalLaunchLease) MarshalJSON() ([]byte, error) {
	return nil, minimalDistributionError(ErrInvalidRequest)
}
func (*VerifiedL8MinimalLaunchLease) MarshalText() ([]byte, error) {
	return nil, minimalDistributionError(ErrInvalidRequest)
}

// TakeLaunchLease atomically transfers existing descriptor ownership without
// reopening asset paths for consumption. Other distribution aliases become
// inert; their Close cannot close the accepted lease's files.
func (verified VerifiedL8MinimalDistribution) TakeLaunchLease(ctx context.Context) (*VerifiedL8MinimalLaunchLease, error) {
	if verified.state == nil {
		return nil, minimalDistributionError(ErrInvalidRequest)
	}
	state := verified.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.transferred {
		return nil, minimalDistributionError(ErrInvalidRequest)
	}
	if err := state.confirmLaunchCurrent(ctx); err != nil {
		return nil, err
	}
	state.transferred = true
	return &VerifiedL8MinimalLaunchLease{state: state}, nil
}

func (lease *VerifiedL8MinimalLaunchLease) ConfirmCurrent(ctx context.Context) error {
	if lease == nil || lease.state == nil {
		return minimalDistributionError(ErrInvalidRequest)
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	return lease.state.confirmLaunchCurrent(ctx)
}

// WithAssets serializes a bounded borrow with Close. Views expire on return or
// panic. Callbacks must not re-enter or Close the lease. No descriptor escapes.
func (lease *VerifiedL8MinimalLaunchLease) WithAssets(ctx context.Context, use func(kernel, rootfs L8MinimalLaunchAsset) error) error {
	if lease == nil || lease.state == nil || use == nil {
		return minimalDistributionError(ErrInvalidRequest)
	}
	state := lease.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.confirmLaunchCurrent(ctx); err != nil {
		return err
	}
	kernel := newMinimalLaunchReader(ctx, state.files["vmlinux"])
	rootfs := newMinimalLaunchReader(ctx, state.files["rootfs.ext4"])
	defer kernel.expire()
	defer rootfs.expire()
	asset := func(name string, reader *minimalLaunchReader) L8MinimalLaunchAsset {
		pinned := state.files[name]
		return L8MinimalLaunchAsset{Source: reader, SizeBytes: pinned.size, SHA256: minimalPinnedDigest(pinned)}
	}
	if err := use(asset("vmlinux", kernel), asset("rootfs.ext4", rootfs)); err != nil {
		return minimalLaunchError(err)
	}
	// Revoke borrowed readers before measuring, including concurrent late reads.
	kernel.expire()
	rootfs.expire()
	return state.confirmLaunchCurrent(ctx)
}

func (lease *VerifiedL8MinimalLaunchLease) Close() error {
	if lease == nil || lease.state == nil {
		return nil
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	return lease.state.closeLocked()
}

func minimalLaunchError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return minimalDistributionError(err)
}

// Revalidate the already authenticated documents by exact retained bytes. No
// mutable metadata is reparsed and no new authority is minted during handoff.
func (state *minimalDistributionState) confirmLaunchCurrent(ctx context.Context) error {
	if ctx == nil || state.closed || state.root == nil || state.parentLease == nil {
		return minimalDistributionError(ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent := state.parentLease
	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.closed || confirmMinimalLaunchRoot(state.rootDir, state.root, verifyMinimalEntrySet) != nil ||
		confirmMinimalLaunchRoot(parent.rootDir, parent.root, func(root *os.File) error {
			return verifyMinimalLaunchEntrySet(root, l5RequiredDistributionOutputs)
		}) != nil {
		return minimalDistributionError(ErrAssetLockMismatch)
	}
	parentFiles := make(map[string]l8PinnedAsset, len(state.parentMetadata)+2)
	for name, pinned := range state.parentMetadata {
		parentFiles[name] = pinned
	}
	for _, item := range []struct {
		name   string
		file   *os.File
		size   int64
		digest string
	}{
		{"vmlinux", parent.kernel, state.parentEvidence.KernelSizeBytes, state.parentEvidence.KernelSHA256},
		{"rootfs.ext4", parent.rootfs, state.parentEvidence.RootfsSizeBytes, state.parentEvidence.RootfsSHA256},
	} {
		digest, err := decodeL8Digest(item.digest)
		if err != nil {
			return minimalDistributionError(err)
		}
		parentFiles[item.name] = l8PinnedAsset{file: item.file, size: item.size, digest: digest}
	}
	for _, set := range []struct {
		root  *os.File
		files map[string]l8PinnedAsset
	}{{state.root, state.files}, {parent.root, parentFiles}} {
		for name, pinned := range set.files {
			if err := confirmMinimalLaunchFile(ctx, set.root, name, pinned); err != nil {
				return minimalLaunchError(err)
			}
		}
	}
	return ctx.Err()
}

func confirmMinimalLaunchRoot(path string, retained *os.File, inventory func(*os.File) error) error {
	current, _, err := openRequestedDistributionRoot(path)
	if err != nil {
		return ErrAssetLockMismatch
	}
	oldInfo, oldErr := retained.Stat()
	newInfo, newErr := current.Stat()
	entryErr := inventory(current)
	closeErr := current.Close()
	if oldErr != nil || newErr != nil || entryErr != nil || closeErr != nil || !os.SameFile(oldInfo, newInfo) {
		return ErrAssetLockMismatch
	}
	return nil
}

func confirmMinimalLaunchFile(ctx context.Context, root *os.File, name string, pinned l8PinnedAsset) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := openDistributionFileNoFollow(root, name)
	if err != nil {
		return ErrAssetLockMismatch
	}
	before, beforeErr := pinned.file.Stat()
	named, namedErr := current.Stat()
	closeErr := current.Close()
	if beforeErr != nil || namedErr != nil || closeErr != nil || !before.Mode().IsRegular() || before.Size() != pinned.size || !os.SameFile(before, named) {
		return ErrAssetLockMismatch
	}
	reader := newMinimalLaunchReader(ctx, pinned)
	defer reader.expire()
	hash := sha256.New()
	n, err := io.Copy(hash, reader)
	if err != nil {
		return err
	}
	after, statErr := pinned.file.Stat()
	if statErr != nil || after.Size() != pinned.size || !os.SameFile(before, after) || n != pinned.size || hex.EncodeToString(hash.Sum(nil)) != minimalPinnedDigest(pinned) {
		return ErrAssetLockMismatch
	}
	return ctx.Err()
}

type minimalLaunchReader struct {
	mu     sync.Mutex
	ctx    context.Context
	reader *io.SectionReader
	size   int64
}

func newMinimalLaunchReader(ctx context.Context, pinned l8PinnedAsset) *minimalLaunchReader {
	return &minimalLaunchReader{ctx: ctx, reader: io.NewSectionReader(pinned.file, 0, pinned.size), size: pinned.size}
}

func (reader *minimalLaunchReader) expire() {
	reader.mu.Lock()
	reader.reader = nil
	reader.mu.Unlock()
}
func (reader *minimalLaunchReader) Read(destination []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.reader == nil {
		return 0, io.ErrClosedPipe
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if len(destination) > 32<<10 {
		destination = destination[:32<<10]
	}
	n, err := reader.reader.Read(destination)
	if err != nil && err != io.EOF {
		err = minimalLaunchError(err)
	}
	return n, err
}
func (reader *minimalLaunchReader) Seek(offset int64, whence int) (int64, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.reader == nil {
		return 0, io.ErrClosedPipe
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	position, err := reader.reader.Seek(offset, whence)
	if err != nil || position < 0 || position > reader.size {
		return 0, minimalDistributionError(ErrInvalidRequest)
	}
	return position, nil
}
