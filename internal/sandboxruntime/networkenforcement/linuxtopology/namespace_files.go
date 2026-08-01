package linuxtopology

import (
	"errors"
	"os"
	"sync"
)

// NamespaceFiles is a live-only duplicate of an already-owned user/network
// namespace pair. It exists solely for narrow namespace-FD command adapters.
// Callers must close it before closing the NamespaceHandle from which it was
// borrowed; neither descriptors nor their kernel identities are serializable.
type NamespaceFiles struct {
	mu      sync.Mutex
	user    *os.File
	network *os.File
	closed  bool
}

// MarshalJSON makes the live-only contract explicit if a containing value is
// accidentally encoded. Descriptor numbers and kernel identity never cross
// the process boundary.
func (*NamespaceFiles) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// BorrowFiles duplicates both descriptors atomically from the perspective of
// the handle. A partial duplicate is always closed before failure returns.
func (h *NamespaceHandle) BorrowFiles() (*NamespaceFiles, error) {
	if h == nil {
		return nil, ErrStopped
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.user == nil || h.network == nil {
		return nil, ErrStopped
	}
	user, err := duplicateNamespaceFile(h.user)
	if err != nil {
		return nil, ErrStartFailed
	}
	network, err := duplicateNamespaceFile(h.network)
	if err != nil {
		_ = user.Close()
		return nil, ErrStartFailed
	}
	files := &NamespaceFiles{user: user, network: network}
	if !files.valid() {
		_ = files.Close()
		return nil, ErrIdentityMismatch
	}
	return files, nil
}

func (f *NamespaceFiles) valid() bool {
	return f != nil && f.user != nil && f.network != nil && f.user.Fd() > 2 && f.network.Fd() > 2 && f.user.Fd() != f.network.Fd()
}

func (f *NamespaceFiles) UserFD() int {
	if f == nil {
		return -1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.user == nil {
		return -1
	}
	return int(f.user.Fd())
}

func (f *NamespaceFiles) NetworkFD() int {
	if f == nil {
		return -1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.network == nil {
		return -1
	}
	return int(f.network.Fd())
}

// DuplicateForCommand returns one independently owned descriptor pair for a
// single child launch. The caller must close both files after Start returns.
func (f *NamespaceFiles) DuplicateForCommand() (*os.File, *os.File, error) {
	if f == nil {
		return nil, nil, ErrStopped
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.user == nil || f.network == nil {
		return nil, nil, ErrStopped
	}
	user, err := duplicateNamespaceFile(f.user)
	if err != nil {
		return nil, nil, ErrStartFailed
	}
	network, err := duplicateNamespaceFile(f.network)
	if err != nil {
		_ = user.Close()
		return nil, nil, ErrStartFailed
	}
	return user, network, nil
}

func (f *NamespaceFiles) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	var result error
	if f.user != nil {
		result = errors.Join(result, f.user.Close())
		f.user = nil
	}
	if f.network != nil {
		result = errors.Join(result, f.network.Close())
		f.network = nil
	}
	return result
}
