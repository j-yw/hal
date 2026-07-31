package linuxtopology

import (
	"errors"
	"os"
	"sync"
)

// NamespaceHandle retains open owning user and network namespace descriptors.
// Its descriptors and kernel identity are deliberately unexported and omitted
// from JSON. Duplicate is the only way to transfer temporary live ownership.
type NamespaceHandle struct {
	mu       sync.Mutex
	user     *os.File
	network  *os.File
	userInfo os.FileInfo
	netInfo  os.FileInfo
	closed   bool
}

func NewNamespaceHandle(user, network *os.File) (*NamespaceHandle, error) {
	if user == nil || network == nil {
		return nil, ErrStartFailed
	}
	userInfo, err := user.Stat()
	if err != nil {
		return nil, ErrStartFailed
	}
	netInfo, err := network.Stat()
	if err != nil {
		return nil, ErrStartFailed
	}
	return &NamespaceHandle{user: user, network: network, userInfo: userInfo, netInfo: netInfo}, nil
}

func (h *NamespaceHandle) Duplicate() (*NamespaceHandle, error) {
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
	duplicate, err := NewNamespaceHandle(user, network)
	if err != nil {
		_ = user.Close()
		_ = network.Close()
		return nil, err
	}
	if !duplicate.Correlates(h) {
		_ = duplicate.Close()
		return nil, ErrIdentityMismatch
	}
	return duplicate, nil
}

// Correlates compares the retained kernel identities without exposing device
// or inode values.
func (h *NamespaceHandle) Correlates(other *NamespaceHandle) bool {
	if h == nil || other == nil || h.userInfo == nil || h.netInfo == nil ||
		other.userInfo == nil || other.netInfo == nil {
		return false
	}
	return os.SameFile(h.userInfo, other.userInfo) && os.SameFile(h.netInfo, other.netInfo)
}

func (h *NamespaceHandle) distinctFrom(other *NamespaceHandle) bool {
	if h == nil || other == nil || h.userInfo == nil || h.netInfo == nil ||
		other.userInfo == nil || other.netInfo == nil {
		return false
	}
	return !os.SameFile(h.userInfo, other.userInfo) && !os.SameFile(h.netInfo, other.netInfo)
}

func (h *NamespaceHandle) extraFiles() ([]*os.File, error) {
	duplicate, err := h.Duplicate()
	if err != nil {
		return nil, err
	}
	duplicate.mu.Lock()
	files := []*os.File{duplicate.user, duplicate.network}
	duplicate.user = nil
	duplicate.network = nil
	duplicate.closed = true
	duplicate.mu.Unlock()
	return files, nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (h *NamespaceHandle) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	var result error
	if h.user != nil {
		result = errors.Join(result, h.user.Close())
		h.user = nil
	}
	if h.network != nil {
		result = errors.Join(result, h.network.Close())
		h.network = nil
	}
	return result
}

func (h *NamespaceHandle) Closed() bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}
