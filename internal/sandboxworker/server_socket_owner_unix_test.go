//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package sandboxworker

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestValidateWorkerSocketParentOwner(t *testing.T) {
	currentUID := uint32(os.Geteuid())
	if err := validateWorkerSocketParentOwner(workerSocketOwnerTestInfo{uid: currentUID}); err != nil {
		t.Fatalf("validateWorkerSocketParentOwner(current user) error: %v", err)
	}
	if err := validateWorkerSocketParentOwner(workerSocketOwnerTestInfo{uid: currentUID + 1}); err == nil {
		t.Fatal("validateWorkerSocketParentOwner(other user) error = nil")
	}
}

type workerSocketOwnerTestInfo struct {
	uid uint32
}

func (info workerSocketOwnerTestInfo) Name() string       { return "socket-parent" }
func (info workerSocketOwnerTestInfo) Size() int64        { return 0 }
func (info workerSocketOwnerTestInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (info workerSocketOwnerTestInfo) ModTime() time.Time { return time.Time{} }
func (info workerSocketOwnerTestInfo) IsDir() bool        { return true }
func (info workerSocketOwnerTestInfo) Sys() any           { return &syscall.Stat_t{Uid: info.uid} }
