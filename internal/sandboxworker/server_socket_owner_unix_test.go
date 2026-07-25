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

func TestValidateWorkerSocketAncestorTrust(t *testing.T) {
	currentUID := uint32(os.Geteuid())
	tests := []struct {
		name    string
		info    workerSocketOwnerTestInfo
		wantErr bool
	}{
		{
			name: "private current-user ancestor",
			info: workerSocketOwnerTestInfo{uid: currentUID, mode: os.ModeDir | 0o700},
		},
		{
			name: "root-owned read-only ancestor",
			info: workerSocketOwnerTestInfo{uid: 0, mode: os.ModeDir | 0o755},
		},
		{
			name: "root-owned sticky temporary ancestor",
			info: workerSocketOwnerTestInfo{uid: 0, mode: os.ModeDir | os.ModeSticky | 0o777},
		},
		{
			name:    "replaceable current-user ancestor",
			info:    workerSocketOwnerTestInfo{uid: currentUID, mode: os.ModeDir | 0o777},
			wantErr: true,
		},
		{
			name:    "other-user ancestor",
			info:    workerSocketOwnerTestInfo{uid: currentUID + 1, mode: os.ModeDir | 0o755},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkerSocketAncestorTrust(tt.info)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateWorkerSocketAncestorTrust() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type workerSocketOwnerTestInfo struct {
	uid  uint32
	mode os.FileMode
}

func (info workerSocketOwnerTestInfo) Name() string { return "socket-parent" }
func (info workerSocketOwnerTestInfo) Size() int64  { return 0 }
func (info workerSocketOwnerTestInfo) Mode() os.FileMode {
	if info.mode == 0 {
		return os.ModeDir | 0o700
	}
	return info.mode
}
func (info workerSocketOwnerTestInfo) ModTime() time.Time { return time.Time{} }
func (info workerSocketOwnerTestInfo) IsDir() bool        { return true }
func (info workerSocketOwnerTestInfo) Sys() any           { return &syscall.Stat_t{Uid: info.uid} }
