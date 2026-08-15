//go:build linux

package firecracker

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestVerifiedL7AssetLeaseClosesAllPinnedDescriptors(t *testing.T) {
	verified := verifiedL7DistributionForTest(t)
	baseline := l7OpenDescriptorCount(t)
	for iteration := 0; iteration < 32; iteration++ {
		lease, err := verified.AcquireL7AssetLease()
		if err != nil {
			t.Fatalf("AcquireL7AssetLease(%d) error = %v", iteration, err)
		}
		if err := lease.Close(); err != nil {
			t.Fatalf("Close(%d) error = %v", iteration, err)
		}
	}
	if got := l7OpenDescriptorCount(t); got != baseline {
		t.Fatalf("open descriptor count = %d, want baseline %d after lease cleanup", got, baseline)
	}
}

func TestSealedL7LaunchMaterialClosePreservesSanitizedOSCause(t *testing.T) {
	kernel, err := os.CreateTemp(t.TempDir(), "private-kernel-")
	if err != nil {
		t.Fatal(err)
	}
	rootfs, err := os.CreateTemp(t.TempDir(), "private-rootfs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, file := range []*os.File{kernel, rootfs} {
			if err := file.Close(); err != nil {
				t.Errorf("Close(%s) error = %v", file.Name(), err)
			}
		}
	})
	firstCloseFailure := &l7FirstCleanupFailure{detail: "private kernel close detail"}
	secondCloseFailure := &l7SecondCleanupFailure{detail: "private rootfs close detail"}
	closeCalls := 0
	material := &sealedL7LaunchMaterial{assets: map[assets.AssetRole]*sealedL7Asset{
		assets.AssetRoleKernel: {file: kernel},
		assets.AssetRoleRootfs: {file: rootfs},
	}, closeFile: func(file *os.File) error {
		closeCalls++
		if file == kernel {
			return firstCloseFailure
		}
		return secondCloseFailure
	}}
	firstCloseErr := material.Close()
	secondCloseErr := material.Close()
	if firstCloseErr == nil || firstCloseErr != secondCloseErr {
		t.Fatalf("repeated Close errors = (%v, %v), want one stable cleanup error", firstCloseErr, secondCloseErr)
	}
	assertL7CleanupCauses(t, firstCloseErr, firstCloseFailure, secondCloseFailure)
	if closeCalls != 2 {
		t.Fatalf("close calls = %d, want two once-only attempts", closeCalls)
	}
}

func TestL7PartialLaunchMaterialWriteCleanupCausesSurviveTranslationBoundaries(t *testing.T) {
	verified := verifiedL7DistributionForTest(t)
	lease, err := verified.AcquireL7AssetLease()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	writeFailure := &l7PartialAssetWriteFailure{detail: "private write path /host/assets/rootfs.ext4"}
	closeFailure := &l7PartialAssetCloseFailure{detail: "private memfd close detail"}
	material := &l7ProbeLaunchMaterial{
		paths: map[assets.AssetRole]string{
			assets.AssetRoleKernel: "/proc/self/fd/3",
			assets.AssetRoleRootfs: "/proc/self/fd/4",
		},
		write: func(_ assets.AssetRole, source io.Reader) error {
			var prefix [1]byte
			if _, err := io.ReadFull(source, prefix[:]); err != nil {
				return err
			}
			return errors.Join(writeFailure, newSanitizedL7LaunchMaterialCleanupError(closeFailure))
		},
	}
	descriptor := verified.Descriptor
	_, _, prepareErr := lease.PrepareLaunch(&descriptor, material)
	if prepareErr == nil {
		t.Fatal("PrepareLaunch() error = nil after partial write and close failure")
	}
	renderErr := newLiveBootRenderL7PrepareError(prepareErr)

	tests := []struct {
		name           string
		err            error
		classification error
	}{
		{name: "resolver", err: prepareErr, classification: localresolver.ErrFileUnavailable},
		{name: "firecracker", err: renderErr, classification: microvm.ErrInvalidConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.classification) {
				t.Fatalf("errors.Is(%v) = false", tt.classification)
			}
			if !errors.Is(tt.err, writeFailure) || !errors.Is(tt.err, closeFailure) {
				t.Fatalf("translation lost an exact causal identity: %v", tt.err)
			}
			var gotWrite *l7PartialAssetWriteFailure
			var gotClose *l7PartialAssetCloseFailure
			if !errors.As(tt.err, &gotWrite) || gotWrite != writeFailure ||
				!errors.As(tt.err, &gotClose) || gotClose != closeFailure {
				t.Fatalf("translation lost a typed causal identity: %v", tt.err)
			}
			encoded, err := json.Marshal(tt.err)
			if err != nil {
				t.Fatal(err)
			}
			publicText := tt.err.Error() + " " + string(encoded) + " " + l7VisibleErrorText(tt.err)
			for _, private := range []string{writeFailure.detail, closeFailure.detail, "/host/assets/rootfs.ext4"} {
				if strings.Contains(publicText, private) {
					t.Fatalf("public error surface leaked %q: %s", private, publicText)
				}
			}
		})
	}
}

type l7PartialAssetWriteFailure struct{ detail string }

func (err *l7PartialAssetWriteFailure) Error() string { return err.detail }

type l7PartialAssetCloseFailure struct{ detail string }

func (err *l7PartialAssetCloseFailure) Error() string { return err.detail }

func l7OpenDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd) error = %v", err)
	}
	return len(entries)
}
