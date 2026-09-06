//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStrictJailerMinimalLinuxFDStagingAndReadback(t *testing.T) {
	for _, scenario := range []string{"success", "same_inode_source_restore", "staged_readback_corruption"} {
		t.Run(scenario, func(t *testing.T) {
			verified, source, kernel, rootfs := minimalJailerFixture(t)
			staging, _ := newLinuxJailerStagingRequest(t)
			request := minimalJailerTestRequest(t)
			request.inspection.chrootBaseDir = staging.Authority.ChrootBaseDir
			request.inspection.runtimeUID, request.inspection.runtimeGID = staging.Authority.UID, staging.Authority.GID
			events := []string{}
			lifecycle := &coordinatorFakeLifecycle{events: &events}
			coordinator := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, lifecycle)
			coordinator.deps.inspect = func(input strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
				return strictJailerHostInspectionResult{canonicalJailerPath: input.jailerPath, canonicalFirecrackerPath: input.firecrackerPath, runtimeUID: input.runtimeUID, runtimeGID: input.runtimeGID, canonicalChrootBaseDir: input.chrootBaseDir}, nil
			}
			coordinator.deps.newFilesystem = func(authority jailerStagingAuthority) (jailerStagingFilesystem, error) {
				fs, err := newLinuxJailerStagingFilesystem(authority)
				if err == nil && scenario == "staged_readback_corruption" {
					fs = &minimalCorruptReadbackFS{jailerStagingFilesystem: fs}
				}
				return fs, err
			}
			coordinator.deps.stage = func(fs jailerStagingFilesystem, input jailerStagingRequest) (jailerStagingResult, error) {
				path := filepath.Join(source, "rootfs.ext4")
				if scenario == "same_inode_source_restore" {
					if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(rootfs)), 0600); err != nil {
						t.Fatal(err)
					}
				}
				result, err := stageStrictJailerResources(fs, input)
				if scenario == "same_inode_source_restore" {
					if err := os.WriteFile(path, rootfs, 0600); err != nil {
						t.Fatal(err)
					}
				}
				return result, err
			}
			checked := false
			coordinator.deps.plan = func(input strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
				for name, want := range map[string][]byte{"boot/vmlinux": kernel, "images/rootfs.ext4": rootfs} {
					path := filepath.Join(request.inspection.chrootBaseDir, "firecracker", request.runtimeID, "root", filepath.FromSlash(name))
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, want) || sha256Hex(got) != sha256Hex(want) {
						t.Fatalf("actual FD-staged bytes differ for %s: %v", name, err)
					}
				}
				checked = true
				return strictJailerLaunchPlan{hostPaths: input.HostPaths}, nil
			}
			session, err := coordinator.startMinimal(context.Background(), request, verified)
			if scenario == "success" {
				if err != nil || !checked || !slices.Contains(events, "start") {
					t.Fatalf("actual staging handoff failed: %v %v", err, events)
				}
				if err := coordinator.stop(context.Background(), session); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || checked || slices.Contains(events, "start") {
				t.Fatalf("corruption reached process: %v %v", err, events)
			}
			root := filepath.Join(request.inspection.chrootBaseDir, "firecracker", request.runtimeID)
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("actual owned root remained: %v", err)
			}
		})
	}
}

type minimalCorruptReadbackFS struct{ jailerStagingFilesystem }

func (fs *minimalCorruptReadbackFS) createExclusiveRoot(request jailerStagingRootRequest) (jailerStagingRoot, error) {
	root, err := fs.jailerStagingFilesystem.createExclusiveRoot(request)
	if err != nil {
		return root, err
	}
	return &minimalCorruptReadbackRoot{jailerStagingRoot: root}, nil
}

type minimalCorruptReadbackRoot struct{ jailerStagingRoot }

func (root *minimalCorruptReadbackRoot) createFileExclusive(relative string) (jailerStagingFile, error) {
	file, err := root.jailerStagingRoot.createFileExclusive(relative)
	if err == nil && relative == "images/rootfs.ext4" {
		return &minimalCorruptReadbackFile{jailerStagingFile: file}, nil
	}
	return file, err
}

type minimalCorruptReadbackFile struct {
	jailerStagingFile
	corrupted bool
}

func (file *minimalCorruptReadbackFile) sync() error {
	if !file.corrupted {
		// The copy hash already consumed correct source bytes. Corrupt the real
		// retained destination FD before sync/readback; its readback hash must fail.
		file.corrupted = true
		if _, err := unix.Pwrite(file.jailerStagingFile.(*linuxJailerStagingFile).fd, []byte("x"), 0); err != nil {
			return err
		}
	}
	return file.jailerStagingFile.sync()
}
