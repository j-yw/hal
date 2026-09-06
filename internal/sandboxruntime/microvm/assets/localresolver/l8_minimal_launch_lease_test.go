package localresolver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestL8MinimalLaunchTransferOwnsFilesAndExpiresViews(t *testing.T) {
	request := minimalDistributionFixture(t)
	verified, err := VerifyL8MinimalDistributionBundle(request)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	files := minimalLaunchRetainedFiles(verified)
	alias := verified
	lease, err := verified.TakeLaunchLease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if _, err := file.Stat(); err != nil {
			t.Fatal("distribution alias closed transferred descriptor")
		}
	}
	if _, err := SelectL8MinimalDistribution(alias); err == nil {
		t.Fatal("transferred distribution remained selectable")
	}
	if _, err := alias.TakeLaunchLease(context.Background()); err == nil {
		t.Fatal("second transfer accepted")
	}
	if _, err := json.Marshal(lease); err == nil {
		t.Fatal("launch ownership serialized")
	}
	var escaped io.ReadSeeker
	err = lease.WithAssets(context.Background(), func(kernel, rootfs L8MinimalLaunchAsset) error {
		for _, asset := range []L8MinimalLaunchAsset{kernel, rootfs} {
			payload, err := io.ReadAll(asset.Source)
			if err != nil || int64(len(payload)) != asset.SizeBytes || l5SHA256(payload) != asset.SHA256 {
				t.Fatalf("borrowed measurement changed: %v", err)
			}
			if _, ok := asset.Source.(*os.File); ok {
				t.Fatal("borrow exposed file descriptor")
			}
		}
		escaped = kernel.Source
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.Seek(0, io.SeekStart); err == nil {
		t.Fatal("escaped reader retained seek access")
	}
	if _, err := escaped.Read(make([]byte, 1)); err == nil {
		t.Fatal("escaped reader retained byte access")
	}
	if err := lease.ConfirmCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if _, err := file.Stat(); err == nil {
			t.Fatal("transferred descriptor leaked")
		}
	}
	if err := lease.ConfirmCurrent(context.Background()); err == nil {
		t.Fatal("closed lease remained current")
	}
}

func TestL8MinimalLaunchRejectsChangedEvidence(t *testing.T) {
	for _, phase := range []string{"before_transfer", "during_borrow", "before_launch"} {
		for _, name := range []string{"vmlinux", "rootfs.ext4", "provenance.json", "parent_rootfs", "parent_metadata", "root_directory", "in_place", "symlink"} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				request := minimalDistributionFixture(t)
				verified, err := VerifyL8MinimalDistributionBundle(request)
				if err != nil {
					t.Fatal(err)
				}
				defer verified.Close()
				mutate := func() { minimalLaunchMutate(t, request, name) }
				if phase == "before_transfer" {
					mutate()
				}
				lease, err := verified.TakeLaunchLease(context.Background())
				if phase == "before_transfer" {
					if err == nil {
						lease.Close()
						t.Fatal("changed evidence transferred")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				if phase == "during_borrow" {
					err = lease.WithAssets(context.Background(), func(kernel, rootfs L8MinimalLaunchAsset) error { mutate(); return nil })
				} else {
					mutate()
					err = lease.ConfirmCurrent(context.Background())
				}
				if err == nil {
					t.Fatal("changed evidence remained usable")
				}
			})
		}
	}
}

func TestL8MinimalLaunchCancellationAndCallbackFailure(t *testing.T) {
	for _, phase := range []string{"take", "borrow", "read", "callback_error", "callback_panic"} {
		t.Run(phase, func(t *testing.T) {
			request := minimalDistributionFixture(t)
			verified, err := VerifyL8MinimalDistributionBundle(request)
			if err != nil {
				t.Fatal(err)
			}
			defer verified.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "take" {
				cancel()
			}
			lease, err := verified.TakeLaunchLease(ctx)
			if phase == "take" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled transfer = %v", err)
				}
				if _, err := SelectL8MinimalDistribution(verified); err != nil {
					t.Fatal("failed transfer consumed distribution")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			if phase == "borrow" {
				cancel()
			}
			var escaped io.ReadSeeker
			called := false
			func() {
				defer func() {
					if got := recover(); phase == "callback_panic" && got != "injected" {
						t.Fatalf("panic = %v", got)
					}
				}()
				err = lease.WithAssets(ctx, func(kernel, rootfs L8MinimalLaunchAsset) error {
					called, escaped = true, rootfs.Source
					if phase == "callback_panic" {
						panic("injected")
					}
					if phase == "callback_error" {
						return errors.New("private callback failure")
					}
					cancel()
					if _, err := rootfs.Source.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled read = %v", err)
					}
					return nil
				})
			}()
			if phase != "callback_panic" && err == nil {
				t.Fatal("failed/canceled callback accepted")
			}
			if phase == "borrow" && called {
				t.Fatal("pre-canceled callback ran")
			}
			if escaped != nil {
				if _, err := escaped.Read(make([]byte, 1)); err == nil {
					t.Fatal("callback retained bytes after failure")
				}
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestL8MinimalLaunchConcurrentTransferAndClose(t *testing.T) {
	for range 8 {
		verified, err := VerifyL8MinimalDistributionBundle(minimalDistributionFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		files := minimalLaunchRetainedFiles(verified)
		start := make(chan struct{})
		leases := make(chan *VerifiedL8MinimalLaunchLease, 4)
		var workers sync.WaitGroup
		for range 4 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				if lease, err := verified.TakeLaunchLease(context.Background()); err == nil {
					leases <- lease
				}
			}()
		}
		workers.Add(1)
		go func() { defer workers.Done(); <-start; _ = verified.Close() }()
		close(start)
		workers.Wait()
		close(leases)
		if len(leases) > 1 {
			t.Fatal("multiple owners accepted")
		}
		for lease := range leases {
			if err := lease.ConfirmCurrent(context.Background()); err != nil {
				t.Fatal("alias close invalidated accepted owner")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for _, file := range files {
			if _, err := file.Stat(); err == nil {
				t.Fatal("concurrent ownership leaked a descriptor")
			}
		}
	}
}

func minimalLaunchRetainedFiles(verified VerifiedL8MinimalDistribution) []*os.File {
	state := verified.state
	files := []*os.File{state.root, state.parentLease.root, state.parentLease.kernel, state.parentLease.rootfs}
	for _, set := range []map[string]l8PinnedAsset{state.files, state.parentMetadata} {
		for _, pinned := range set {
			files = append(files, pinned.file)
		}
	}
	return files
}

func minimalLaunchMutate(t *testing.T, request L8MinimalDistributionRequest, name string) {
	t.Helper()
	root := request.RootDir
	if name == "parent_rootfs" {
		root, name = request.ParentL7.rootDir, "rootfs.ext4"
	}
	if name == "parent_metadata" {
		root, name = request.ParentL7.rootDir, "provenance.json"
	}
	if name == "root_directory" {
		if err := os.Rename(root, filepath.Join(t.TempDir(), "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		return
	}
	if name == "in_place" {
		if err := os.WriteFile(filepath.Join(root, "rootfs.ext4"), []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	symlink := name == "symlink"
	if symlink {
		name = "rootfs.ext4"
	}
	path := filepath.Join(root, name)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(t.TempDir(), "original")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if symlink {
		if err := os.Symlink(moved, path); err != nil {
			t.Fatal(err)
		}
		return
	}
	// Byte-identical replacement must fail inode correlation too.
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
}
