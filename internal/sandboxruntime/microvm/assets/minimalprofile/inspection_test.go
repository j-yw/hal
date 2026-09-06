//go:build linux && microvm_assets_integration

package minimalprofile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMinimalExt4ScanFailsClosed(t *testing.T) {
	requireImageTools(t)
	archive, pins := stagedFixture(t, nil)
	image := filepath.Join(privateDir(t), "rootfs.ext4")
	if _, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: image, Epoch: 1700000000, Pins: pins}); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"directory_incomplete", "directory_control_name", "attributes_failed", "capabilities", "content_failed", "content_incomplete", "logical_bound", "inode_bound", "symlink_spoof", "canary"} {
		t.Run(scenario, func(t *testing.T) {
			injected, readContent := false, false
			_, err := inspect(func(command string) ([]byte, error) {
				out, err := debugTool(context.Background(), 1700000000, image, "-R", command)
				if err != nil {
					return nil, err
				}
				if strings.HasPrefix(command, "cat ") {
					readContent = true
				}
				if !injected {
					switch {
					case scenario == "directory_incomplete" && strings.HasPrefix(command, "ls "):
						injected = true
						return []byte(""), nil
					case scenario == "directory_control_name" && strings.HasPrefix(command, "ls "):
						injected = true
						return append(out, []byte("/11/100644/0/0/bad\nname/1/\n")...), nil
					case scenario == "attributes_failed" && strings.HasPrefix(command, "ea_list "):
						injected = true
						return nil, errors.New("fixture failure")
					case scenario == "capabilities" && strings.HasPrefix(command, "ea_list "):
						injected = true
						return []byte("Extended attributes:\n security.capability (20)\n"), nil
					case scenario == "content_failed" && strings.HasPrefix(command, "cat "):
						injected = true
						return nil, errors.New("fixture failure")
					case scenario == "content_incomplete" && strings.HasPrefix(command, "cat ") && len(out) > 0:
						injected = true
						return out[:len(out)-1], nil
					case scenario == "logical_bound" && strings.HasPrefix(command, "ls "):
						injected = true
						return append(out, []byte("/60000/100644/0/0/oversized/536870913/\n")...), nil
					case scenario == "inode_bound" && strings.HasPrefix(command, "ls "):
						injected = true
						return append(out, []byte("/65537/100644/0/0/extra/1/\n")...), nil
					case scenario == "symlink_spoof" && strings.HasPrefix(command, "stat "):
						injected = true
						return append(out, []byte("Fast link dest: \"/bin/busybox\"\n")...), nil
					case scenario == "canary" && strings.HasPrefix(command, "cat ") && len(out) >= 14:
						injected = true
						copy(out, []byte("HAL_TESTCANARY"))
						return out, nil
					}
				}
				return out, nil
			}, pins)
			if !injected || err == nil {
				t.Fatalf("injection=%v error=%v", injected, err)
			}
			if (scenario == "logical_bound" || scenario == "inode_bound") && readContent {
				t.Fatal("content read before bounding inventory")
			}
		})
	}
}

func TestMinimalImageInputAndPublicationRaces(t *testing.T) {
	requireImageTools(t)
	archive, pins := stagedFixture(t, nil)
	digest := fileHash(t, archive)
	t.Run("nofollow source and parent", func(t *testing.T) {
		root := privateDir(t)
		link := filepath.Join(root, "input.tar")
		if err := os.Symlink(archive, link); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildImage(context.Background(), ImageRequest{Archive: link, ArchiveSHA256: digest, Output: filepath.Join(root, "out.ext4"), Epoch: 1700000000, Pins: pins}); err == nil {
			t.Fatal("symlink accepted")
		}
		parentLink := filepath.Join(root, "source")
		if err := os.Symlink(filepath.Dir(archive), parentLink); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildImage(context.Background(), ImageRequest{Archive: filepath.Join(parentLink, "rootfs.tar"), ArchiveSHA256: digest, Output: filepath.Join(root, "out.ext4"), Epoch: 1700000000, Pins: pins}); err == nil {
			t.Fatal("symlink ancestor accepted")
		}
	})
	t.Run("cancelled build", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out := filepath.Join(privateDir(t), "out.ext4")
		if _, err := BuildImage(ctx, ImageRequest{Archive: archive, ArchiveSHA256: digest, Output: out, Epoch: 1700000000, Pins: pins}); err == nil {
			t.Fatal("cancelled build accepted")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("cancelled build published")
		}
	})
	t.Run("one exact publisher", func(t *testing.T) {
		out := filepath.Join(privateDir(t), "out.ext4")
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: digest, Output: out, Epoch: 1700000000, Pins: pins})
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatalf("successful publishers=%d", success)
		}
		files, err := os.ReadDir(filepath.Dir(out))
		if err != nil || len(files) != 1 {
			t.Fatalf("partial publication leftovers: %v %v", files, err)
		}
	})
}

func TestMinimalImageReleasesPrivateScratch(t *testing.T) {
	requireImageTools(t)
	archive, pins := stagedFixture(t, nil)
	output := privateDir(t)
	scratch := privateDir(t)
	t.Setenv("TMPDIR", scratch)
	for index, valid := range []bool{true, false} {
		selected := pins
		if !valid {
			selected.InstalledPiTreeSHA256 = strings.Repeat("a", 64)
		}
		_, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: filepath.Join(output, []string{"valid.ext4", "invalid.ext4"}[index]), Epoch: 1700000000, Pins: selected})
		if (err == nil) != valid {
			t.Fatalf("valid=%v error=%v", valid, err)
		}
		entries, err := os.ReadDir(scratch)
		if err != nil || len(entries) != 0 {
			t.Fatalf("private build scratch not released: %v %v", entries, err)
		}
	}
	parent, err := openDirectory(output, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := publishFile(parent, "closed.ext4", filepath.Join(output, "valid.ext4"), fileHash(t, filepath.Join(output, "valid.ext4"))); err == nil {
		t.Fatal("closed output ownership accepted")
	}
}
