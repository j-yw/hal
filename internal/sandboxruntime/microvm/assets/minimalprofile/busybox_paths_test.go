//go:build linux

package minimalprofile

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalBusyboxIndependentGIDAndDuplicate(t *testing.T) {
	for _, scenario := range []string{"gid", "duplicate_tar", "duplicate_inode_record"} {
		t.Run(scenario, func(t *testing.T) {
			archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
				entries["usr/bin/["] = fixtureEntry{mode: 0777, link: "../../bin/busybox"}
			})
			if scenario != "duplicate_inode_record" {
				data, err := os.ReadFile(archive)
				if err != nil {
					t.Fatal(err)
				}
				r := tar.NewReader(bytes.NewReader(data))
				var rewritten bytes.Buffer
				w := tar.NewWriter(&rewritten)
				changed := false
				for {
					h, err := r.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(r)
					if err != nil {
						t.Fatal(err)
					}
					if h.Name == "usr/bin/[" && scenario == "gid" {
						h.Gid = 1000
						changed = true
					}
					if err := w.WriteHeader(h); err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write(body); err != nil {
						t.Fatal(err)
					}
					if h.Name == "usr/bin/[" && scenario == "duplicate_tar" {
						if err := w.WriteHeader(h); err != nil {
							t.Fatal(err)
						}
						changed = true
					}
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				if !changed {
					t.Fatal("negative tuple not installed")
				}
				archive = filepath.Join(privateDir(t), "negative.tar")
				if err := os.WriteFile(archive, rewritten.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				t.Run("extract", func(t *testing.T) {
					if _, _, err := extractStage(archive, privateDir(t), 1700000000); err == nil {
						t.Fatal("unsafe applet archive admitted")
					}
				})
			}
			if scenario == "duplicate_tar" {
				return
			} // Tar duplicates are not inode transcript properties.
			t.Run("inspect", func(t *testing.T) {
				transcript := fakeTranscript(t, archive)
				injected := false
				_, err := inspect(func(command string) ([]byte, error) {
					out, ok := transcript[command]
					if !ok {
						return nil, errors.New("unexpected fixture query")
					}
					if scenario == "duplicate_inode_record" && strings.HasPrefix(command, "ls ") {
						for _, line := range strings.Split(string(out), "\n") {
							if strings.Contains(line, "/[/") {
								out = append(append([]byte(nil), out...), []byte(line+"\n")...)
								injected = true
								break
							}
						}
					}
					return out, nil
				}, pins)
				if err == nil {
					t.Fatal("unsafe applet inode admitted")
				}
				if scenario == "duplicate_inode_record" && !injected {
					t.Fatal("duplicate inode listing not reached")
				}
			})
		})
	}
}

func TestMinimalBusyboxPaths(t *testing.T) {
	for _, applet := range []string{"[", "[["} {
		for _, scenario := range []string{"baseline", "valid", "both", "wrong_location", "suffix", "space", "newline", "semicolon", "wrong_target", "escaping_target", "target_newline", "regular", "directory", "wrong_mode", "wrong_uid", "symlink_parent"} {
			t.Run(applet+"/"+scenario, func(t *testing.T) {
				archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
					if scenario == "baseline" {
						return
					}
					name := "usr/bin/" + applet
					e := fixtureEntry{mode: 0777, link: "../../bin/busybox"}
					switch scenario {
					case "both":
						entries["usr/bin/["] = e
						entries["usr/bin/[["] = e
					case "wrong_location":
						name = "usr/lib/" + applet
					case "suffix":
						name += "x"
					case "space":
						name += " x"
					case "newline":
						name += "\ninjected"
					case "semicolon":
						name += ";x"
					case "wrong_target":
						e.link = "../../bin/notbusybox"
						entries["bin/notbusybox"] = fixtureEntry{mode: 0755, data: "different executable"}
					case "escaping_target":
						e.link = "../../../outside"
					case "target_newline":
						e.link += "\ninjected"
					case "regular":
						e = fixtureEntry{mode: 0755, data: "not the BusyBox applet"}
					case "directory":
						e = fixtureEntry{mode: 0755, dir: true}
					case "wrong_mode":
						e.mode = 0755
					case "wrong_uid":
						e.uid = 1000
					case "symlink_parent":
						entries["usr/bin"] = fixtureEntry{mode: 0777, link: "../lib"}
					}
					entries[name] = e
				})
				wantOK := scenario == "baseline" || scenario == "valid" || scenario == "both"
				// Independent subtests: extraction rejection cannot conceal the
				// distinct inode-parser rejection or stand in for its validation.
				t.Run("extract", func(t *testing.T) {
					root := privateDir(t)
					_, _, err := extractStage(archive, root, 1700000000)
					if (err == nil) != wantOK {
						t.Fatalf("actual extractor acceptance=%v, want=%v: %v", err == nil, wantOK, err)
					}
					if wantOK && scenario != "baseline" {
						link, err := os.Readlink(filepath.Join(root, "usr/bin", applet))
						if err != nil || link != "../../bin/busybox" {
							t.Fatal("actual extracted applet changed", err)
						}
					}
				})
				t.Run("inspect", func(t *testing.T) {
					transcript := fakeTranscript(t, archive)
					calls := 0
					result, err := inspect(func(command string) ([]byte, error) {
						calls++
						// Production inspection must remain numeric-inode only.
						if strings.ContainsAny(command, "[/;\n\r\t") {
							t.Fatalf("untrusted path entered inspector command: %q", command)
						}
						out, ok := transcript[command]
						if !ok {
							return nil, errors.New("unexpected fixture query")
						}
						return out, nil
					}, pins)
					if calls == 0 {
						t.Fatal("actual inspector not reached")
					}
					if (err == nil) != wantOK {
						t.Fatalf("actual inspector acceptance=%v, want=%v: %v", err == nil, wantOK, err)
					}
					if wantOK && (len(result.Executables) != 4 || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 || result.Inventory.Findings == nil) {
						t.Fatal("measurement lost unchanged pins/inventory")
					}
				})
			})
		}
	}
}

func TestMinimalBusyboxArchivePathNormalization(t *testing.T) {
	// Archive syntax is not an ext4 directory-record property. Exercise it at
	// extraction rather than pretending a normalized fake inode transcript can
	// retain the original unsafe tar spelling.
	for _, name := range []string{"usr/bin/../bin/[", "usr//bin/[", "./usr/bin/[", "/usr/bin/[", "usr/bin/[/child", "usr/bin/[x]", "usr/bin/$(x)", "usr/bin/`x`", "usr/bin/[\t", "usr/bin/[\r"} {
		t.Run(name, func(t *testing.T) {
			archive, _ := stagedFixture(t, func(entries map[string]fixtureEntry) {
				entries[name] = fixtureEntry{mode: 0777, link: "../../bin/busybox"}
			})
			if _, _, err := extractStage(archive, privateDir(t), 1700000000); err == nil {
				t.Fatal("unsafe path spelling admitted")
			}
		})
	}
}

func TestMinimalBusyboxPublicNamesRemainRestricted(t *testing.T) {
	for _, name := range []string{"[", "[[", "usr/bin/[", "usr/bin/[[", "request[.json", "image[[.ext4"} {
		if safeLeaf(name) || safeName.MatchString(name) {
			t.Fatalf("unrelated name alphabet expanded: %q", name)
		}
	}
	for _, target := range []string{"../../usr/bin/[", "/usr/bin/[[", "../../bin/busybox\ninjected"} {
		if safeLink("/usr/bin/example", target) {
			t.Fatalf("generic link target expanded: %q", target)
		}
	}
	for _, location := range []string{"/usr/bin/[", "/usr/bin/[["} {
		passwd := []byte("root:x:0:0:root:" + location + ":/bin/sh\nworkload:x:1000:1000:Workload:/workspace:/bin/sh\n")
		if validLockedAccounts(passwd, []byte("root:x:0:\nworkload:x:1000:\n"), []byte("root:!:::::::\nworkload:!:::::::\n")) {
			t.Fatal("account-location vocabulary expanded")
		}
	}
}
