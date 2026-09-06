//go:build linux

package minimalprofile

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalFakeInspector(t *testing.T) {
	for _, scenario := range []string{"valid", "missing_tree_pin", "tree_tamper", "role_tamper", "credentials", "private_key", "privilege", "wrong_workspace_uid", "untraversable_parent", "missing_agent", "incomplete_directory", "capabilities", "incomplete_content", "logical_bound", "symlink_spoof"} {
		t.Run(scenario, func(t *testing.T) {
			archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
				switch scenario {
				case "credentials":
					entries["etc/.npmrc"] = fixtureEntry{mode: 0600, data: "fixture token"}
				case "private_key":
					entries["etc/innocent"] = fixtureEntry{mode: 0600, data: "-----BEGIN OPENSSH PRIVATE KEY-----"}
				case "privilege":
					e := entries["usr/bin/node"]
					e.mode = 04755
					entries["usr/bin/node"] = e
				case "wrong_workspace_uid":
					e := entries["workspace"]
					e.uid = 998
					entries["workspace"] = e
				case "untraversable_parent":
					e := entries["usr"]
					e.mode = 0700
					entries["usr"] = e
				case "missing_agent":
					delete(entries, "usr/bin/hal-guest-agent")
				}
			})
			transcript := fakeTranscript(t, archive)
			switch scenario {
			case "missing_tree_pin":
				pins.InstalledPiTreeSHA256 = ""
			case "tree_tamper":
				pins.InstalledPiTreeSHA256 = strings.Repeat("a", 64)
			case "role_tamper":
				pins.NodeSHA256 = strings.Repeat("a", 64)
			case "incomplete_directory":
				transcript["ls -p -r <2>"] = nil
			case "logical_bound":
				transcript["ls -p -r <2>"] = append(transcript["ls -p -r <2>"], []byte("/60000/100644/0/0/oversized/536870913/\n")...)
			}
			injected, readContent := false, false
			result, err := inspect(func(command string) ([]byte, error) {
				out, ok := transcript[command]
				if !ok {
					return nil, errors.New("missing fake response")
				}
				if strings.HasPrefix(command, "cat ") {
					readContent = true
				}
				if !injected {
					switch {
					case scenario == "capabilities" && strings.HasPrefix(command, "ea_list "):
						injected = true
						return []byte("security.capability"), nil
					case scenario == "incomplete_content" && strings.HasPrefix(command, "cat ") && len(out) > 0:
						injected = true
						return out[:len(out)-1], nil
					case scenario == "symlink_spoof" && strings.HasPrefix(command, "stat "):
						injected = true
						return append(append([]byte(nil), out...), out...), nil
					}
				}
				return out, nil
			}, pins)
			if scenario == "valid" {
				if err != nil || len(result.Executables) != 4 || result.Inventory.Inodes < 15 || result.Inventory.Findings == nil || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 {
					t.Fatalf("fake measurement=%+v error=%v", result, err)
				}
			} else if err == nil {
				t.Fatal("unsafe fake image accepted")
			}
			if scenario == "logical_bound" && readContent {
				t.Fatal("content read before bounded inventory")
			}
		})
	}
}

func TestMinimalArchiveValidationWithoutTools(t *testing.T) {
	for _, scenario := range []string{"valid", "traversal", "symlink_parent", "privilege", "wrong_uid", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			archive, _ := stagedFixture(t, func(entries map[string]fixtureEntry) {
				switch scenario {
				case "traversal":
					entries["../escape"] = fixtureEntry{mode: 0600, data: "fixture"}
				case "symlink_parent":
					entries["usr"] = fixtureEntry{mode: 0777, link: "/tmp"}
				case "privilege":
					entries["usr/bin/node"] = fixtureEntry{mode: 04755, data: "fixture"}
				case "wrong_uid":
					entries["usr/bin/node"] = fixtureEntry{mode: 0755, uid: 1000, data: "fixture"}
				case "oversize":
					entries["large"] = fixtureEntry{mode: 0600, declared: 513 << 20}
				}
			})
			_, _, err := extractStage(archive, privateDir(t), 1700000000)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("scenario=%s error=%v", scenario, err)
			}
		})
	}
}

func TestMinimalPinnedRequestAndReceiptWithoutTools(t *testing.T) {
	dir := privateDir(t)
	name := filepath.Join(dir, "request.json")
	data := []byte(`{"SourceRevision":"fixture"}`)
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	request, err := ReadPublishRequest(name, hash(data))
	if err != nil || request.SourceRevision != "fixture" {
		t.Fatalf("request=%+v error=%v", request, err)
	}
	if err := os.WriteFile(name, []byte(`{"SourceRevision":"changed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishRequest(name, hash(data)); err == nil {
		t.Fatal("changed request accepted")
	}
	receipt := Receipt{ArchiveSHA256: hash(data), InstalledPiTreeSHA256: hash([]byte("independent tree"))}
	receipt.Expected.SourceRevision = "trusted-source"
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Receipt
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != receipt {
		t.Fatalf("receipt lost independent identity: %v", err)
	}
	if strings.Contains(string(encoded), dir) {
		t.Fatal("receipt exposed source directory")
	}
}

// The fake transcript derives only from test tar bytes; no command runs and no
// version probe occurs. Production inspection still consumes the same parser.
func fakeTranscript(t *testing.T, archive string) map[string][]byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := tar.NewReader(f)
	type entry struct {
		header tar.Header
		inode  int
		data   []byte
	}
	entries := map[string]entry{"/": {header: tar.Header{Mode: 0755, Typeflag: tar.TypeDir}, inode: 2}}
	for inode := 3; ; inode++ {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		entries["/"+h.Name] = entry{*h, inode, data}
	}
	record := func(name string, e entry) string {
		mode := int64(0100000) | e.header.Mode
		size := fmt.Sprint(len(e.data))
		if e.header.Typeflag == tar.TypeDir {
			mode = 0040000 | e.header.Mode
			size = ""
		}
		if e.header.Typeflag == tar.TypeSymlink {
			mode = 0120000 | e.header.Mode
			size = fmt.Sprint(len(e.header.Linkname))
		}
		return fmt.Sprintf("/%d/%06o/%d/%d/%s/%s/\n", e.inode, mode, e.header.Uid, e.header.Gid, name, size)
	}
	out := map[string][]byte{}
	for name, e := range entries {
		out[fmt.Sprintf("ea_list <%d>", e.inode)] = nil
		switch e.header.Typeflag {
		case tar.TypeDir:
			listing := record(".", e) + record("..", entries[path.Dir(name)])
			for _, child := range sortedKeys(entries) {
				if child != "/" && path.Dir(child) == name {
					listing += record(path.Base(child), entries[child])
				}
			}
			out[fmt.Sprintf("ls -p -r <%d>", e.inode)] = []byte(listing)
		case tar.TypeReg:
			out[fmt.Sprintf("cat <%d>", e.inode)] = e.data
		case tar.TypeSymlink:
			out[fmt.Sprintf("stat <%d>", e.inode)] = []byte(fmt.Sprintf("Fast link dest: %q\n", e.header.Linkname))
		}
	}
	return out
}
