//go:build linux

package minimalprofile

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type fixtureEntry struct {
	mode       int64
	uid        int
	dir        bool
	link, data string
	declared   int64
}

func stagedFixture(t *testing.T, mutate func(map[string]fixtureEntry)) (string, Pins) {
	t.Helper()
	entries := map[string]fixtureEntry{}
	for _, name := range []string{"bin", "etc", "sbin", "usr", "usr/bin", "usr/lib", "usr/lib/pi", "usr/lib/pi/node_modules", "usr/lib/pi/node_modules/dependency", "run", "run/agent", "workspace", "tmp", "dev", "proc", "sys"} {
		entries[name] = fixtureEntry{mode: 0755, dir: true}
	}
	entries["workspace"] = fixtureEntry{mode: 0700, uid: 1000, dir: true}
	entries["run/agent"] = fixtureEntry{mode: 0700, uid: 1000, dir: true}
	entries["tmp"] = fixtureEntry{mode: 01777, dir: true}
	for _, name := range []string{"sbin/init", "sbin/hal-init", "usr/bin/hal-guest-agent", "usr/bin/node", "usr/bin/pi", "bin/busybox", "usr/bin/setpriv"} {
		entries[name] = fixtureEntry{mode: 0755, data: "safe fixture executable " + name}
	}
	for _, name := range []string{"bin/sh", "usr/bin/env", "sbin/ip", "usr/bin/nc", "bin/ping", "bin/ping6", "usr/bin/nslookup", "usr/bin/wget"} {
		entries[name] = fixtureEntry{mode: 0777, link: "/bin/busybox"}
	}
	entries["etc/resolv.conf"] = fixtureEntry{mode: 0644}
	entries["etc/passwd"] = fixtureEntry{mode: 0644, data: "root:x:0:0:root:/root:/bin/sh\nworkload:x:1000:1000:Workload:/workspace:/bin/sh\n"}
	entries["etc/group"] = fixtureEntry{mode: 0644, data: "root:x:0:\nworkload:x:1000:\n"}
	entries["etc/shadow"] = fixtureEntry{mode: 0600, data: "root:!:::::::\nworkload:!:::::::\n"}
	entries["usr/lib/pi/package.json"] = fixtureEntry{mode: 0644, data: `{"name":"@earendil-works/pi-coding-agent","version":"0.82.1"}`}
	entries["usr/lib/pi/node_modules/dependency/package.json"] = fixtureEntry{mode: 0644, data: `{"name":"dependency","version":"1.0.0"}`}
	entries["usr/lib/pi/node_modules/dependency/index.js"] = fixtureEntry{mode: 0644, data: "module.exports = 1;\n"}
	pins := Pins{GuestInitSHA256: hash([]byte(entries["sbin/hal-init"].data)), GuestAgentSHA256: hash([]byte(entries["usr/bin/hal-guest-agent"].data)), NodeSHA256: hash([]byte(entries["usr/bin/node"].data)), PiLauncherSHA256: hash([]byte(entries["usr/bin/pi"].data)), InitScriptSHA256: hash([]byte(entries["sbin/init"].data))}
	// Independent fixture inventory: the inspector must derive this from ext4.
	var tree strings.Builder
	for _, name := range sortedEntryNames(entries) {
		if strings.HasPrefix(name, "usr/lib/pi/") || name == "usr/lib/pi" {
			e := entries[name]
			kind, digest := "regular", hash([]byte(e.data))
			if e.dir {
				kind, digest = "directory", ""
			}
			if e.link != "" {
				kind, digest = "symlink", hash([]byte(e.link))
			}
			fmt.Fprintf(&tree, "%s\x00%s\x00%o\x000\x000\x00%s\n", "/"+name, kind, e.mode, digest)
		}
	}
	pins.InstalledPiTreeSHA256 = hash([]byte(tree.String()))
	if mutate != nil {
		mutate(entries)
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, name := range sortedEntryNames(entries) {
		e := entries[name]
		h := &tar.Header{Name: name, Mode: e.mode, Uid: e.uid, Gid: e.uid, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
		if e.dir {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if e.link != "" {
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.link, 0
		}
		if e.declared > 0 {
			h.Size = e.declared
		}
		if err := writer.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.declared > 0 {
			break
		}
		if _, err := writer.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	_ = writer.Close()
	name := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(name, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return name, pins
}

func sortedEntryNames(entries map[string]fixtureEntry) []string {
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fileHash(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return hash(data)
}
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
