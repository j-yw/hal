//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalArchiveMeasuresAndRejectsUnsafeOutput(t *testing.T) {
	for _, scenario := range []string{"valid", "long_package_name", "missing_executable", "traversal", "duplicate", "symlink_parent", "foreign_uid", "setuid", "trailing", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil {
				t.Fatal("chmod")
			}
			var raw bytes.Buffer
			writer := tar.NewWriter(&raw)
			write := func(name string, kind byte, mode int64, uid int, data string, link string) {
				t.Helper()
				h := &tar.Header{Name: name, Typeflag: kind, Mode: mode, Uid: uid, Gid: uid, Linkname: link}
				if kind == tar.TypeReg {
					h.Size = int64(len(data))
				}
				if writer.WriteHeader(h) != nil {
					t.Fatal("header")
				}
				if kind == tar.TypeReg {
					if _, err := writer.Write([]byte(data)); err != nil {
						t.Fatal(err)
					}
				}
			}
			write("./", tar.TypeDir, 0755, 0, "", "")
			for _, name := range []string{"sbin", "usr", "usr/bin", "usr/lib", "usr/lib/pi"} {
				if scenario == "symlink_parent" && name == "usr/lib/pi" {
					write("./"+name, tar.TypeSymlink, 0777, 0, "", "/tmp")
				} else {
					write("./"+name, tar.TypeDir, 0755, 0, "", "")
				}
			}
			for _, name := range []string{"sbin/init", "sbin/hal-init", "usr/bin/hal-guest-agent", "usr/bin/node", "usr/bin/pi"} {
				if scenario == "missing_executable" && name == "usr/bin/node" {
					continue
				}
				mode := int64(0755)
				uid := 0
				if scenario == "setuid" && name == "usr/bin/node" {
					mode = 04755
				}
				if scenario == "foreign_uid" && name == "usr/bin/node" {
					uid = 1000
				}
				write("./"+name, tar.TypeReg, mode, uid, "fixture executable\n", "")
			}
			write("./usr/lib/pi/package.json", tar.TypeReg, 0644, 0, "fixture package\n", "")
			if scenario == "long_package_name" {
				write("./usr/lib/pi/"+strings.Repeat("a", 120)+".js", tar.TypeReg, 0644, 0, "long pinned package name\n", "")
			}
			if scenario == "duplicate" {
				write("./usr/lib/pi/package.json", tar.TypeReg, 0644, 0, "duplicate\n", "")
			}
			if scenario == "traversal" {
				write("./usr/lib/pi/../escape", tar.TypeReg, 0644, 0, "escape\n", "")
			}
			if writer.Close() != nil {
				t.Fatal("close")
			}
			if scenario == "trailing" {
				raw.WriteString("unvalidated second payload")
			}
			input, output := filepath.Join(root, "input.tar"), filepath.Join(root, "output.tar")
			if os.WriteFile(input, raw.Bytes(), 0600) != nil {
				t.Fatal("write")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			actual, pins, err := canonicalize(ctx, input, output, 1700000000)
			if scenario != "valid" && scenario != "long_package_name" {
				if err == nil {
					t.Fatal("unsafe builder output admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if actual != digest(data) || pins.NodeSHA256 != digest([]byte("fixture executable\n")) {
				t.Fatal("measurement not bound to actual bytes")
			}
			r := tar.NewReader(bytes.NewReader(data))
			seen := 0
			for {
				h, err := r.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if h.Name == "." || h.Name == "./" || h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 1700000000 || len(h.PAXRecords) != 0 {
					t.Fatal("noncanonical output")
				}
				seen++
			}
			want := 11
			if scenario == "long_package_name" {
				want++
			}
			if seen != want {
				t.Fatalf("canonical count %d", seen)
			}
		})
	}
}
