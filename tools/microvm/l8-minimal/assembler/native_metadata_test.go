//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const framebufferRow = "/dev/fb c 640 0 5 29 0 0 1 4"

func nativeMetadataRows(t *testing.T, filename string) []string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) != 10 {
			t.Fatalf("invalid device-table fixture row: %q", line)
		}
		rows = append(rows, strings.Join(f, " "))
	}
	return rows
}

func nativeMetadataSelectedRows(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../buildroot.config")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\nBR2_ROOTFS_DEVICE_CREATION_STATIC=y\n") ||
		!strings.Contains(string(data), "\nBR2_ROOTFS_DEVICE_TABLE=\"system/device_table.txt /src/tools/microvm/l8-minimal/permissions.txt\"\n") {
		t.Fatal("selected static mode or permission-table order changed")
	}
	const key = "BR2_ROOTFS_STATIC_DEVICE_TABLE="
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, key) {
			continue
		}
		name, err := strconv.Unquote(strings.TrimPrefix(line, key))
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "system/device_table_dev.txt":
			// The actual RED config selects this exact pinned upstream table.
			// Resolve only that known path to deterministic recorded source rows;
			// no live cache dependency or missing future file is the failure.
			return nativeMetadataRows(t, "testdata/buildroot-2026.05.1-static-devices.txt")
		case "/src/tools/microvm/l8-minimal/static-devices.txt":
			return nativeMetadataRows(t, "../static-devices.txt")
		default:
			t.Fatalf("unexpected selected device table: %q", name)
		}
	}
	t.Fatal("selected device table missing")
	return nil
}

func TestNativeMetadataRecipeStaticRows(t *testing.T) {
	upstream := nativeMetadataRows(t, "testdata/buildroot-2026.05.1-static-devices.txt")
	var expected []string
	for _, row := range upstream {
		if row != framebufferRow {
			expected = append(expected, row)
		}
	}
	if len(upstream) != 52 || len(expected) != 51 {
		t.Fatal("pinned upstream fixture drift")
	}
	if actual := nativeMetadataSelectedRows(t); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("selected static table must preserve all 51 other rows and omit only framebuffer expansion; got %d rows", len(actual))
	}
}

func TestCanonicalNativeRecipeMetadata(t *testing.T) {
	for _, scenario := range []string{"baseline", "framebuffer_recipe", "web_recipe", "combined_recipe", "raw_web_owner", "raw_fb0", "raw_fb1", "raw_fb2", "raw_fb3", "foreign_device_owner"} {
		t.Run(scenario, func(t *testing.T) {
			wantOK := !strings.HasPrefix(scenario, "raw_") && scenario != "foreign_device_owner"
			nativeMetadataCanonical(t, wantOK, func(headers map[string]tar.Header) {
				if scenario == "framebuffer_recipe" || scenario == "combined_recipe" {
					for _, row := range nativeMetadataSelectedRows(t) {
						if row != framebufferRow {
							continue
						}
						// Exactly the four observed makedevs results, not real host devices.
						for n := 0; n < 4; n++ {
							headers[fmt.Sprintf("dev/fb%d", n)] = tar.Header{Typeflag: tar.TypeChar, Mode: 0640, Gid: 5, Devmajor: 29, Devminor: int64(n)}
						}
					}
				}
				if scenario == "web_recipe" || scenario == "combined_recipe" || scenario == "raw_web_owner" {
					h := tar.Header{Typeflag: tar.TypeDir, Mode: 0755, Uid: 33, Gid: 33}
					if scenario != "raw_web_owner" {
						_ = nativeMetadataSelectedRows(t) // Verify the actual last-table ordering.
						for _, row := range nativeMetadataRows(t, "../permissions.txt") {
							f := strings.Fields(row)
							if f[0] != "/var/www" {
								continue
							}
							if f[1] != "d" || strings.Join(f[5:], " ") != "- - - - -" {
								t.Fatal("unexpected web ownership rule")
							}
							mode, err := strconv.ParseInt(f[2], 8, 64)
							if err != nil {
								t.Fatal(err)
							}
							h.Mode = mode
							h.Uid, err = strconv.Atoi(f[3])
							if err != nil {
								t.Fatal(err)
							}
							h.Gid, err = strconv.Atoi(f[4])
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					headers["var/www"] = h
				}
				if strings.HasPrefix(scenario, "raw_fb") {
					headers["dev/"+strings.TrimPrefix(scenario, "raw_")] = tar.Header{Typeflag: tar.TypeChar, Mode: 0640, Gid: 5, Devmajor: 29, Devminor: int64(scenario[len(scenario)-1] - '0')}
				}
				if scenario == "foreign_device_owner" {
					headers["dev/unexpected"] = tar.Header{Typeflag: tar.TypeChar, Mode: 0640, Uid: 77, Gid: 77}
				}
				if scenario == "combined_recipe" {
					for _, name := range []string{"usr/bin/[", "usr/bin/[["} {
						headers[name] = tar.Header{Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "../../bin/busybox"}
					}
				}
			})
		})
	}
}

func TestCanonicalNativeBusyboxPaths(t *testing.T) {
	for _, name := range []string{"usr/bin/[", "usr/bin/[["} {
		for _, scenario := range []string{"valid", "duplicate", "wrong_location", "suffix", "traversal", "space", "newline", "semicolon", "wrong_target", "escaping_target", "target_newline", "regular", "directory", "wrong_mode", "wrong_uid", "wrong_gid", "symlink_parent"} {
			t.Run(name+"/"+scenario, func(t *testing.T) {
				var duplicates []string
				if scenario == "duplicate" {
					duplicates = []string{name}
				}
				nativeMetadataCanonical(t, scenario == "valid", func(headers map[string]tar.Header) {
					path := name
					h := tar.Header{Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "../../bin/busybox"}
					switch scenario {
					case "wrong_location":
						path = strings.Replace(name, "usr/bin/", "usr/lib/", 1)
					case "suffix":
						path += "x"
					case "traversal":
						path = "usr/bin/../bin/" + strings.TrimPrefix(name, "usr/bin/")
					case "space":
						path += " x"
					case "newline":
						path += "\nset_inode_field /bin/busybox mode 35309"
					case "semicolon":
						path += ";x"
					case "wrong_target":
						h.Linkname = "../../bin/notbusybox"
					case "escaping_target":
						h.Linkname = "../../../outside"
					case "target_newline":
						h.Linkname += "\ninjected"
					case "regular":
						h.Typeflag, h.Linkname, h.Mode = tar.TypeReg, "", 0755
					case "directory":
						h.Typeflag, h.Linkname, h.Mode = tar.TypeDir, "", 0755
					case "wrong_mode":
						h.Mode = 0755
					case "wrong_uid":
						h.Uid = 1000
					case "wrong_gid":
						h.Gid = 1000
					case "symlink_parent":
						headers["usr/bin"] = tar.Header{Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "../lib"}
					}
					headers[path] = h
				}, duplicates...)
			})
		}
	}
}

// A small Buildroot-shaped candidate drives the real canonicalizer. No package,
// fakeroot, container, external image tool or device creation is executed.
func nativeMetadataCanonical(t *testing.T, wantOK bool, mutate func(map[string]tar.Header), duplicates ...string) {
	t.Helper()
	headers := map[string]tar.Header{}
	for _, name := range []string{"bin", "dev", "sbin", "usr", "usr/bin", "usr/lib", "usr/lib/pi", "run", "var", "workspace"} {
		headers[name] = tar.Header{Typeflag: tar.TypeDir, Mode: 0755}
	}
	headers["workspace"] = tar.Header{Typeflag: tar.TypeDir, Mode: 0700, Uid: 1000, Gid: 1000}
	for _, name := range []string{"bin/busybox", "bin/notbusybox", "sbin/init", "sbin/hal-init", "usr/bin/hal-guest-agent", "usr/bin/node", "usr/bin/pi", "usr/lib/pi/package.json"} {
		headers[name] = tar.Header{Typeflag: tar.TypeReg, Mode: 0755}
	}
	headers["dev/null"] = tar.Header{Typeflag: tar.TypeChar, Mode: 0666, Devmajor: 1, Devminor: 3}
	mutate(headers)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var raw bytes.Buffer
	w := tar.NewWriter(&raw)
	for _, name := range names {
		h := headers[name]
		h.Name = "./" + name
		var body string
		if h.Typeflag == tar.TypeReg {
			body = "unchanged fixture bytes: " + name
			h.Size = int64(len(body))
		}
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range duplicates {
		h := headers[name]
		h.Name = "./" + name
		if h.Typeflag != tar.TypeSymlink {
			t.Fatal("duplicate fixture requires applet symlink")
		}
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	input, output := filepath.Join(dir, "input.tar"), filepath.Join(dir, "canonical.tar")
	if err := os.WriteFile(input, raw.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	measured, pins, err := canonicalize(context.Background(), input, output, 1700000000)
	inputAfter, readErr := os.ReadFile(input)
	if readErr != nil || !bytes.Equal(inputAfter, raw.Bytes()) {
		t.Fatal("candidate input changed", readErr)
	}
	if !wantOK {
		if err == nil {
			t.Fatal("unsafe candidate metadata accepted")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("rejected metadata created canonical output", err)
		}
		return
	}
	if err != nil {
		t.Fatal("declared native metadata rejected by actual canonicalizer", err)
	}
	data, err := os.ReadFile(output)
	if err != nil || measured != digest(data) || pins.NodeSHA256 != digest([]byte("unchanged fixture bytes: usr/bin/node")) {
		t.Fatal("canonical bytes/pin mismatch", err)
	}
	r := tar.NewReader(bytes.NewReader(data))
	seen := map[string]bool{}
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[h.Name] = true
		if h.Typeflag == tar.TypeChar || h.Typeflag == tar.TypeBlock {
			t.Fatal("device escaped canonical omission")
		}
		if h.Name == "usr/bin/[" || h.Name == "usr/bin/[[" {
			if h.Typeflag != tar.TypeSymlink || h.Mode != 0777 || h.Uid != 0 || h.Gid != 0 || h.Linkname != "../../bin/busybox" || h.Size != 0 {
				t.Fatal("applet tuple changed")
			}
		}
		if h.Name == "var/www" && (h.Typeflag != tar.TypeDir || h.Mode != 0755 || h.Uid != 0 || h.Gid != 0) {
			t.Fatal("web recipe did not produce exact root-owned directory")
		}
	}
	for _, name := range []string{"usr/bin/[", "usr/bin/[["} {
		if _, present := headers[name]; present && !seen[name] {
			t.Fatal("BusyBox compatibility applet removed")
		}
	}
}
