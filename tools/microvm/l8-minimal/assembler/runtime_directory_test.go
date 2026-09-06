//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Buildroot 2026.05.1 fs/common.mk clears every /run child after post-build,
// mkusers and makedevs, before rootfs-tar. This fixture therefore differs from
// the valid staged layout only by the missing declared runtime directory. The
// actual canonicalizer, not a replacement recipe or mocked return, must emit it.
func TestCanonicalArchiveConstructsDeclaredRuntimeDirectory(t *testing.T) {
	var expected []byte
	for _, scenario := range []string{
		"buildroot_cleared_run", "exact_existing_directory", "missing_run",
		"run_regular", "run_symlink", "run_world_writable", "run_untraversable",
		"run_foreign_owner", "agent_regular", "agent_symlink", "agent_wrong_mode",
		"agent_root_owned", "agent_wrong_gid", "agent_not_empty",
	} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			headers := map[string]tar.Header{}
			bodies := map[string]string{}
			for _, name := range []string{"sbin", "usr", "usr/bin", "usr/lib", "usr/lib/pi", "run", "run/agent", "workspace"} {
				headers[name] = tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}
			}
			for _, name := range []string{"sbin/init", "sbin/hal-init", "usr/bin/hal-guest-agent", "usr/bin/node", "usr/bin/pi", "usr/lib/pi/package.json"} {
				bodies[name] = "unchanged fixture bytes: " + name + "\n"
				headers[name] = tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(bodies[name]))}
			}
			for _, name := range []string{"run/agent", "workspace"} {
				h := headers[name]
				h.Mode, h.Uid, h.Gid = 0700, 1000, 1000
				headers[name] = h
			}
			run, agent := headers["run"], headers["run/agent"]
			switch scenario {
			case "run_regular":
				run.Typeflag = tar.TypeReg
			case "run_symlink":
				run.Typeflag, run.Linkname = tar.TypeSymlink, "/usr"
			case "run_world_writable":
				run.Mode = 0777
			case "run_untraversable":
				run.Mode = 0700
			case "run_foreign_owner":
				run.Uid, run.Gid = 1000, 1000
			case "agent_regular":
				agent.Typeflag, agent.Uid, agent.Gid = tar.TypeReg, 0, 0
			case "agent_symlink":
				agent.Typeflag, agent.Uid, agent.Gid, agent.Linkname = tar.TypeSymlink, 0, 0, "/workspace"
			case "agent_wrong_mode":
				agent.Mode = 0755
			case "agent_root_owned":
				agent.Uid, agent.Gid = 0, 0
			case "agent_wrong_gid":
				agent.Gid = 0
			case "agent_not_empty":
				bodies["run/agent/foreign"] = "must not be silently removed"
				headers["run/agent/foreign"] = tar.Header{Name: "run/agent/foreign", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(bodies["run/agent/foreign"]))}
			}
			headers["run"], headers["run/agent"] = run, agent
			if scenario == "buildroot_cleared_run" || scenario == "missing_run" {
				delete(headers, "run/agent")
			}
			if scenario == "missing_run" {
				delete(headers, "run")
			}
			var names []string
			for name := range headers {
				names = append(names, name)
			}
			sort.Strings(names)
			var raw bytes.Buffer
			writer := tar.NewWriter(&raw)
			for _, name := range names {
				h := headers[name]
				h.Name = "./" + h.Name
				if err := writer.WriteHeader(&h); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte(bodies[name])); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			input, output := filepath.Join(root, "buildroot.tar"), filepath.Join(root, "canonical.tar")
			if err := os.WriteFile(input, raw.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			const epoch = int64(1700000000)
			measured, pins, err := canonicalize(context.Background(), input, output, epoch)
			original, readErr := os.ReadFile(input)
			if readErr != nil || !bytes.Equal(original, raw.Bytes()) {
				t.Fatal("canonical recipe modified its candidate input", readErr)
			}
			if scenario != "buildroot_cleared_run" && scenario != "exact_existing_directory" {
				if err == nil {
					t.Fatal("malformed runtime directory or parent was accepted instead of rejected")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("rejected runtime metadata created canonical output", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output)
			if err != nil || measured != digest(data) || pins.NodeSHA256 != digest([]byte(bodies["usr/bin/node"])) {
				t.Fatal("canonical bytes or unchanged executable not bound to measurement", err)
			}
			reader := tar.NewReader(bytes.NewReader(data))
			found, count := false, 0
			for {
				h, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				body, err := io.ReadAll(reader)
				if err != nil || string(body) != bodies[h.Name] {
					t.Fatal("canonical recipe changed existing file bytes", err)
				}
				if h.Name == "run/agent" {
					if found || h.Typeflag != tar.TypeDir || h.Mode != 0700 || h.Uid != 1000 || h.Gid != 1000 || h.Size != 0 || h.Linkname != "" || !h.ModTime.Equal(time.Unix(epoch, 0)) || len(h.PAXRecords) != 0 {
						t.Fatal("declared directory has incorrect measured metadata")
					}
					found = true
				}
			}
			if !found {
				t.Fatal("Buildroot-shaped canonical archive lacks required measured run/agent directory")
			}
			if count != 14 {
				t.Fatalf("recipe changed unrelated archive entries: %d", count)
			}
			if expected == nil {
				expected = data
			} else if !bytes.Equal(expected, data) {
				t.Fatal("constructed and already-exact directory produced different canonical bytes")
			}
		})
	}
}
