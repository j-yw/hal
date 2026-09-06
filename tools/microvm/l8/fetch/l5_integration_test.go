//go:build linux && microvm_assets_integration

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestL5BoundedTransferOptInPreservesDefault(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_default", true: "bounded_opt_in"}[bounded], func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, "curl-args")
			shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FETCH_TEST_LOG\"\nexit 1\n"
			if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(shim), 0700); err != nil {
				t.Fatal(err)
			}
			script, err := filepath.Abs("../../l5/fetch.sh")
			if err != nil {
				t.Fatal(err)
			}
			args := []string{script, "--cache", filepath.Join(root, "cache")}
			if bounded {
				args = append(args, "--bounded-transfers")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/bash", args...)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + root, "FETCH_TEST_LOG=" + log}
			output, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatal("injected download failure unexpectedly succeeded")
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatalf("first download not reached: %v; child=%s", err, output)
			}
			text := string(data)
			if bounded {
				for _, fragment := range []string{"--max-filesize\n371680\n", "--connect-timeout\n20\n", "--max-time\n600\n", "--retry-max-time\n1200\n", "--max-redirs\n5\n", "--proto\n=https\n", "--proto-redir\n=https\n"} {
					if !strings.Contains(text, fragment) {
						t.Errorf("bounded transfer missing %q", fragment)
					}
				}
			} else if strings.Contains(text, "--max-filesize") || strings.Contains(text, "--proto") {
				t.Fatal("legacy default changed")
			}
		})
	}
}
