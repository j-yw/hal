//go:build linux

package main

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalRuntimeDirectoryKeepsEntryBound(t *testing.T) {
	for _, inputCount := range []int{65533, 65534} {
		t.Run(fmt.Sprint(inputCount), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			input, output := filepath.Join(root, "input.tar"), filepath.Join(root, "output.tar")
			file, err := os.OpenFile(input, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			writer := tar.NewWriter(file)
			count := 0
			write := func(name string, kind byte) {
				t.Helper()
				h := &tar.Header{Name: name, Typeflag: kind, Mode: 0755}
				if kind == tar.TypeReg {
					h.Size = 1
				}
				if err := writer.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if kind == tar.TypeReg {
					if _, err := writer.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
				}
				count++
			}
			for _, name := range []string{"run", "sbin", "usr", "usr/bin", "usr/lib", "usr/lib/pi"} {
				write(name, tar.TypeDir)
			}
			for _, name := range []string{"sbin/init", "sbin/hal-init", "usr/bin/hal-guest-agent", "usr/bin/node", "usr/bin/pi", "usr/lib/pi/package.json"} {
				write(name, tar.TypeReg)
			}
			for count < inputCount {
				write(fmt.Sprintf("empty-%05d", count), tar.TypeDir)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			_, _, err = canonicalize(context.Background(), input, output, 1700000000)
			if inputCount == 65534 {
				if err == nil {
					t.Fatal("constructed directory exceeded the output entry bound")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("oversize recipe created output", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := os.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			reader := tar.NewReader(result)
			count = 0
			for {
				if _, err := reader.Next(); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				count++
			}
			if count != 65534 {
				t.Fatalf("exact-bound canonical count=%d", count)
			}
		})
	}
}
