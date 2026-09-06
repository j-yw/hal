package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCachePublishesExactVerifiedSetOrPreservesPriorState(t *testing.T) {
	for _, scenario := range []string{"valid", "reuse", "existing_corrupt", "l5_corrupt", "l5_extra", "l5_symlink", "l8_bad_pin", "missing_archive", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			l5 := filepath.Join(parent, "l5")
			if err := os.Mkdir(l5, 0700); err != nil {
				t.Fatal(err)
			}
			l5locks := map[string]lockedFile{"base.tar": testPin("base.tar", "base")}
			if err := os.WriteFile(filepath.Join(l5, "base.tar"), []byte("base"), 0600); err != nil {
				t.Fatal(err)
			}
			wrap := `{"lockfileVersion":3,"packages":{"":{"name":"@earendil-works/pi-coding-agent","version":"0.82.1"},"node_modules/pkg":{"version":"1.2.3","resolved":"https://registry.npmjs.org/pkg/-/pkg-1.2.3.tgz"}}}`
			archive := fixtureArchive(t, []*tar.Header{{Name: "package/npm-shrinkwrap.json", Mode: 0644, Size: int64(len(wrap)), Typeflag: tar.TypeReg}}, []string{wrap})
			payloads := map[string][]byte{nodeFile: []byte("node"), piFile: archive, shrinkwrapFile: []byte(wrap), "pkg-1.2.3.tgz": []byte("package")}
			l8locks := map[string]lockedFile{}
			for name, data := range payloads {
				l8locks[name] = testPin(name, string(data))
			}
			var calls atomic.Int32
			client := newHTTPClient(fakeTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				data := payloads[filepath.Base(r.URL.Path)]
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header), ContentLength: int64(len(data)), Request: r}, nil
			}))
			output := filepath.Join(parent, "cache")
			if scenario == "reuse" || scenario == "existing_corrupt" {
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range payloads {
					if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(output, "base.tar"), []byte("base"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "existing_corrupt":
				if err := os.WriteFile(filepath.Join(output, nodeFile), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "l5_corrupt":
				if err := os.WriteFile(filepath.Join(l5, "base.tar"), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "l5_extra":
				if err := os.WriteFile(filepath.Join(l5, "extra"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "l5_symlink":
				if err := os.Rename(filepath.Join(l5, "base.tar"), filepath.Join(parent, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(parent, "saved"), filepath.Join(l5, "base.tar")); err != nil {
					t.Fatal(err)
				}
			case "l8_bad_pin":
				pin := l8locks[nodeFile]
				pin.SHA256 = strings.Repeat("1", 64)
				l8locks[nodeFile] = pin
			case "missing_archive":
				delete(payloads, "pkg-1.2.3.tgz")
			}
			before, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			err = acquireCache(ctx, output, l5, l5locks, l8locks, client)
			if scenario == "valid" || scenario == "reuse" {
				if err != nil {
					t.Fatal(err)
				}
				all := map[string]lockedFile{}
				for name, pin := range l5locks {
					all[name] = pin
				}
				for name, pin := range l8locks {
					all[name] = pin
				}
				if err := verifyCache(ctx, output, all); err != nil {
					t.Fatal(err)
				}
				if scenario == "valid" && calls.Load() != 3 {
					t.Fatalf("requests=%d, want Node+Pi+dependency", calls.Load())
				}
				if scenario == "reuse" && calls.Load() != 0 {
					t.Fatal("existing verified cache triggered network")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe cache accepted")
				}
				after, e := os.ReadDir(parent)
				if e != nil {
					t.Fatal(e)
				}
				names := func(entries []os.DirEntry) []string {
					var out []string
					for _, e := range entries {
						out = append(out, e.Name())
					}
					return out
				}
				if !reflect.DeepEqual(names(before), names(after)) {
					t.Fatalf("partial publication or leaked stage: %v -> %v", names(before), names(after))
				}
				if scenario == "existing_corrupt" {
					data, _ := os.ReadFile(filepath.Join(output, nodeFile))
					if string(data) != "keep" || calls.Load() != 0 {
						t.Fatal("repaired existing cache without authority")
					}
				}
			}
		})
	}
}
