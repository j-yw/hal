package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func testPin(name, content string) lockedFile {
	sum := sha256.Sum256([]byte(content))
	return lockedFile{Name: name, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
}

func manifestText(files ...lockedFile) string {
	var lines []string
	for _, f := range files {
		lines = append(lines, fmt.Sprintf("%s\t%d\t%s\n", f.SHA256, f.Size, f.Name))
	}
	sort.Strings(lines)
	return strings.Join(lines, "")
}

func TestLockedManifestRejectsAmbiguousInputs(t *testing.T) {
	a, b := testPin("a.tgz", "one"), testPin("b.tgz", "two")
	valid := manifestText(a, b)
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"valid", valid, true}, {"empty", "", false},
		{"duplicate", manifestText(a, a), false},
		{"traversal", manifestText(testPin("../a.tgz", "one")), false},
		{"absolute", manifestText(testPin("/a.tgz", "one")), false},
		{"backslash", manifestText(testPin(`a\b`, "one")), false},
		{"extra_field", strings.TrimSuffix(valid, "\n") + "\textra\n", false},
		{"zero_size", strings.ReplaceAll(valid, "\t3\t", "\t0\t"), false},
		{"overflow", strings.ReplaceAll(valid, "\t3\t", "\t999999999999999999999\t"), false},
		{"zero_digest", strings.Repeat("0", 64) + "\t1\ta.tgz\n", false},
		{"unsorted", strings.Split(valid, "\n")[1] + "\n" + strings.Split(valid, "\n")[0] + "\n", false},
		{"bounded", strings.Repeat("x", 4<<20+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseManifest(strings.NewReader(tc.data))
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%v, expected=%v: %v", err == nil, tc.valid, err)
			}
			if tc.valid && len(got) != 2 {
				t.Fatal("lost manifest entries")
			}
		})
	}
}

func fixtureArchive(t *testing.T, headers []*tar.Header, payloads []string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for i, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, payloads[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestShrinkwrapExtractsOnlyVerifiedBoundedRegularBytes(t *testing.T) {
	content := `{"lockfileVersion":3,"packages":{}}`
	for _, tc := range []string{"valid", "wrong_pin", "duplicate", "link", "traversal", "absolute", "unexpected_link", "bad_gzip", "expanded_bound"} {
		t.Run(tc, func(t *testing.T) {
			h := &tar.Header{Name: "package/npm-shrinkwrap.json", Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(content))}
			headers, payloads := []*tar.Header{h}, []string{content}
			pin := testPin("pi-shrinkwrap-0.82.1.json", content)
			switch tc {
			case "wrong_pin":
				pin.SHA256 = strings.Repeat("1", 64)
			case "duplicate":
				headers = append(headers, h)
				payloads = append(payloads, content)
			case "link":
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "elsewhere"
				h.Size = 0
				payloads[0] = ""
			case "traversal":
				h.Name = "package/../npm-shrinkwrap.json"
			case "absolute":
				h.Name = "/package/npm-shrinkwrap.json"
			case "unexpected_link":
				headers = append(headers, &tar.Header{Name: "package/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
				payloads = append(payloads, "")
			case "expanded_bound":
				headers = append(headers, &tar.Header{Name: "package/large", Typeflag: tar.TypeReg, Size: 65 << 20})
				payloads = append(payloads, strings.Repeat("a", 65<<20))
			}
			data := fixtureArchive(t, headers, payloads)
			if tc == "bad_gzip" {
				data = data[:len(data)/2]
			}
			got, err := extractShrinkwrap(context.Background(), bytes.NewReader(data), pin)
			if tc == "valid" {
				if err != nil || string(got) != content {
					t.Fatalf("got %q error %v", got, err)
				}
			} else if err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestShrinkwrapPlansOnlyExactLockedRegistryClosure(t *testing.T) {
	wrap := `{"lockfileVersion":3,"packages":{"":{"name":"@earendil-works/pi-coding-agent","version":"0.82.1"},"node_modules/@scope/pkg":{"version":"1.2.3","resolved":"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"}}}`
	locks := map[string]lockedFile{}
	for _, name := range []string{"node-v22.22.0.tar.xz", "pi-coding-agent-0.82.1.tgz", "pi-shrinkwrap-0.82.1.json", "scope-pkg-1.2.3.tgz"} {
		locks[name] = testPin(name, "data")
	}
	for _, tc := range []string{"valid", "wrong_origin", "http", "user_info", "query", "path_mismatch", "traversal", "wrong_version", "unlocked", "extra_lock", "missing_resolved", "duplicate_archive"} {
		t.Run(tc, func(t *testing.T) {
			data := wrap
			pins := map[string]lockedFile{}
			for k, v := range locks {
				pins[k] = v
			}
			switch tc {
			case "wrong_origin":
				data = strings.Replace(data, "registry.npmjs.org", "registry.npmjs.org.evil", 1)
			case "http":
				data = strings.Replace(data, "https:", "http:", 1)
			case "user_info":
				data = strings.Replace(data, "https://", "https://secret@", 1)
			case "query":
				data = strings.Replace(data, "pkg-1.2.3.tgz", "pkg-1.2.3.tgz?token=secret", 1)
			case "path_mismatch":
				data = strings.Replace(data, "/-/pkg-", "/-/other-", 1)
			case "traversal":
				data = strings.Replace(data, "node_modules/@scope/pkg", "node_modules/../pkg", 1)
			case "wrong_version":
				data = strings.Replace(data, `"version":"1.2.3"`, `"version":"1.2.4"`, 1)
			case "unlocked":
				delete(pins, "scope-pkg-1.2.3.tgz")
			case "extra_lock":
				pins["extra-1.0.0.tgz"] = testPin("extra-1.0.0.tgz", "data")
			case "missing_resolved":
				data = strings.Replace(data, `,"resolved":"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"`, "", 1)
			case "duplicate_archive":
				data = strings.Replace(data, `"node_modules/@scope/pkg":`, `"node_modules/parent/node_modules/@scope/pkg":{"version":"1.2.3","resolved":"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"},"node_modules/@scope/pkg":`, 1)
			}
			got, err := planNPMDownloads([]byte(data), pins)
			// Repeated identical installed packages share one locked tarball;
			// records without resolved URLs derive only the canonical exact URL.
			valid := tc == "valid" || tc == "missing_resolved" || tc == "duplicate_archive"
			if valid {
				if err != nil || len(got) != 1 || got[0].File.Name != "scope-pkg-1.2.3.tgz" {
					t.Fatalf("plan=%#v err=%v", got, err)
				}
			} else if err == nil {
				t.Fatal("unsafe or incomplete closure accepted")
			}
		})
	}
}

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedReader struct {
	io.Reader
	count int
}

func (r *observedReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.count += n
	return n, e
}

func TestDownloadPinsBoundsCancellationAndNoOverwrite(t *testing.T) {
	for _, tc := range []string{"valid", "wrong_digest", "short", "oversize", "http_error", "redirect_origin", "cancelled", "existing", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			root := t.TempDir()
			spec := downloadSpec{File: testPin("pkg.tgz", "data"), URL: "https://registry.npmjs.org/pkg/-/pkg.tgz"}
			body := "data"
			if tc == "short" {
				body = "dat"
			}
			if tc == "oversize" {
				body = strings.Repeat("x", 1024)
			}
			if tc == "wrong_digest" {
				spec.File.SHA256 = strings.Repeat("1", 64)
			}
			reader := &observedReader{Reader: strings.NewReader(body)}
			calls := 0
			client := newHTTPClient(fakeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Fatal("unexpected credentials")
				}
				status := 200
				h := make(http.Header)
				if tc == "http_error" {
					status = 500
				}
				if tc == "redirect_origin" {
					status = 302
					h.Set("Location", "https://evil.example/pkg")
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(reader), ContentLength: -1, Request: r}, nil
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc == "cancelled" {
				cancel()
			}
			file := filepath.Join(root, "pkg.tgz")
			if tc == "existing" {
				if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc == "symlink" {
				if err := os.Symlink("missing", file); err != nil {
					t.Fatal(err)
				}
			}
			err := downloadPinned(ctx, client, root, spec)
			if tc == "valid" {
				got, e := os.ReadFile(file)
				if err != nil || e != nil || string(got) != "data" {
					t.Fatalf("download=%q %v %v", got, e, err)
				}
			} else {
				if err == nil {
					t.Fatal("unsafe download accepted")
				}
				if tc == "existing" {
					got, _ := os.ReadFile(file)
					if string(got) != "keep" {
						t.Fatal("overwrote existing cache")
					}
				} else if tc == "symlink" {
					if target, _ := os.Readlink(file); target != "missing" {
						t.Fatal("changed existing symlink")
					}
				} else if _, e := os.Lstat(file); !os.IsNotExist(e) {
					t.Fatal("partial cache file remains")
				}
			}
			if reader.count > int(spec.File.Size)+1 {
				t.Fatalf("unbounded read: %d", reader.count)
			}
			if tc == "cancelled" && calls != 0 {
				t.Fatal("cancelled request reached transport")
			}
			if tc == "redirect_origin" && calls != 1 {
				t.Fatal("followed unsafe redirect")
			}
		})
	}
}
