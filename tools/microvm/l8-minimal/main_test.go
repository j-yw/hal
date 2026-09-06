//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/minimalprofile"
)

func TestMinimalToolRequiresIndependentRequestPin(t *testing.T) {
	for _, scenario := range []string{"missing_pin", "wrong_pin", "unknown_field", "trailing_json", "symlink", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			data := []byte(`{"SourceRevision":"fixture"}`)
			if scenario == "unknown_field" {
				data = []byte(`{"unexpected":true}`)
			}
			if scenario == "trailing_json" {
				data = []byte(`{} {}`)
			}
			name := filepath.Join(t.TempDir(), "request.json")
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			digest := hex.EncodeToString(sum[:])
			if scenario == "symlink" {
				link := filepath.Join(t.TempDir(), "request.json")
				if err := os.Symlink(name, link); err != nil {
					t.Fatal(err)
				}
				name = link
			}
			if scenario == "missing_pin" {
				digest = ""
			}
			if scenario == "wrong_pin" {
				digest = hex.EncodeToString(make([]byte, 32))
			}
			called := false
			var out bytes.Buffer
			err := run(context.Background(), []string{"-request", name, "-request-sha256", digest}, &out, func(_ context.Context, req minimalprofile.PublishRequest) (minimalprofile.Receipt, error) {
				called = true
				if req.SourceRevision != "fixture" {
					t.Fatal("wrong request bytes")
				}
				return minimalprofile.Receipt{}, nil
			})
			if scenario == "valid" {
				if err != nil || !called || !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
					t.Fatalf("valid request=%v called=%v", err, called)
				}
			} else if err == nil || called || out.Len() != 0 {
				t.Fatalf("unsafe request reached publisher: %v %v", err, called)
			}
		})
	}
}
