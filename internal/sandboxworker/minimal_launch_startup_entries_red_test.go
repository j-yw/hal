package sandboxworker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMinimalLaunchStartupQuarantinesUncertainEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "unpublished temporary", "unknown file"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newMinimalLaunchDispatchFixture(t)
			if _, err := newJobStoreV2(fixture.stateDir); err != nil {
				t.Fatal(err)
			}
			canary := filepath.Join(t.TempDir(), "successor-canary")
			payload := []byte("unrelated successor must remain unchanged\n")
			if err := os.WriteFile(canary, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixture.stateDir, "job-retained.json")
			switch kind {
			case "symlink":
				if err := os.Symlink(canary, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				canary = filepath.Join(path, "child-canary")
				if err := os.WriteFile(canary, payload, 0o600); err != nil {
					t.Fatal(err)
				}
			case "unpublished temporary", "unknown file":
				name := ".minimal-job-retained-pending"
				if kind == "unknown file" {
					name = "unexpected"
				}
				path = filepath.Join(fixture.stateDir, name)
				if err := os.WriteFile(path, payload, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			service, admissionErr := NewL8DurableService(fixture.options())
			if service != nil {
				service.Close()
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("startup replaced retained entry: %v", err)
			}
			got, err := os.ReadFile(canary)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("startup changed successor canary: %v", err)
			}
			if before.Mode().IsRegular() {
				got, err = os.ReadFile(path)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("startup changed retained bytes: %v", err)
				}
			}
			if fixture.provider.resolveCalls != 0 || fixture.provider.startCalls != 0 || fixture.provider.recoverCalls != 0 {
				t.Fatal("uncertain startup entered a provider")
			}
			if service != nil || admissionErr == nil {
				t.Fatalf("selected startup accepted uncertain %s: service=%t error=%v", kind, service != nil, admissionErr)
			}
		})
	}
}
