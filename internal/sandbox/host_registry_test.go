package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveHostAndLoadHost(t *testing.T) {
	home := setSandboxHome(t)

	host := &SandboxHost{
		ID:       "host-01",
		Name:     "builder-01",
		Kind:     SandboxHostKindWorker,
		Endpoint: "ssh://builder-01.example.test",
		Labels: map[string]string{
			"region": "iad",
		},
	}

	if err := SaveHost(host); err != nil {
		t.Fatalf("SaveHost() unexpected error: %v", err)
	}

	hostPath := filepath.Join(home, sandboxHostsDirName, "host-01.json")
	info, err := os.Stat(hostPath)
	if err != nil {
		t.Fatalf("expected host file to exist: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("host file perms = %o, want %o", info.Mode().Perm(), 0o600)
	}
	assertNoTempFiles(t, filepath.Join(home, sandboxHostsDirName))

	dirInfo, err := os.Stat(filepath.Join(home, sandboxHostsDirName))
	if err != nil {
		t.Fatalf("expected host dir to exist: %v", err)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("host dir perms = %o, want %o", dirInfo.Mode().Perm(), 0o700)
	}

	loaded, err := LoadHost("host-01")
	if err != nil {
		t.Fatalf("LoadHost() unexpected error: %v", err)
	}
	if loaded.ID != host.ID || loaded.Name != host.Name || loaded.Kind != host.Kind || loaded.Endpoint != host.Endpoint {
		t.Fatalf("loaded host = %#v, want %#v", loaded, host)
	}
	if loaded.Labels["region"] != "iad" {
		t.Fatalf("loaded labels = %#v, want region iad", loaded.Labels)
	}
}

func TestSaveHostValidationLeavesNoFiles(t *testing.T) {
	home := setSandboxHome(t)

	tests := []struct {
		name string
		host *SandboxHost
	}{
		{
			name: "missing id",
			host: &SandboxHost{Name: "builder-01", Kind: SandboxHostKindLocal},
		},
		{
			name: "missing name",
			host: &SandboxHost{ID: "host-01", Kind: SandboxHostKindLocal},
		},
		{
			name: "path separator",
			host: &SandboxHost{ID: "nested/host", Name: "builder-01", Kind: SandboxHostKindLocal},
		},
		{
			name: "dot segment",
			host: &SandboxHost{ID: "..", Name: "builder-01", Kind: SandboxHostKindLocal},
		},
		{
			name: "leading whitespace",
			host: &SandboxHost{ID: " host-01", Name: "builder-01", Kind: SandboxHostKindLocal},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveHost(tt.host); err == nil {
				t.Fatal("SaveHost() error = nil, want validation error")
			}
			assertNoStoreFiles(t, filepath.Join(home, sandboxHostsDirName))
		})
	}
}

func TestSaveHostDuplicatePreservesExisting(t *testing.T) {
	home := setSandboxHome(t)

	if err := SaveHost(&SandboxHost{ID: "host-01", Name: "builder-01", Kind: SandboxHostKindLocal}); err != nil {
		t.Fatalf("SaveHost() first save failed: %v", err)
	}

	hostPath := filepath.Join(home, sandboxHostsDirName, "host-01.json")
	before, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	err = SaveHost(&SandboxHost{ID: "host-01", Name: "replacement", Kind: SandboxHostKindWorker})
	if err == nil {
		t.Fatal("SaveHost() duplicate error = nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("SaveHost() duplicate error = %q, want already exists", err.Error())
	}

	after, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile() after duplicate failed: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("duplicate save changed host file:\nbefore=%s\nafter=%s", before, after)
	}
	assertNoTempFiles(t, filepath.Join(home, sandboxHostsDirName))
}

func TestForceWriteHostOverwrites(t *testing.T) {
	setSandboxHome(t)

	if err := SaveHost(&SandboxHost{ID: "host-01", Name: "builder-01", Kind: SandboxHostKindLocal}); err != nil {
		t.Fatalf("SaveHost() failed: %v", err)
	}

	if err := ForceWriteHost(&SandboxHost{ID: "host-01", Name: "builder-02", Kind: SandboxHostKindWorker}); err != nil {
		t.Fatalf("ForceWriteHost() failed: %v", err)
	}

	loaded, err := LoadHost("host-01")
	if err != nil {
		t.Fatalf("LoadHost() failed: %v", err)
	}
	if loaded.Name != "builder-02" || loaded.Kind != SandboxHostKindWorker {
		t.Fatalf("loaded host = %#v, want overwritten host", loaded)
	}
}

func TestListHostsMissingDirAndSorted(t *testing.T) {
	setSandboxHome(t)

	hosts, err := ListHosts()
	if err != nil {
		t.Fatalf("ListHosts() on missing dir unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("ListHosts() len = %d, want 0", len(hosts))
	}

	for _, host := range []*SandboxHost{
		{ID: "host-c", Name: "worker", Kind: SandboxHostKindWorker},
		{ID: "host-b", Name: "builder", Kind: SandboxHostKindWorker},
		{ID: "host-a", Name: "builder", Kind: SandboxHostKindLocal},
	} {
		if err := SaveHost(host); err != nil {
			t.Fatalf("SaveHost(%q) failed: %v", host.ID, err)
		}
	}

	hosts, err = ListHosts()
	if err != nil {
		t.Fatalf("ListHosts() unexpected error: %v", err)
	}
	got := []string{hosts[0].ID, hosts[1].ID, hosts[2].ID}
	want := []string{"host-a", "host-b", "host-c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ListHosts() order = %v, want %v", got, want)
	}
}

func TestLoadAndListHostsPreserveCorruptJSON(t *testing.T) {
	home := setSandboxHome(t)
	hostDir := filepath.Join(home, sandboxHostsDirName)
	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() failed: %v", err)
	}
	hostPath := filepath.Join(hostDir, "host-01.json")
	corrupt := []byte("{not-json\n")
	if err := os.WriteFile(hostPath, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	if _, err := LoadHost("host-01"); err == nil || !strings.Contains(err.Error(), "parse host") {
		t.Fatalf("LoadHost() error = %v, want parse host error", err)
	}
	assertFileBytes(t, hostPath, corrupt)

	if _, err := ListHosts(); err == nil || !strings.Contains(err.Error(), "parse host") {
		t.Fatalf("ListHosts() error = %v, want parse host error", err)
	}
	assertFileBytes(t, hostPath, corrupt)
}

func TestRemoveHost(t *testing.T) {
	setSandboxHome(t)

	if err := SaveHost(&SandboxHost{ID: "host-01", Name: "builder-01", Kind: SandboxHostKindLocal}); err != nil {
		t.Fatalf("SaveHost() failed: %v", err)
	}
	if err := RemoveHost("host-01"); err != nil {
		t.Fatalf("RemoveHost() failed: %v", err)
	}
	if _, err := LoadHost("host-01"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadHost() after remove error = %v, want fs.ErrNotExist", err)
	}

	err := RemoveHost("host-01")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("RemoveHost() missing error = %v, want fs.ErrNotExist", err)
	}
}

func assertNoStoreFiles(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("ReadDir(%q) failed: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("store %q has entries after failed operation: %v", dir, entries)
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(dir, "*.tmp*"))
	if err != nil {
		t.Fatalf("Glob() failed: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp files should not remain in %q: %v", dir, matches)
	}
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) failed: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("file %q bytes = %q, want %q", path, string(got), string(want))
	}
}
