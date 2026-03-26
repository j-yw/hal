package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSaveInstanceAndLoadInstance(t *testing.T) {
	home := setSandboxHome(t)

	created := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	instance := &SandboxState{
		ID:          "0195b8d6-0f40-7a3f-8c4e-cf7a99e8cc1f",
		Name:        "api-backend",
		Provider:    "daytona",
		WorkspaceID: "ws-123",
		IP:          "100.64.1.10",
		Status:      StatusRunning,
		CreatedAt:   created,
	}

	if err := SaveInstance(instance); err != nil {
		t.Fatalf("SaveInstance() unexpected error: %v", err)
	}

	statePath := filepath.Join(home, sandboxesDirName, "api-backend.json")
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("expected state file to exist: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state file perms = %o, want %o", info.Mode().Perm(), 0o600)
	}
	if _, err := os.Stat(statePath + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temp file should not remain after atomic save")
	}

	loaded, err := LoadInstance("api-backend")
	if err != nil {
		t.Fatalf("LoadInstance() unexpected error: %v", err)
	}
	if loaded.Name != instance.Name {
		t.Fatalf("loaded name = %q, want %q", loaded.Name, instance.Name)
	}
	if loaded.ID != instance.ID {
		t.Fatalf("loaded id = %q, want %q", loaded.ID, instance.ID)
	}
	if loaded.WorkspaceID != instance.WorkspaceID {
		t.Fatalf("loaded workspace = %q, want %q", loaded.WorkspaceID, instance.WorkspaceID)
	}
}

func TestSaveInstance_NameCollision(t *testing.T) {
	setSandboxHome(t)

	if err := SaveInstance(&SandboxState{Name: "worker-01", Status: StatusRunning}); err != nil {
		t.Fatalf("first SaveInstance() failed: %v", err)
	}

	err := SaveInstance(&SandboxState{Name: "worker-01", Status: StatusStopped})
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
	want := `sandbox "worker-01" already exists`
	if err.Error() != want {
		t.Fatalf("collision error = %q, want %q", err.Error(), want)
	}
}

func TestSaveRegistryFileExclusive_DoesNotReplaceExisting(t *testing.T) {
	home := setSandboxHome(t)

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() failed: %v", err)
	}

	path := filepath.Join(home, sandboxesDirName, "worker-01.json")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	err := saveRegistryFileExclusive(path, []byte("second\n"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("saveRegistryFileExclusive() error = %v, want fs.ErrExist", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() failed: %v", readErr)
	}
	if string(data) != "first\n" {
		t.Fatalf("file contents = %q, want %q", string(data), "first\n")
	}
}

func TestForceWriteInstance_Overwrites(t *testing.T) {
	setSandboxHome(t)

	if err := SaveInstance(&SandboxState{
		ID:        "old-id",
		Name:      "frontend",
		Status:    StatusRunning,
		CreatedAt: time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("SaveInstance() failed: %v", err)
	}

	if err := ForceWriteInstance(&SandboxState{
		ID:        "new-id",
		Name:      "frontend",
		Status:    StatusStopped,
		CreatedAt: time.Date(2026, 3, 21, 11, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("ForceWriteInstance() failed: %v", err)
	}

	loaded, err := LoadInstance("frontend")
	if err != nil {
		t.Fatalf("LoadInstance() failed: %v", err)
	}
	if loaded.ID != "new-id" {
		t.Fatalf("loaded id = %q, want %q", loaded.ID, "new-id")
	}
	if loaded.Status != StatusStopped {
		t.Fatalf("loaded status = %q, want %q", loaded.Status, StatusStopped)
	}
}

func TestForceWriteInstance_RetriesWhenRenameCannotReplace(t *testing.T) {
	home := setSandboxHome(t)

	if err := SaveInstance(&SandboxState{
		ID:     "old-id",
		Name:   "frontend",
		Status: StatusRunning,
	}); err != nil {
		t.Fatalf("SaveInstance() failed: %v", err)
	}

	statePath := filepath.Join(home, sandboxesDirName, "frontend.json")
	tmpPath := statePath + ".tmp"
	backupPath := statePath + ".bak"

	originalRename := renameRegistryFile
	originalRemove := removeRegistryFile
	t.Cleanup(func() {
		renameRegistryFile = originalRename
		removeRegistryFile = originalRemove
	})

	renameAttempts := 0
	renameRegistryFile = func(oldPath, newPath string) error {
		if oldPath == tmpPath && newPath == statePath {
			renameAttempts++
			if renameAttempts == 1 {
				return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: fs.ErrExist}
			}
		}
		return originalRename(oldPath, newPath)
	}

	if err := ForceWriteInstance(&SandboxState{
		ID:     "new-id",
		Name:   "frontend",
		Status: StatusStopped,
	}); err != nil {
		t.Fatalf("ForceWriteInstance() failed: %v", err)
	}

	loaded, err := LoadInstance("frontend")
	if err != nil {
		t.Fatalf("LoadInstance() failed: %v", err)
	}
	if loaded.ID != "new-id" {
		t.Fatalf("loaded id = %q, want %q", loaded.ID, "new-id")
	}
	if loaded.Status != StatusStopped {
		t.Fatalf("loaded status = %q, want %q", loaded.Status, StatusStopped)
	}
	if _, err := os.Stat(backupPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("backup file should be removed after overwrite fallback")
	}
}

func TestStageInstanceRemoval_CommitFailureBlocksReuseUntilResolved(t *testing.T) {
	home := setSandboxHome(t)

	if err := SaveInstance(&SandboxState{
		ID:     "old-id",
		Name:   "frontend",
		Status: StatusRunning,
	}); err != nil {
		t.Fatalf("SaveInstance() failed: %v", err)
	}

	statePath := filepath.Join(home, sandboxesDirName, "frontend.json")
	backupPath := statePath + pendingRemovalRegistryFileExt

	originalRemove := removeRegistryFile
	t.Cleanup(func() {
		removeRegistryFile = originalRemove
	})

	removeRegistryFile = func(path string) error {
		if path == backupPath {
			if _, err := os.Stat(path); err == nil {
				return &os.PathError{Op: "remove", Path: path, Err: fs.ErrPermission}
			}
		}
		return originalRemove(path)
	}

	pending, err := StageInstanceRemoval("frontend")
	if err != nil {
		t.Fatalf("StageInstanceRemoval() failed: %v", err)
	}
	if err := pending.Commit(); err == nil {
		t.Fatal("Commit() error = nil, want error")
	}

	if _, err := os.Stat(statePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("active registry file should be absent after staged removal, got %v", err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("staged backup should remain when commit fails: %v", err)
	}
	loaded, err := LoadInstance("frontend")
	if err != nil {
		t.Fatalf("LoadInstance() unexpected error while staged backup exists: %v", err)
	}
	if loaded.ID != "old-id" {
		t.Fatalf("LoadInstance() id = %q, want %q", loaded.ID, "old-id")
	}

	removeRegistryFile = originalRemove
	err = SaveInstance(&SandboxState{
		ID:     "new-id",
		Name:   "frontend",
		Status: StatusStopped,
	})
	if err == nil {
		t.Fatal("SaveInstance() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "pending removal") {
		t.Fatalf("SaveInstance() error = %q, want pending-removal guidance", err.Error())
	}
	if _, err := os.Stat(statePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("active registry file should still be absent while pending removal exists, got %v", err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("staged backup should remain after failed save: %v", err)
	}

	loaded, err = LoadInstance("frontend")
	if err != nil {
		t.Fatalf("LoadInstance() should still return staged backup after failed save: %v", err)
	}
	if loaded.ID != "old-id" {
		t.Fatalf("LoadInstance() id after failed save = %q, want %q", loaded.ID, "old-id")
	}
}

func TestStageInstanceRemoval_RetryReusesExistingStagedBackup(t *testing.T) {
	home := setSandboxHome(t)

	if err := SaveInstance(&SandboxState{
		ID:     "old-id",
		Name:   "frontend",
		Status: StatusRunning,
	}); err != nil {
		t.Fatalf("SaveInstance() failed: %v", err)
	}

	statePath := filepath.Join(home, sandboxesDirName, "frontend.json")
	backupPath := statePath + pendingRemovalRegistryFileExt

	first, err := StageInstanceRemoval("frontend")
	if err != nil {
		t.Fatalf("first StageInstanceRemoval() failed: %v", err)
	}
	if first == nil || !first.active {
		t.Fatalf("first pending removal = %#v, want active staged removal", first)
	}

	retry, err := StageInstanceRemoval("frontend")
	if err != nil {
		t.Fatalf("retry StageInstanceRemoval() failed: %v", err)
	}
	if retry == nil || !retry.active {
		t.Fatalf("retry pending removal = %#v, want active staged removal", retry)
	}
	if retry.path != statePath || retry.backupPath != backupPath {
		t.Fatalf("retry pending removal paths = (%q, %q), want (%q, %q)", retry.path, retry.backupPath, statePath, backupPath)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("active registry file should stay absent during retry, got %v", err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("staged backup should still exist on retry: %v", err)
	}

	if err := retry.Rollback(); err != nil {
		t.Fatalf("retry Rollback() failed: %v", err)
	}

	loaded, err := LoadInstance("frontend")
	if err != nil {
		t.Fatalf("LoadInstance() after rollback failed: %v", err)
	}
	if loaded.ID != "old-id" {
		t.Fatalf("loaded id = %q, want %q", loaded.ID, "old-id")
	}
	if _, err := os.Stat(backupPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("backup file should be removed after rollback, got %v", err)
	}
}

func TestListInstances_IncludesStagedRemovalWhenActiveMissing(t *testing.T) {
	setSandboxHome(t)

	if err := SaveInstance(&SandboxState{
		ID:     "old-id",
		Name:   "frontend",
		Status: StatusRunning,
	}); err != nil {
		t.Fatalf("SaveInstance(frontend) failed: %v", err)
	}
	if err := SaveInstance(&SandboxState{
		ID:     "other-id",
		Name:   "api",
		Status: StatusStopped,
	}); err != nil {
		t.Fatalf("SaveInstance(api) failed: %v", err)
	}

	pending, err := StageInstanceRemoval("frontend")
	if err != nil {
		t.Fatalf("StageInstanceRemoval() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	instances, err := ListInstances()
	if err != nil {
		t.Fatalf("ListInstances() unexpected error: %v", err)
	}
	if len(instances) != 2 {
		t.Fatalf("ListInstances() len = %d, want 2", len(instances))
	}

	gotNames := []string{instances[0].Name, instances[1].Name}
	wantNames := []string{"api", "frontend"}
	if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("ListInstances() names = %v, want %v", gotNames, wantNames)
	}
	if instances[1].ID != "old-id" {
		t.Fatalf("staged instance id = %q, want %q", instances[1].ID, "old-id")
	}
}

func TestLoadInstance_NotFoundWrapsErrNotExist(t *testing.T) {
	setSandboxHome(t)

	_, err := LoadInstance("does-not-exist")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected errors.Is(err, fs.ErrNotExist) to be true, got %v", err)
	}
}

func TestLoadInstance_NormalizesLegacyDigitalOceanWorkspaceID(t *testing.T) {
	home := setSandboxHome(t)

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() failed: %v", err)
	}

	path := filepath.Join(home, sandboxesDirName, "do-box.json")
	data := []byte("{\n  \"id\": \"123456789\",\n  \"name\": \"do-box\",\n  \"provider\": \"digitalocean\",\n  \"status\": \"running\"\n}\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	loaded, err := LoadInstance("do-box")
	if err != nil {
		t.Fatalf("LoadInstance() unexpected error: %v", err)
	}
	if loaded.WorkspaceID != "123456789" {
		t.Fatalf("loaded workspace = %q, want %q", loaded.WorkspaceID, "123456789")
	}
}

func TestLoadInstance_DoesNotBackfillModernDigitalOceanHALID(t *testing.T) {
	home := setSandboxHome(t)

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() failed: %v", err)
	}

	path := filepath.Join(home, sandboxesDirName, "do-box.json")
	data := []byte("{\n  \"id\": \"019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f\",\n  \"name\": \"do-box\",\n  \"provider\": \"digitalocean\",\n  \"status\": \"running\"\n}\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	loaded, err := LoadInstance("do-box")
	if err != nil {
		t.Fatalf("LoadInstance() unexpected error: %v", err)
	}
	if loaded.WorkspaceID != "" {
		t.Fatalf("loaded workspace = %q, want empty", loaded.WorkspaceID)
	}
}

func TestListInstances_NormalizesLegacyDigitalOceanWorkspaceID(t *testing.T) {
	home := setSandboxHome(t)

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() failed: %v", err)
	}

	path := filepath.Join(home, sandboxesDirName, "do-box.json")
	data := []byte("{\n  \"id\": \"123456789\",\n  \"name\": \"do-box\",\n  \"provider\": \"digitalocean\",\n  \"status\": \"running\"\n}\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	instances, err := ListInstances()
	if err != nil {
		t.Fatalf("ListInstances() unexpected error: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("ListInstances() len = %d, want 1", len(instances))
	}
	if instances[0].WorkspaceID != "123456789" {
		t.Fatalf("WorkspaceID = %q, want %q", instances[0].WorkspaceID, "123456789")
	}
}

func TestLoadInstance_BackfillsMissingLegacyID(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		data     string
		wantID   string
	}{
		{
			name:     "workspace fallback",
			filename: "workspace-box",
			data:     "{\n  \"name\": \"workspace-box\",\n  \"provider\": \"daytona\",\n  \"workspaceId\": \"ws-123\",\n  \"status\": \"running\"\n}\n",
			wantID:   "ws-123",
		},
		{
			name:     "name fallback",
			filename: "name-box",
			data:     "{\n  \"name\": \"name-box\",\n  \"provider\": \"daytona\",\n  \"status\": \"running\"\n}\n",
			wantID:   "name-box",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := setSandboxHome(t)

			if err := EnsureGlobalDir(); err != nil {
				t.Fatalf("EnsureGlobalDir() failed: %v", err)
			}

			path := filepath.Join(home, sandboxesDirName, tt.filename+".json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("WriteFile() failed: %v", err)
			}

			loaded, err := LoadInstance(tt.filename)
			if err != nil {
				t.Fatalf("LoadInstance() unexpected error: %v", err)
			}
			if loaded.ID != tt.wantID {
				t.Fatalf("loaded ID = %q, want %q", loaded.ID, tt.wantID)
			}
		})
	}
}

func TestListInstances(t *testing.T) {
	home := setSandboxHome(t)

	instances, err := ListInstances()
	if err != nil {
		t.Fatalf("ListInstances() on empty dir unexpected error: %v", err)
	}
	if len(instances) != 0 {
		t.Fatalf("ListInstances() on empty dir len = %d, want 0", len(instances))
	}

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, sandboxesDirName, "README.md"), []byte("ignore me"), 0o600); err != nil {
		t.Fatalf("write non-json file: %v", err)
	}

	for _, instance := range []*SandboxState{
		{Name: "worker-02", Status: StatusRunning},
		{Name: "api-backend", Status: StatusRunning},
		{Name: "worker-01", Status: StatusStopped},
	} {
		if err := SaveInstance(instance); err != nil {
			t.Fatalf("SaveInstance(%q) failed: %v", instance.Name, err)
		}
	}

	instances, err = ListInstances()
	if err != nil {
		t.Fatalf("ListInstances() unexpected error: %v", err)
	}
	if len(instances) != 3 {
		t.Fatalf("ListInstances() len = %d, want 3", len(instances))
	}

	gotNames := []string{instances[0].Name, instances[1].Name, instances[2].Name}
	wantNames := []string{"api-backend", "worker-01", "worker-02"}
	if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("ListInstances() names = %v, want %v", gotNames, wantNames)
	}
}

func TestResolveDefault(t *testing.T) {
	runningOnly := func(instance *SandboxState) bool {
		return instance.Status == StatusRunning
	}

	tests := []struct {
		name      string
		instances []*SandboxState
		filter    func(*SandboxState) bool
		wantName  string
		wantHint  string
		wantErr   string
	}{
		{
			name:    "no sandboxes returns no sandboxes found",
			wantErr: "no sandboxes found",
		},
		{
			name: "single sandbox returns instance and hint",
			instances: []*SandboxState{
				{Name: "api-backend", Status: StatusRunning},
			},
			wantName: "api-backend",
			wantHint: `connecting to only active sandbox "api-backend"`,
		},
		{
			name: "multiple sandboxes returns sorted choices",
			instances: []*SandboxState{
				{Name: "worker-01", Status: StatusRunning},
				{Name: "frontend", Status: StatusStopped},
				{Name: "api-backend", Status: StatusRunning},
			},
			wantErr: "multiple sandboxes found: api-backend, frontend, worker-01",
		},
		{
			name: "running filter with no running sandboxes returns running error",
			instances: []*SandboxState{
				{Name: "api-backend", Status: StatusStopped},
				{Name: "worker-01", Status: StatusUnknown},
			},
			filter:  runningOnly,
			wantErr: "no running sandboxes",
		},
		{
			name: "running filter with one match returns instance and hint",
			instances: []*SandboxState{
				{Name: "api-backend", Status: StatusStopped},
				{Name: "worker-01", Status: StatusRunning},
			},
			filter:   runningOnly,
			wantName: "worker-01",
			wantHint: `connecting to only active sandbox "worker-01"`,
		},
		{
			name: "running filter with multiple matches returns choices",
			instances: []*SandboxState{
				{Name: "worker-01", Status: StatusRunning},
				{Name: "api-backend", Status: StatusStopped},
				{Name: "frontend", Status: StatusRunning},
			},
			filter:  runningOnly,
			wantErr: "multiple sandboxes found: frontend, worker-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSandboxHome(t)

			for _, instance := range tt.instances {
				if err := SaveInstance(instance); err != nil {
					t.Fatalf("SaveInstance(%q) failed: %v", instance.Name, err)
				}
			}

			got, hint, err := ResolveDefault(tt.filter)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
				}
				if got != nil {
					t.Fatalf("expected nil instance on error, got %q", got.Name)
				}
				if hint != "" {
					t.Fatalf("expected empty hint on error, got %q", hint)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected resolved sandbox, got nil")
			}
			if got.Name != tt.wantName {
				t.Fatalf("resolved name = %q, want %q", got.Name, tt.wantName)
			}
			if hint != tt.wantHint {
				t.Fatalf("hint = %q, want %q", hint, tt.wantHint)
			}
		})
	}
}

func TestResolveDefault_IgnoresStagedRemovalEntries(t *testing.T) {
	setSandboxHome(t)

	if err := SaveInstance(&SandboxState{Name: "api-backend", Status: StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(api-backend) failed: %v", err)
	}
	if err := SaveInstance(&SandboxState{Name: "frontend", Status: StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(frontend) failed: %v", err)
	}

	pending, err := StageInstanceRemoval("frontend")
	if err != nil {
		t.Fatalf("StageInstanceRemoval() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	got, hint, err := ResolveDefault(nil)
	if err != nil {
		t.Fatalf("ResolveDefault() unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected resolved sandbox, got nil")
	}
	if got.Name != "api-backend" {
		t.Fatalf("resolved name = %q, want %q", got.Name, "api-backend")
	}
	if hint != `connecting to only active sandbox "api-backend"` {
		t.Fatalf("hint = %q, want %q", hint, `connecting to only active sandbox "api-backend"`)
	}
}

func TestRemoveInstance(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T)
		target   string
		wantErr  string
		wantIsFS bool
	}{
		{
			name: "removes existing sandbox",
			setup: func(t *testing.T) {
				t.Helper()
				if err := SaveInstance(&SandboxState{Name: "worker-01", Status: StatusRunning}); err != nil {
					t.Fatalf("SaveInstance() failed: %v", err)
				}
			},
			target: "worker-01",
		},
		{
			name:     "returns error when sandbox is missing",
			target:   "missing",
			wantErr:  `sandbox "missing" does not exist`,
			wantIsFS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSandboxHome(t)
			if tt.setup != nil {
				tt.setup(t)
			}

			err := RemoveInstance(tt.target)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				if tt.wantIsFS && !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("expected errors.Is(err, fs.ErrNotExist), got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, err = LoadInstance(tt.target)
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("expected sandbox to be removed, LoadInstance err = %v", err)
			}
		})
	}
}

func setSandboxHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv(halConfigHomeEnv, home)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())
	return home
}
