package sandbox

import "testing"

func TestRegistrySupportsLegacySandboxNames(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	name := "Feature_A.v1"
	if err := SaveInstance(&SandboxState{Name: name, Status: StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(%q) failed: %v", name, err)
	}

	loaded, err := LoadInstance(name)
	if err != nil {
		t.Fatalf("LoadInstance(%q) failed: %v", name, err)
	}
	if loaded.Name != name {
		t.Fatalf("LoadInstance(%q) name = %q, want %q", name, loaded.Name, name)
	}

	pending, err := StageInstanceRemoval(name)
	if err != nil {
		t.Fatalf("StageInstanceRemoval(%q) failed: %v", name, err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	loaded, err = LoadInstance(name)
	if err != nil {
		t.Fatalf("LoadInstance(%q) after staging failed: %v", name, err)
	}
	if loaded.Name != name {
		t.Fatalf("LoadInstance(%q) after staging name = %q, want %q", name, loaded.Name, name)
	}
}
