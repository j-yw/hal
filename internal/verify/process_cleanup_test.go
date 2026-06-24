package verify

import (
	"errors"
	"reflect"
	"testing"
)

func TestKillWindowsProcessTreeUsesTaskkillTreeMode(t *testing.T) {
	var gotName string
	var gotArgs []string

	err := killWindowsProcessTree(1234, func() error {
		t.Fatal("killParent should not be called when taskkill succeeds")
		return nil
	}, func(name string, args ...string) error {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return nil
	})
	if err != nil {
		t.Fatalf("killWindowsProcessTree() error = %v, want nil", err)
	}

	if gotName != "taskkill.exe" {
		t.Fatalf("command = %q, want taskkill.exe", gotName)
	}
	wantArgs := []string{"/T", "/F", "/PID", "1234"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %#v, want %#v", gotArgs, wantArgs)
	}
}

func TestKillWindowsProcessTreeFallsBackToParentKill(t *testing.T) {
	taskkillErr := errors.New("taskkill failed")
	parentKilled := false

	err := killWindowsProcessTree(1234, func() error {
		parentKilled = true
		return nil
	}, func(string, ...string) error {
		return taskkillErr
	})
	if !errors.Is(err, taskkillErr) {
		t.Fatalf("killWindowsProcessTree() error = %v, want taskkill error", err)
	}
	if !parentKilled {
		t.Fatal("killParent was not called")
	}
}
