package rootlesspodman_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestL7PodmanExactContainerCleanupReportsDeleteFailureAndStillProvesAbsence(t *testing.T) {
	deleteCalls := 0
	absenceCalls := 0
	err := runL7PodmanExactContainerCleanup(true, func() error {
		deleteCalls++
		return errors.New("delete endpoint=/run/user/1000/private.sock token=delete-secret")
	}, func() error {
		absenceCalls++
		return nil
	})
	if !errors.Is(err, errL7PodmanExactContainerDeleteFailed) {
		t.Fatalf("cleanup error = %v, want reported exact-container delete failure", err)
	}
	if deleteCalls != 1 || absenceCalls != 1 {
		t.Fatalf("post-create failure cleanup calls = delete:%d absence:%d, want both exactly once", deleteCalls, absenceCalls)
	}
	for _, forbidden := range []string{"/run/user", "private.sock", "delete-secret"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("cleanup error leaked %q: %v", forbidden, err)
		}
	}
}

func TestL7PodmanExactContainerCleanupAlwaysChecksAbsence(t *testing.T) {
	deleteCalls := 0
	absenceCalls := 0
	err := runL7PodmanExactContainerCleanup(false, func() error {
		deleteCalls++
		return errors.New("unexpected delete")
	}, func() error {
		absenceCalls++
		return errors.New("absence endpoint=/run/user/1000/private.sock token=absence-secret")
	})
	if !errors.Is(err, errL7PodmanExactContainerAbsenceUnverified) {
		t.Fatalf("cleanup error = %v, want exact-container absence failure", err)
	}
	if deleteCalls != 0 || absenceCalls != 1 {
		t.Fatalf("post-delete cleanup calls = delete:%d absence:%d, want absence only", deleteCalls, absenceCalls)
	}
	for _, forbidden := range []string{"/run/user", "private.sock", "absence-secret"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("cleanup error leaked %q: %v", forbidden, err)
		}
	}
}

func TestL7PodmanExactContainerAbsenceUsesOnlyExactExistsQuery(t *testing.T) {
	var gotExecutable string
	var gotArgs []string
	err := proveL7PodmanExactContainerAbsentWithRunner(
		context.Background(),
		"/private/podman",
		"exact-created-container-id",
		func(_ context.Context, executable string, args ...string) (int, error) {
			gotExecutable = executable
			gotArgs = append([]string(nil), args...)
			return 1, nil
		},
	)
	if err != nil {
		t.Fatalf("absence proof error: %v", err)
	}
	if gotExecutable != "/private/podman" || !reflect.DeepEqual(gotArgs, []string{"container", "exists", "exact-created-container-id"}) {
		t.Fatalf("absence query = %q %#v, want exact non-destructive container exists query", gotExecutable, gotArgs)
	}

	for _, test := range []struct {
		name     string
		exitCode int
		err      error
	}{
		{name: "container remains", exitCode: 0},
		{name: "unexpected status", exitCode: 125},
		{name: "runner error", exitCode: -1, err: errors.New("endpoint=/run/user/1000/private.sock token=query-secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := proveL7PodmanExactContainerAbsentWithRunner(
				context.Background(), "podman", "exact-created-container-id",
				func(context.Context, string, ...string) (int, error) { return test.exitCode, test.err },
			)
			if !errors.Is(err, errL7PodmanExactContainerAbsenceUnverified) {
				t.Fatalf("absence proof error = %v, want fail-closed sentinel", err)
			}
			for _, forbidden := range []string{"/run/user", "private.sock", "query-secret"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("absence proof error leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}
