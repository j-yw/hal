package rootlesspodman_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

const l7PodmanExactContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	errL7PodmanExactContainerDeleteFailed      = errors.New("selected L7 Podman exact-container delete failed")
	errL7PodmanExactContainerAbsenceUnverified = errors.New("selected L7 Podman exact-container absence unverified")
	errL7PodmanRestartCleanupUncertain         = errors.New("selected L7 Podman restart cleanup ownership unverified")
)

type l7PodmanCommandRunner func(context.Context, string, ...string) (int, error)
type l7PodmanOutputRunner func(context.Context, string, ...string) ([]byte, error)

type l7PodmanCleanupFailure struct {
	safe  error
	cause error
}

func (e *l7PodmanCleanupFailure) Error() string {
	return e.safe.Error()
}

func (e *l7PodmanCleanupFailure) Unwrap() []error {
	return []error{e.safe, e.cause}
}

func runL7PodmanExactContainerCleanup(deletePending bool, deleteExact, proveExactAbsent func() error) error {
	var cleanupErrors []error
	if deletePending {
		if deleteExact == nil {
			cleanupErrors = append(cleanupErrors, errL7PodmanExactContainerDeleteFailed)
		} else if err := deleteExact(); err != nil {
			cleanupErrors = append(cleanupErrors, &l7PodmanCleanupFailure{
				safe:  errL7PodmanExactContainerDeleteFailed,
				cause: err,
			})
		}
	}
	if proveExactAbsent == nil || proveExactAbsent() != nil {
		cleanupErrors = append(cleanupErrors, errL7PodmanExactContainerAbsenceUnverified)
	}
	return errors.Join(cleanupErrors...)
}

func proveL7PodmanExactContainerAbsentWithRunner(ctx context.Context, podmanPath, exactContainerID string, run l7PodmanCommandRunner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	podmanPath = strings.TrimSpace(podmanPath)
	exactContainerID = strings.TrimSpace(exactContainerID)
	if ctx.Err() != nil || podmanPath == "" || !validL7PodmanExactContainerID(exactContainerID) || run == nil {
		return errL7PodmanExactContainerAbsenceUnverified
	}
	exitCode, err := run(ctx, podmanPath, "container", "exists", exactContainerID)
	if err != nil || exitCode != 1 {
		return errL7PodmanExactContainerAbsenceUnverified
	}
	return nil
}

func validL7PodmanExactContainerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func removeOwnedL7PodmanRestartContainerWithRunner(ctx context.Context, podmanPath, containerName string, identity rootlesspodman.NetworkTopologyIdentity, run l7PodmanOutputRunner) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	podmanPath = strings.TrimSpace(podmanPath)
	containerName = strings.TrimSpace(containerName)
	if ctx.Err() != nil || podmanPath == "" || containerName == "" || run == nil {
		return "", errL7PodmanRestartCleanupUncertain
	}
	output, err := run(ctx, podmanPath, "container", "inspect", containerName)
	if err != nil {
		return "", errL7PodmanRestartCleanupUncertain
	}
	var payload []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal(output, &payload) != nil || len(payload) != 1 || !validL7PodmanExactContainerID(payload[0].ID) || strings.TrimPrefix(payload[0].Name, "/") != containerName {
		return "", errL7PodmanRestartCleanupUncertain
	}
	wantLabels := map[string]string{
		"dev.jywlabs.hal.runtime":                  rootlesspodman.DriverID,
		"dev.jywlabs.hal.sandbox.name":             containerName,
		"dev.jywlabs.hal.runtime.generation":       identity.RuntimeGenerationID,
		"dev.jywlabs.hal.topology.generation":      identity.TopologyGenerationID,
		"dev.jywlabs.hal.network-rules.generation": identity.RuleGenerationID,
	}
	for label, want := range wantLabels {
		if want == "" || payload[0].Config.Labels[label] != want {
			return "", errL7PodmanRestartCleanupUncertain
		}
	}
	exactID := payload[0].ID
	if _, err := run(ctx, podmanPath, "container", "rm", "--force", exactID); err != nil {
		return "", errL7PodmanRestartCleanupUncertain
	}
	return exactID, nil
}

func TestL7PodmanExactContainerCleanupReportsDeleteFailureAndStillProvesAbsence(t *testing.T) {
	deleteCalls := 0
	absenceCalls := 0
	deleteFailure := errors.New("delete endpoint=/run/user/1000/private.sock token=delete-secret")
	err := runL7PodmanExactContainerCleanup(true, func() error {
		deleteCalls++
		return deleteFailure
	}, func() error {
		absenceCalls++
		return nil
	})
	if !errors.Is(err, errL7PodmanExactContainerDeleteFailed) {
		t.Fatalf("cleanup error = %v, want reported exact-container delete failure", err)
	}
	if !errors.Is(err, deleteFailure) {
		t.Fatal("cleanup error discarded the exact-container delete error")
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
		l7PodmanExactContainerID,
		func(_ context.Context, executable string, args ...string) (int, error) {
			gotExecutable = executable
			gotArgs = append([]string(nil), args...)
			return 1, nil
		},
	)
	if err != nil {
		t.Fatalf("absence proof error: %v", err)
	}
	if gotExecutable != "/private/podman" || !reflect.DeepEqual(gotArgs, []string{"container", "exists", l7PodmanExactContainerID}) {
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
				context.Background(), "podman", l7PodmanExactContainerID,
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

func TestL7PodmanRestartFallbackCleanupRequiresExactOwnershipBeforeDelete(t *testing.T) {
	identity := rootlesspodman.NetworkTopologyIdentity{
		RuntimeGenerationID:  "runtime-generation-a",
		TopologyGenerationID: "topology-generation-a",
		RuleGenerationID:     "rule-generation-a",
	}
	containerName := "hal-l7-restart-a"
	inspectPayload := func(labels map[string]string) []byte {
		payload, err := json.Marshal([]map[string]any{{
			"Id": l7PodmanExactContainerID, "Name": "/" + containerName,
			"Config": map[string]any{"Labels": labels},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	matchingLabels := map[string]string{
		"dev.jywlabs.hal.runtime":                  rootlesspodman.DriverID,
		"dev.jywlabs.hal.sandbox.name":             containerName,
		"dev.jywlabs.hal.runtime.generation":       identity.RuntimeGenerationID,
		"dev.jywlabs.hal.topology.generation":      identity.TopologyGenerationID,
		"dev.jywlabs.hal.network-rules.generation": identity.RuleGenerationID,
	}

	var calls [][]string
	exactID, err := removeOwnedL7PodmanRestartContainerWithRunner(context.Background(), "/private/podman", containerName, identity, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 1 {
			return inspectPayload(matchingLabels), nil
		}
		return nil, nil
	})
	if err != nil || exactID != l7PodmanExactContainerID {
		t.Fatalf("owned cleanup = (%q, %v)", exactID, err)
	}
	wantCalls := [][]string{{"container", "inspect", containerName}, {"container", "rm", "--force", l7PodmanExactContainerID}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("owned cleanup calls = %#v, want %#v", calls, wantCalls)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "unrelated runtime", mutate: func(labels map[string]string) { labels["dev.jywlabs.hal.runtime"] = "other" }},
		{name: "sandbox collision", mutate: func(labels map[string]string) { labels["dev.jywlabs.hal.sandbox.name"] = "other" }},
		{name: "runtime generation collision", mutate: func(labels map[string]string) { labels["dev.jywlabs.hal.runtime.generation"] = "other" }},
		{name: "topology generation collision", mutate: func(labels map[string]string) { labels["dev.jywlabs.hal.topology.generation"] = "other" }},
		{name: "rule generation collision", mutate: func(labels map[string]string) { labels["dev.jywlabs.hal.network-rules.generation"] = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			labels := make(map[string]string, len(matchingLabels))
			for key, value := range matchingLabels {
				labels[key] = value
			}
			test.mutate(labels)
			callCount := 0
			_, err := removeOwnedL7PodmanRestartContainerWithRunner(context.Background(), "podman", containerName, identity, func(context.Context, string, ...string) ([]byte, error) {
				callCount++
				return inspectPayload(labels), nil
			})
			if !errors.Is(err, errL7PodmanRestartCleanupUncertain) || callCount != 1 {
				t.Fatalf("collision cleanup = (%v, %d calls), want uncertainty without delete", err, callCount)
			}
		})
	}
}
