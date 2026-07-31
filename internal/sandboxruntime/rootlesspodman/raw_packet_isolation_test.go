package rootlesspodman_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

const testRawPacketPID = 4242

var _ linuxrules.RawPacketIsolationVerifier = (*rootlesspodman.PodmanRawPacketIsolationVerifier)(nil)

func TestL7PodmanRawPacketVerifierUsesExactInspectAndHostProcEvidence(t *testing.T) {
	runner := &rawPacketInspectRunner{outputs: []string{validRawPacketInspectJSON(), validRawPacketInspectJSON()}}
	process := &rawPacketProcessInspector{}
	verifier := newRawPacketVerifier(runner, process, func() time.Time {
		return time.UnixMilli(1777777777000)
	})
	correlation := testRawPacketCorrelation()

	proof, err := verifier.VerifyRawPacketIsolation(context.Background(), correlation)
	if err != nil {
		t.Fatalf("VerifyRawPacketIsolation() unexpected error: %v", err)
	}
	if !networkenforcement.RawPacketIsolationProofMatches(proof, correlation) {
		t.Fatalf("proof = %#v, want exact correlated verified proof", proof)
	}
	if proof.VerifiedAtUnixMilli != 1777777777000 || proof.Correlation == nil || *proof.Correlation != correlation {
		t.Fatalf("proof timestamp/correlation = %#v, want injected positive time and exact identity", proof)
	}
	if process.calls != 1 || process.pid != testRawPacketPID {
		t.Fatalf("host proc inspection = calls:%d pid:%d, want one exact init-pid inspection", process.calls, process.pid)
	}
	wantArgs := []string{"podman", "inspect", "--type", "container", testContainerID}
	if len(runner.requests) != 2 {
		t.Fatalf("Podman inspect calls = %d, want before and after host proc inspection", len(runner.requests))
	}
	for _, request := range runner.requests {
		if request.Operation != rootlesspodman.OperationInspect || !reflect.DeepEqual(request.Args, wantArgs) {
			t.Fatalf("inspect request = %#v, want exact container-only inspection %#v", request, wantArgs)
		}
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("json.Marshal(proof) error: %v", err)
	}
	for _, forbidden := range []string{"4242", "/proc", "StartedAt", "EffectiveCaps", "hostname", "endpoint"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("proof leaked private runtime evidence %q: %s", forbidden, encoded)
		}
	}
}

func TestL7PodmanRawPacketVerifierRunsBeforeLinuxRulesMutationWhenComposed(t *testing.T) {
	correlation := testRawPacketCorrelation()
	verifier := newRawPacketVerifier(
		&rawPacketInspectRunner{outputs: []string{validRawPacketInspectJSON()}},
		&rawPacketProcessInspector{err: errors.New("seeded private proc failure")},
		positiveRawPacketTime,
	)
	expected, err := linuxrules.NewExpectedRuleSet(linuxrules.RuleSetConfig{
		Correlation:         correlation,
		Profile:             linuxrules.RuleProfileWorkloadOutput,
		Namespace:           linuxrules.NewNamespaceHandle(10, 11),
		TableName:           "hal_l7_podman",
		InterfaceName:       "eth0",
		ProxyAddress:        "192.0.2.10",
		ProxyPort:           3128,
		RawPacketIsolation:  verifier,
		WorkloadIPv6Address: "fd00:7::2",
		GatewayIPv6Address:  "fd00:7::1",
		IPv6PrefixBits:      64,
	})
	if err != nil {
		t.Fatalf("NewExpectedRuleSet() unexpected error: %v", err)
	}
	executor := &panicLinuxRulesExecutor{}
	adapter := linuxrules.NewAdapter(executor, linuxrules.AdapterOptions{Now: positiveRawPacketTime})
	if _, err := adapter.ApplyAndInspect(context.Background(), expected); !errors.Is(err, linuxrules.ErrRawPacketIsolation) {
		t.Fatalf("ApplyAndInspect() error = %v, want raw-packet proof rejection before mutation", err)
	}
}

func TestL7PodmanRawPacketVerifierIgnoresPodmanEffectiveCapsAndFailsOnHostProc(t *testing.T) {
	t.Run("null EffectiveCaps is not treated as missing proof", func(t *testing.T) {
		runner := &rawPacketInspectRunner{outputs: []string{validRawPacketInspectJSON(), validRawPacketInspectJSON()}}
		process := &rawPacketProcessInspector{}
		if _, err := newRawPacketVerifier(runner, process, positiveRawPacketTime).VerifyRawPacketIsolation(context.Background(), testRawPacketCorrelation()); err != nil {
			t.Fatalf("VerifyRawPacketIsolation() with null EffectiveCaps unexpected error: %v", err)
		}
	})

	t.Run("labels and requested config alone cannot prove isolation", func(t *testing.T) {
		seeded := errors.New("/proc/4242/status token=private must not escape")
		process := &rawPacketProcessInspector{err: seeded}
		verifier := newRawPacketVerifier(&rawPacketInspectRunner{outputs: []string{validRawPacketInspectJSON()}}, process, positiveRawPacketTime)
		if _, err := verifier.VerifyRawPacketIsolation(context.Background(), testRawPacketCorrelation()); !errors.Is(err, rootlesspodman.ErrRawPacketIsolationUnverified) {
			t.Fatalf("VerifyRawPacketIsolation() error = %v, want sanitized fail-closed sentinel", err)
		} else if errors.Is(err, seeded) {
			t.Fatalf("VerifyRawPacketIsolation() retained injected private error: %v", err)
		} else if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "/proc") || strings.Contains(err.Error(), "private") {
			t.Fatalf("VerifyRawPacketIsolation() leaked injected process error: %v", err)
		}
	})
}

func TestL7PodmanRawPacketVerifierRejectsInspectIdentityStateAndConfigDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "container ID", mutate: func(value map[string]any) { value["Id"] = "different-container" }},
		{name: "container name", mutate: func(value map[string]any) { value["Name"] = "different-name" }},
		{name: "stopped", mutate: func(value map[string]any) { value["State"].(map[string]any)["Running"] = false }},
		{name: "non-running status", mutate: func(value map[string]any) { value["State"].(map[string]any)["Status"] = "configured" }},
		{name: "missing PID", mutate: func(value map[string]any) { value["State"].(map[string]any)["Pid"] = 0 }},
		{name: "missing start identity", mutate: func(value map[string]any) { value["State"].(map[string]any)["StartedAt"] = "" }},
		{name: "runtime label", mutate: func(value map[string]any) {
			value["Config"].(map[string]any)["Labels"].(map[string]any)["dev.jywlabs.hal.runtime"] = "other"
		}},
		{name: "sandbox label", mutate: func(value map[string]any) {
			value["Config"].(map[string]any)["Labels"].(map[string]any)["dev.jywlabs.hal.sandbox.name"] = "other"
		}},
		{name: "topology generation", mutate: func(value map[string]any) {
			value["Config"].(map[string]any)["Labels"].(map[string]any)["dev.jywlabs.hal.topology.generation"] = "other"
		}},
		{name: "runtime generation", mutate: func(value map[string]any) {
			value["Config"].(map[string]any)["Labels"].(map[string]any)["dev.jywlabs.hal.runtime.generation"] = "other"
		}},
		{name: "rule generation", mutate: func(value map[string]any) {
			value["Config"].(map[string]any)["Labels"].(map[string]any)["dev.jywlabs.hal.network-rules.generation"] = "other"
		}},
		{name: "privileged", mutate: func(value map[string]any) { value["HostConfig"].(map[string]any)["Privileged"] = true }},
		{name: "host network", mutate: func(value map[string]any) { value["HostConfig"].(map[string]any)["NetworkMode"] = "host" }},
		{name: "cap add raw", mutate: func(value map[string]any) { value["HostConfig"].(map[string]any)["CapAdd"] = []any{"CAP_NET_RAW"} }},
		{name: "cap add admin", mutate: func(value map[string]any) { value["HostConfig"].(map[string]any)["CapAdd"] = []any{"CAP_NET_ADMIN"} }},
		{name: "missing all-cap drop", mutate: func(value map[string]any) { value["HostConfig"].(map[string]any)["CapDrop"] = []any{} }},
		{name: "missing no-new-privileges", mutate: func(value map[string]any) { value["HostConfig"].(map[string]any)["SecurityOpt"] = []any{} }},
		{name: "Podman socket bind", mutate: func(value map[string]any) {
			value["HostConfig"].(map[string]any)["Binds"] = []any{"/run/podman/podman.sock:/run/podman/podman.sock"}
		}},
		{name: "Docker socket mount", mutate: func(value map[string]any) {
			value["Mounts"] = []any{map[string]any{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process := &rawPacketProcessInspector{panicOnCall: true}
			verifier := newRawPacketVerifier(&rawPacketInspectRunner{outputs: []string{mutatedRawPacketInspectJSON(t, tt.mutate)}}, process, positiveRawPacketTime)
			if _, err := verifier.VerifyRawPacketIsolation(context.Background(), testRawPacketCorrelation()); !errors.Is(err, rootlesspodman.ErrRawPacketIsolationUnverified) {
				t.Fatalf("VerifyRawPacketIsolation() error = %v, want fail-closed sentinel", err)
			}
		})
	}
}

func TestL7PodmanRawPacketVerifierRejectsRestartPIDReuseAndCrossGeneration(t *testing.T) {
	tests := []struct {
		name   string
		second func(map[string]any)
	}{
		{name: "PID drift", second: func(value map[string]any) { value["State"].(map[string]any)["Pid"] = testRawPacketPID + 1 }},
		{name: "restart drift", second: func(value map[string]any) { value["State"].(map[string]any)["StartedAt"] = "2026-08-01T00:00:01Z" }},
		{name: "stopped after proc read", second: func(value map[string]any) { value["State"].(map[string]any)["Running"] = false }},
		{name: "cross-generation label", second: func(value map[string]any) {
			value["Config"].(map[string]any)["Labels"].(map[string]any)["dev.jywlabs.hal.runtime.generation"] = "runtime-generation-b"
		}},
		{name: "config changed", second: func(value map[string]any) { value["HostConfig"].(map[string]any)["CapDrop"] = []any{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &rawPacketInspectRunner{outputs: []string{validRawPacketInspectJSON(), mutatedRawPacketInspectJSON(t, tt.second)}}
			verifier := newRawPacketVerifier(runner, &rawPacketProcessInspector{}, positiveRawPacketTime)
			if _, err := verifier.VerifyRawPacketIsolation(context.Background(), testRawPacketCorrelation()); !errors.Is(err, rootlesspodman.ErrRawPacketIsolationUnverified) {
				t.Fatalf("VerifyRawPacketIsolation() error = %v, want restart/drift rejection", err)
			}
		})
	}
}

func TestL7PodmanRawPacketVerifierRejectsMalformedOversizedErrorsCorrelationAndTime(t *testing.T) {
	tests := []struct {
		name        string
		outputs     []string
		runnerErr   error
		correlation networkenforcement.EnforcementCorrelation
		now         func() time.Time
	}{
		{name: "missing inspect", outputs: []string{"[]"}, correlation: testRawPacketCorrelation(), now: positiveRawPacketTime},
		{name: "duplicate inspect", outputs: []string{"[" + strings.TrimSuffix(strings.TrimPrefix(validRawPacketInspectJSON(), "["), "]") + "," + strings.TrimSuffix(strings.TrimPrefix(validRawPacketInspectJSON(), "["), "]") + "]"}, correlation: testRawPacketCorrelation(), now: positiveRawPacketTime},
		{name: "malformed inspect", outputs: []string{"[{"}, correlation: testRawPacketCorrelation(), now: positiveRawPacketTime},
		{name: "oversized inspect", outputs: []string{strings.Repeat("x", 300<<10)}, correlation: testRawPacketCorrelation(), now: positiveRawPacketTime},
		{name: "injected inspect error", runnerErr: errors.New("podman endpoint=/run/user/1000/private.sock token=secret"), correlation: testRawPacketCorrelation(), now: positiveRawPacketTime},
		{name: "correlation mismatch", outputs: []string{validRawPacketInspectJSON()}, correlation: func() networkenforcement.EnforcementCorrelation {
			value := testRawPacketCorrelation()
			value.TopologyGenerationID = "other-generation"
			return value
		}(), now: positiveRawPacketTime},
		{name: "zero time", outputs: []string{validRawPacketInspectJSON(), validRawPacketInspectJSON()}, correlation: testRawPacketCorrelation(), now: func() time.Time { return time.UnixMilli(0) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process := &rawPacketProcessInspector{}
			verifier := newRawPacketVerifier(&rawPacketInspectRunner{outputs: tt.outputs, err: tt.runnerErr}, process, tt.now)
			if _, err := verifier.VerifyRawPacketIsolation(context.Background(), tt.correlation); !errors.Is(err, rootlesspodman.ErrRawPacketIsolationUnverified) {
				t.Fatalf("VerifyRawPacketIsolation() error = %v, want fail-closed sentinel", err)
			} else {
				for _, forbidden := range []string{"/run/user", "private.sock", "token=secret"} {
					if strings.Contains(err.Error(), forbidden) {
						t.Fatalf("VerifyRawPacketIsolation() leaked %q: %v", forbidden, err)
					}
				}
			}
		})
	}
}

func TestL7PodmanRawPacketVerifierRejectsInvalidConstructionWithoutInspecting(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*rootlesspodman.PodmanRawPacketIsolationVerifierOptions)
	}{
		{name: "nil runner", mutate: func(options *rootlesspodman.PodmanRawPacketIsolationVerifierOptions) { options.LifecycleRunner = nil }},
		{name: "unsafe identity", mutate: func(options *rootlesspodman.PodmanRawPacketIsolationVerifierOptions) {
			options.Identity.RuntimeGenerationID = "/proc/private"
		}},
		{name: "target prefix", mutate: func(options *rootlesspodman.PodmanRawPacketIsolationVerifierOptions) { options.Target.ID = "container" }},
		{name: "wrong runtime driver", mutate: func(options *rootlesspodman.PodmanRawPacketIsolationVerifierOptions) {
			options.Target.Runtime.Driver = sandboxruntime.DriverSSHMachine
		}},
		{name: "negative bound", mutate: func(options *rootlesspodman.PodmanRawPacketIsolationVerifierOptions) { options.MaxInspectBytes = -1 }},
		{name: "excessive bound", mutate: func(options *rootlesspodman.PodmanRawPacketIsolationVerifierOptions) {
			options.MaxInspectBytes = 257 << 10
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &rawPacketInspectRunner{}
			options := validRawPacketVerifierOptions(runner, &rawPacketProcessInspector{panicOnCall: true}, positiveRawPacketTime)
			tt.mutate(&options)
			verifier := rootlesspodman.NewPodmanRawPacketIsolationVerifier(options)
			if _, err := verifier.VerifyRawPacketIsolation(context.Background(), testRawPacketCorrelation()); !errors.Is(err, rootlesspodman.ErrRawPacketIsolationUnverified) {
				t.Fatalf("VerifyRawPacketIsolation() error = %v, want invalid-construction rejection", err)
			}
			if len(runner.requests) != 0 {
				t.Fatalf("invalid verifier reached Podman inspect: %#v", runner.requests)
			}
		})
	}
}

func newRawPacketVerifier(runner rootlesspodman.LifecycleCommandRunner, process rootlesspodman.RawPacketProcessInspector, now func() time.Time) *rootlesspodman.PodmanRawPacketIsolationVerifier {
	return rootlesspodman.NewPodmanRawPacketIsolationVerifier(validRawPacketVerifierOptions(runner, process, now))
}

func validRawPacketVerifierOptions(runner rootlesspodman.LifecycleCommandRunner, process rootlesspodman.RawPacketProcessInspector, now func() time.Time) rootlesspodman.PodmanRawPacketIsolationVerifierOptions {
	return rootlesspodman.PodmanRawPacketIsolationVerifierOptions{
		LifecycleRunner:  runner,
		ProcessInspector: process,
		Identity:         testNetworkTopologyIdentity(),
		Target: sandboxruntime.Target{
			ID: testContainerID, Name: "hal-l7", Runtime: sandboxruntime.RuntimeState{
				Driver: sandboxruntime.DriverRootlessPodman, RuntimeID: testContainerID,
			},
		},
		Now: now,
	}
}

func testRawPacketCorrelation() networkenforcement.EnforcementCorrelation {
	identity := testNetworkTopologyIdentity()
	return networkenforcement.EnforcementCorrelation{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
}

func positiveRawPacketTime() time.Time { return time.UnixMilli(1777777777000) }

func validRawPacketInspectJSON() string {
	value := map[string]any{
		"Id":   testContainerID,
		"Name": "hal-l7",
		"State": map[string]any{
			"Running": true, "Status": "running", "Pid": testRawPacketPID, "StartedAt": "2026-08-01T00:00:00Z",
		},
		"Config": map[string]any{"Labels": map[string]any{
			"dev.jywlabs.hal.runtime":                  sandboxruntime.DriverRootlessPodman,
			"dev.jywlabs.hal.sandbox.name":             "hal-l7",
			"dev.jywlabs.hal.topology.generation":      "topology-generation-a",
			"dev.jywlabs.hal.runtime.generation":       "runtime-generation-a",
			"dev.jywlabs.hal.network-rules.generation": "rule-generation-a",
		}},
		"HostConfig": map[string]any{
			"Privileged": false, "NetworkMode": "pasta", "CapAdd": []any{}, "CapDrop": []any{"CAP_ALL"},
			"SecurityOpt": []any{"no-new-privileges"}, "Binds": []any{},
		},
		"EffectiveCaps": nil,
		"Mounts":        []any{},
	}
	payload, err := json.Marshal([]any{value})
	if err != nil {
		panic(err)
	}
	return string(payload)
}

func mutatedRawPacketInspectJSON(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	var values []map[string]any
	if err := json.Unmarshal([]byte(validRawPacketInspectJSON()), &values); err != nil {
		t.Fatalf("decode inspect fixture: %v", err)
	}
	mutate(values[0])
	payload, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("encode inspect fixture: %v", err)
	}
	return string(payload)
}

type rawPacketInspectRunner struct {
	requests []rootlesspodman.CommandRequest
	outputs  []string
	err      error
}

func (r *rawPacketInspectRunner) RunLifecycleCommand(_ context.Context, request rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	if request.Operation != rootlesspodman.OperationInspect {
		panic(fmt.Sprintf("forbidden raw-packet trust shortcut used operation %q", request.Operation))
	}
	r.requests = append(r.requests, request)
	if r.err != nil {
		return rootlesspodman.CommandResult{Stdout: "private inspect output", Stderr: "private inspect error"}, r.err
	}
	if len(r.outputs) == 0 {
		return rootlesspodman.CommandResult{}, nil
	}
	output := r.outputs[0]
	r.outputs = r.outputs[1:]
	return rootlesspodman.CommandResult{Stdout: output}, nil
}

type rawPacketProcessInspector struct {
	calls       int
	pid         int
	err         error
	panicOnCall bool
}

type panicLinuxRulesExecutor struct{}

func (*panicLinuxRulesExecutor) ApplyBatch(context.Context, linuxrules.NamespaceHandle, []byte) error {
	panic("linuxrules mutated before raw-packet capability proof")
}

func (*panicLinuxRulesExecutor) ListTableJSON(context.Context, linuxrules.NamespaceHandle, linuxrules.TableQuery, int64) ([]byte, error) {
	panic("linuxrules inspected or mutated before raw-packet capability proof")
}

func (p *rawPacketProcessInspector) VerifyRawPacketProcess(_ context.Context, pid int, _ int64) error {
	if p.panicOnCall {
		panic("host proc inspection reached after invalid Podman evidence")
	}
	p.calls++
	p.pid = pid
	return p.err
}
