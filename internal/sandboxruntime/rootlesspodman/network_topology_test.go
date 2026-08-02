package rootlesspodman_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

const (
	testContainerID   = "container-generation-a"
	testProxyEndpoint = "http://169.254.77.2:31077"
)

func TestL7PodmanTopologySequencesCreateActivationInspectionAndExec(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	factory := &fakeNetworkTopologyFactory{
		sequence: sequence,
		preparation: rootlesspodman.NetworkTopologyPreparation{
			Identity:   testNetworkTopologyIdentity(),
			CreateArgs: testPastaCreateArgs(),
			Session:    session,
		},
	}
	runner := &topologyCommandRunner{sequence: sequence}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner:        runner,
		ExecRunner:             runner,
		NetworkTopologyFactory: factory,
	})

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if created.Runtime.Metadata != nil && created.Runtime.Metadata.NetworkEnforcement != nil {
		t.Fatalf("Create() projected network proof before activation: %#v", created.Runtime.Metadata.NetworkEnforcement)
	}
	createArgs := runner.lifecycleRequests[0].Args
	assertExplicitSafePastaCreateArgs(t, createArgs)
	if !containsArg(createArgs, "--cap-drop=ALL") {
		t.Fatalf("Create() args = %#v, want explicit all-capability drop", createArgs)
	}
	if !containsArgPair(createArgs, "--label", "dev.jywlabs.hal.topology.generation=topology-generation-a") {
		t.Fatalf("Create() args = %#v, want safe topology-generation label", createArgs)
	}

	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: *created,
		Args:   []string{"true"},
	}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyInactive) {
		t.Fatalf("Exec() before Start error = %v, want ErrNetworkTopologyInactive", err)
	}
	if len(runner.execRequests) != 0 {
		t.Fatalf("Exec() reached command runner before active proof: %#v", runner.execRequests)
	}

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	assertAdvisoryActiveNetworkProof(t, started)

	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: *started,
		Args:   []string{"hal", "status"},
		Env: map[string]string{
			"NO_PROXY":  "unsafe-bypass.example",
			"ALL_PROXY": "socks5://unsafe.example:1080",
			"HAL_SAFE":  "1",
		},
	}); err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	request := runner.execRequests[0]
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if request.Env[key] != testProxyEndpoint {
			t.Fatalf("Exec() %s = %q, want live proxy endpoint", key, request.Env[key])
		}
	}
	for _, key := range []string{"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"} {
		if _, ok := request.Env[key]; ok {
			t.Fatalf("Exec() preserved uncontrolled bypass variable %q", key)
		}
	}
	if request.Env["HAL_SAFE"] != "1" {
		t.Fatalf("Exec() lost caller environment: %#v", request.Env)
	}
	if strings.Contains(strings.Join(request.Args, "\x00"), testProxyEndpoint) {
		t.Fatalf("Exec() persisted live endpoint in argv: %#v", request.Args)
	}
	encoded, err := json.Marshal(started)
	if err != nil {
		t.Fatalf("json.Marshal(started) error: %v", err)
	}
	if strings.Contains(string(encoded), "169.254.77.2") || strings.Contains(string(encoded), "31077") {
		t.Fatalf("runtime metadata persisted live endpoint: %s", encoded)
	}

	wantSequence := []string{"prepare", "podman_create", "podman_start", "activate", "inspect", "inspect", "podman_exec"}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, wantSequence) {
		t.Fatalf("operation sequence = %#v, want %#v", got, wantSequence)
	}
}

func TestL7PodmanTopologyRejectsUnsafeIdentityAndCreateArgsBeforePodman(t *testing.T) {
	tests := []struct {
		name       string
		identity   rootlesspodman.NetworkTopologyIdentity
		createArgs []string
	}{
		{name: "unsafe identity", identity: func() rootlesspodman.NetworkTopologyIdentity {
			identity := testNetworkTopologyIdentity()
			identity.TopologyGenerationID = "https://unsafe.example/generation"
			return identity
		}(), createArgs: testPastaCreateArgs()},
		{name: "host network", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "host"}},
		{name: "default network", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "bridge"}},
		{name: "wildcard mapping", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=0.0.0.0,-t,none,-u,none,-T,none,-U,none"}},
		{name: "guest address translation", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-guest-addr=169.254.77.2,-t,none,-u,none,-T,none,-U,none"}},
		{name: "IPv4-only mapping", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=169.254.77.2,--ipv4-only,-t,none,-u,none,-T,none,-U,none"}},
		{name: "IPv6-only mapping", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=fd00::77:2,--ipv6-only,-t,none,-u,none,-T,none,-U,none"}},
		{name: "privileged", identity: testNetworkTopologyIdentity(), createArgs: append(testPastaCreateArgs(), "--privileged")},
		{name: "net admin", identity: testNetworkTopologyIdentity(), createArgs: append(testPastaCreateArgs(), "--cap-add=NET_ADMIN")},
		{name: "socket mount", identity: testNetworkTopologyIdentity(), createArgs: append(testPastaCreateArgs(), "--volume", "/run/podman/podman.sock:/run/podman/podman.sock")},
		{name: "automatic host-to-namespace TCP forwarding", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=169.254.77.2,-t,auto,-u,none,-T,none,-U,none"}},
		{name: "missing namespace-to-init forwarding controls", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=169.254.77.2,-t,none,-u,none"}},
		{name: "automatic namespace-to-init TCP forwarding", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=169.254.77.2,-t,none,-u,none,-T,auto,-U,none"}},
		{name: "automatic namespace-to-init UDP forwarding", identity: testNetworkTopologyIdentity(), createArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=169.254.77.2,-t,none,-u,none,-T,none,-U,auto"}},
		{name: "publish", identity: testNetworkTopologyIdentity(), createArgs: append(testPastaCreateArgs(), "--publish-all")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &topologyCommandRunner{}
			session := newFakeNetworkTopologySession(nil)
			driver := rootlesspodman.New(rootlesspodman.Options{
				LifecycleRunner: runner,
				NetworkTopologyFactory: &fakeNetworkTopologyFactory{preparation: rootlesspodman.NetworkTopologyPreparation{
					Identity: tt.identity, CreateArgs: tt.createArgs, Session: session,
				}},
			})

			if _, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"}); err == nil {
				t.Fatal("Create() error = nil, want fail-closed validation")
			}
			if len(runner.lifecycleRequests) != 0 {
				t.Fatalf("Create() reached Podman for invalid topology: %#v", runner.lifecycleRequests)
			}
			_, _, _, cleanupCalls, _, _ := session.callState()
			if cleanupCalls != 1 {
				t.Fatalf("invalid prepared session cleanup calls = %d, want 1", cleanupCalls)
			}
		})
	}
}

func TestL7PodmanTopologyAcceptsBoundedDualStackPastaMapping(t *testing.T) {
	tests := []struct {
		name  string
		guest string
		proxy string
	}{
		{name: "IPv4 proxy tuple", guest: "169.254.77.2", proxy: "http://169.254.77.2:31077"},
		{name: "IPv6 proxy tuple", guest: "fd00::77:2", proxy: "http://[fd00::77:2]:31077"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newFakeNetworkTopologySession(nil)
			session.proxyEnv = proxyEnvironment(tt.proxy)
			runner := &topologyCommandRunner{}
			driver := rootlesspodman.New(rootlesspodman.Options{
				LifecycleRunner: runner,
				ExecRunner:      runner,
				NetworkTopologyFactory: &fakeNetworkTopologyFactory{preparation: rootlesspodman.NetworkTopologyPreparation{
					Identity: testNetworkTopologyIdentity(), CreateArgs: testPastaCreateArgsFor(tt.guest), Session: session,
				}},
			})

			created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
			if err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
			createdArgs := runner.lifecycleRequests[0].Args
			if !containsArgPair(createdArgs, "--network", testPastaCreateArgsFor(tt.guest)[1]) {
				t.Fatalf("Create() args = %#v, want bounded pasta mapping", createdArgs)
			}
			if joined := strings.Join(createdArgs, "\x00"); strings.Contains(joined, "--ipv4-only") || strings.Contains(joined, "--ipv6-only") {
				t.Fatalf("Create() args = %#v, want both address families available for default-drop enforcement", createdArgs)
			}
			started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
			if err != nil {
				t.Fatalf("Start() unexpected error: %v", err)
			}
			if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: *started, Args: []string{"true"}}); err != nil {
				t.Fatalf("Exec() unexpected error: %v", err)
			}
		})
	}
}

func TestL7PodmanTopologyRetainsUnregisteredSessionCleanupAuthority(t *testing.T) {
	session := newFakeNetworkTopologySession(nil)
	session.cleanupErr = errors.New("private transient cleanup failure")
	identity := testNetworkTopologyIdentity()
	identity.TopologyGenerationID = "https://unsafe.example/generation"
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: &topologyCommandRunner{},
		NetworkTopologyFactory: &fakeNetworkTopologyFactory{preparation: rootlesspodman.NetworkTopologyPreparation{
			Identity: identity, CreateArgs: testPastaCreateArgs(), Session: session,
		}},
	})

	if _, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"}); err == nil {
		t.Fatal("Create() error = nil, want fail-closed topology validation")
	}
	_, _, _, cleanupCalls, _, _ := session.callState()
	if cleanupCalls != 1 {
		t.Fatalf("initial unregistered cleanup calls = %d, want 1", cleanupCalls)
	}
	retrier, ok := any(driver).(interface {
		RetryNetworkTopologyCleanup(context.Context) error
	})
	if !ok {
		t.Fatal("driver discarded unregistered topology cleanup authority")
	}
	session.cleanupErr = nil
	if err := retrier.RetryNetworkTopologyCleanup(context.Background()); err != nil {
		t.Fatalf("RetryNetworkTopologyCleanup() error = %v", err)
	}
	_, _, _, cleanupCalls, _, _ = session.callState()
	if cleanupCalls != 2 {
		t.Fatalf("retained unregistered cleanup calls = %d, want 2", cleanupCalls)
	}
}

func TestL7PodmanTopologyActivationFailureRollsBackInReverseOrder(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	session.activateErr = errors.New("raw endpoint 169.254.77.2:31077 must not escape")
	runner := &topologyCommandRunner{sequence: sequence}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner,
		NetworkTopologyFactory: &fakeNetworkTopologyFactory{
			sequence: sequence,
			preparation: rootlesspodman.NetworkTopologyPreparation{
				Identity: testNetworkTopologyIdentity(), CreateArgs: testPastaCreateArgs(), Session: session,
			},
		},
	})

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created}); err == nil {
		t.Fatal("Start() error = nil, want activation failure")
	} else if strings.Contains(err.Error(), "169.254.77.2") || strings.Contains(err.Error(), "31077") {
		t.Fatalf("Start() error leaked live endpoint: %v", err)
	}
	want := []string{"prepare", "podman_create", "podman_start", "activate", "revoke", "podman_stop", "cleanup"}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback sequence = %#v, want %#v", got, want)
	}
}

func TestL7PodmanTopologyPodmanStartFailureStillRevokesStopsAndCleans(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	runner := &topologyCommandRunner{sequence: sequence, errByOperation: map[string]error{
		rootlesspodman.OperationStart: errors.New("start failed"),
	}}
	driver := newTopologyDriver(runner, session, sequence)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created}); err == nil {
		t.Fatal("Start() error = nil, want Podman start failure")
	}
	want := []string{"prepare", "podman_create", "podman_start", "revoke", "podman_stop", "cleanup"}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("start failure rollback sequence = %#v, want %#v", got, want)
	}
}

func TestL7PodmanTopologyRejectsMismatchedProofAndRuntimeGeneration(t *testing.T) {
	t.Run("proof identity mismatch", func(t *testing.T) {
		session := newFakeNetworkTopologySession(nil)
		session.proof.Identity.RuleGenerationID = "different-rule-generation"
		driver, created, runner := createPreparedTopologyDriver(t, session)
		if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyProofMismatch) {
			t.Fatalf("Start() error = %v, want ErrNetworkTopologyProofMismatch", err)
		}
		if got := runner.lifecycleOperations(); !reflect.DeepEqual(got, []string{rootlesspodman.OperationCreate, rootlesspodman.OperationStart, rootlesspodman.OperationStop}) {
			t.Fatalf("lifecycle operations = %#v, want reverse stop after proof mismatch", got)
		}
	})

	t.Run("runtime generation mismatch", func(t *testing.T) {
		session := newFakeNetworkTopologySession(nil)
		driver, created, runner := createPreparedTopologyDriver(t, session)
		started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
		if err != nil {
			t.Fatalf("Start() unexpected error: %v", err)
		}
		started.Runtime.RuntimeID = "different-container-generation"
		if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: *started, Args: []string{"true"}}); !errors.Is(err, rootlesspodman.ErrNetworkTopologySessionMissing) {
			t.Fatalf("Exec() error = %v, want exact-generation ErrNetworkTopologySessionMissing", err)
		}
		if len(runner.execRequests) != 0 {
			t.Fatalf("Exec() reached Podman with mismatched runtime generation: %#v", runner.execRequests)
		}
	})
}

func TestL7PodmanTopologyProxyLossRevokesProofAndBlocksExec(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	runner := &topologyCommandRunner{sequence: sequence}
	driver := newTopologyDriver(runner, session, sequence)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	close(session.loss)

	deadline := time.Now().Add(time.Second)
	for {
		_, _, revokeCalls, cleanupCalls, _, _ := session.callState()
		if revokeCalls > 0 && cleanupCalls > 0 || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_, _, revokeCalls, cleanupCalls, revokeContextErr, cleanupContextErr := session.callState()
	if revokeCalls != 1 {
		t.Fatalf("proxy loss revoke calls = %d, want 1", revokeCalls)
	}
	if cleanupCalls != 1 {
		t.Fatalf("proxy loss cleanup calls = %d, want 1 after runtime quiesce", cleanupCalls)
	}
	if revokeContextErr != nil || cleanupContextErr != nil {
		t.Fatalf("proxy loss contexts = revoke:%v cleanup:%v, want independent live contexts", revokeContextErr, cleanupContextErr)
	}
	wantSuffix := []string{"revoke", "podman_stop", "cleanup"}
	got := sequence.snapshot()
	if !reflect.DeepEqual(got[len(got)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("proxy loss sequence = %#v, want suffix %#v", got, wantSuffix)
	}
	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: *started, Args: []string{"true"}}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyInactive) {
		t.Fatalf("Exec() after proxy loss error = %v, want ErrNetworkTopologyInactive", err)
	}
	if len(runner.execRequests) != 0 {
		t.Fatalf("Exec() reached Podman after proxy loss: %#v", runner.execRequests)
	}
	beforeRestart := runner.lifecycleOperations()
	if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); !errors.Is(err, rootlesspodman.ErrNetworkTopologySessionMissing) {
		t.Fatalf("Start() after proxy loss error = %v, want fresh-session ErrNetworkTopologySessionMissing", err)
	}
	if afterRestart := runner.lifecycleOperations(); !reflect.DeepEqual(afterRestart, beforeRestart) {
		t.Fatalf("Start() after proxy loss reached Podman: before=%#v after=%#v", beforeRestart, afterRestart)
	}
}

func TestL7PodmanTopologyStopRevokesBeforePodmanAndCleansWithIndependentContext(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	runner := &topologyCommandRunner{sequence: sequence}
	driver := newTopologyDriver(runner, session, sequence)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := driver.Stop(canceled, sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}
	wantSuffix := []string{"revoke", "podman_stop", "cleanup"}
	got := sequence.snapshot()
	if !reflect.DeepEqual(got[len(got)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("Stop() sequence = %#v, want suffix %#v", got, wantSuffix)
	}
	_, _, _, _, revokeContextErr, cleanupContextErr := session.callState()
	if revokeContextErr != nil || cleanupContextErr != nil {
		t.Fatalf("cleanup contexts = revoke:%v cleanup:%v, want independent live contexts", revokeContextErr, cleanupContextErr)
	}

	before := len(sequence.snapshot())
	if _, err := driver.Stop(canceled, sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("second Stop() unexpected error: %v", err)
	}
	after := sequence.snapshot()[before:]
	if !reflect.DeepEqual(after, []string{"podman_stop"}) {
		t.Fatalf("second Stop() operations = %#v, want idempotent Podman stop only", after)
	}
}

func TestL7PodmanTopologyDeleteRevokesBeforeRemovalAndCleansAfterRuntimeQuiesce(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	runner := &topologyCommandRunner{sequence: sequence}
	driver := newTopologyDriver(runner, session, sequence)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}
	wantSuffix := []string{"revoke", "podman_delete", "cleanup"}
	got := sequence.snapshot()
	if !reflect.DeepEqual(got[len(got)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("Delete() sequence = %#v, want suffix %#v", got, wantSuffix)
	}
}

func TestL7PodmanTopologyDeleteCleanupRetryDoesNotRepeatSuccessfulRuntimeDelete(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	session.cleanupErr = errors.New("transient cleanup failure from /tmp/private-topology")
	runner := &topologyCommandRunner{sequence: sequence}
	driver := newTopologyDriver(runner, session, sequence)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyCleanupFailed) {
		t.Fatalf("first Delete() error = %v, want retained cleanup failure", err)
	} else if strings.Contains(err.Error(), "private-topology") {
		t.Fatalf("first Delete() error leaked cleanup detail: %v", err)
	}
	if got, want := sequence.snapshot()[len(sequence.snapshot())-3:], []string{"revoke", "podman_delete", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first Delete() sequence = %#v, want %#v", got, want)
	}

	session.mu.Lock()
	session.cleanupErr = nil
	session.mu.Unlock()
	retryStart := len(sequence.snapshot())
	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("retry Delete() unexpected error: %v", err)
	}
	if got, want := sequence.snapshot()[retryStart:], []string{"revoke", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry Delete() sequence = %#v, want retained cleanup without Podman delete %#v", got, want)
	}
	if got := countOperation(runner.lifecycleOperations(), rootlesspodman.OperationDelete); got != 1 {
		t.Fatalf("Podman delete calls = %d, want exactly one after successful runtime removal", got)
	}

	revokeRequests, cleanupRequests := session.topologyRequests()
	wantRequest := rootlesspodman.NetworkTopologyTargetRequest{Identity: testNetworkTopologyIdentity(), Target: *started}
	if len(revokeRequests) != 2 || len(cleanupRequests) != 2 {
		t.Fatalf("retained topology calls = revoke:%d cleanup:%d, want two exact attempts", len(revokeRequests), len(cleanupRequests))
	}
	for index, request := range append(revokeRequests, cleanupRequests...) {
		if !reflect.DeepEqual(request, wantRequest) {
			t.Fatalf("topology request %d = %#v, want exact identity and target %#v", index, request, wantRequest)
		}
	}

	beforeTerminalProbe := runner.lifecycleOperations()
	if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); !errors.Is(err, rootlesspodman.ErrNetworkTopologySessionMissing) {
		t.Fatalf("Start() after terminal cleanup error = %v, want removed topology entry", err)
	}
	if afterTerminalProbe := runner.lifecycleOperations(); !reflect.DeepEqual(afterTerminalProbe, beforeTerminalProbe) {
		t.Fatalf("terminal entry probe reached Podman: before=%#v after=%#v", beforeTerminalProbe, afterTerminalProbe)
	}
}

func TestL7PodmanTopologyDeleteAfterCompletedStopStillRunsRuntimeDelete(t *testing.T) {
	session := newFakeNetworkTopologySession(nil)
	session.cleanupErr = errors.New("transient cleanup failure")
	runner := &topologyCommandRunner{}
	driver := newTopologyDriver(runner, session, nil)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if _, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyCleanupFailed) {
		t.Fatalf("Stop() error = %v, want retained cleanup failure", err)
	}

	session.mu.Lock()
	session.cleanupErr = nil
	session.mu.Unlock()
	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("Delete() after completed Stop unexpected error: %v", err)
	}
	if got, want := runner.lifecycleOperations(), []string{
		rootlesspodman.OperationCreate,
		rootlesspodman.OperationStart,
		rootlesspodman.OperationStop,
		rootlesspodman.OperationDelete,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle operation transition = %#v, want %#v", got, want)
	}
}

func TestL7PodmanTopologyGenuineDeleteFailureRemainsRetryable(t *testing.T) {
	deleteFailure := errors.New("delete failed token=private-delete from /tmp/private-runtime")
	session := newFakeNetworkTopologySession(nil)
	runner := &topologyCommandRunner{errByOperation: map[string]error{
		rootlesspodman.OperationDelete: deleteFailure,
	}}
	driver := newTopologyDriver(runner, session, nil)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); !errors.Is(err, deleteFailure) || !errors.Is(err, rootlesspodman.ErrNetworkTopologyCleanupFailed) {
		t.Fatalf("first Delete() error = %v, want genuine delete plus cleanup classification", err)
	} else {
		for _, forbidden := range []string{"private-delete", "private-runtime"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("first Delete() error leaked %q: %v", forbidden, err)
			}
		}
	}
	_, _, _, cleanupCalls, _, _ := session.callState()
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls after failed runtime delete = %d, want retained ownership", cleanupCalls)
	}

	delete(runner.errByOperation, rootlesspodman.OperationDelete)
	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("retry Delete() unexpected error: %v", err)
	}
	if got := countOperation(runner.lifecycleOperations(), rootlesspodman.OperationDelete); got != 2 {
		t.Fatalf("Podman delete calls = %d, want failed delete retried", got)
	}
	_, _, _, cleanupCalls, _, _ = session.callState()
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls after successful delete retry = %d, want 1", cleanupCalls)
	}
}

func TestL7PodmanTopologyStopFailureLeavesQuarantineSessionForRetry(t *testing.T) {
	sequence := &topologySequence{}
	session := newFakeNetworkTopologySession(sequence)
	runner := &topologyCommandRunner{sequence: sequence, errByOperation: map[string]error{
		rootlesspodman.OperationStop: errors.New("stop uncertain"),
	}}
	driver := newTopologyDriver(runner, session, sequence)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if _, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyCleanupFailed) {
		t.Fatalf("Stop() error = %v, want cleanup-incomplete classification", err)
	}
	_, _, revokeCalls, cleanupCalls, _, _ := session.callState()
	if revokeCalls != 1 || cleanupCalls != 0 {
		t.Fatalf("failed Stop() calls = revoke:%d cleanup:%d, want quarantined session retained without rule removal", revokeCalls, cleanupCalls)
	}
	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: *started, Args: []string{"true"}}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyInactive) {
		t.Fatalf("Exec() after uncertain Stop error = %v, want inactive proof", err)
	}

	delete(runner.errByOperation, rootlesspodman.OperationStop)
	if _, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: *started}); err != nil {
		t.Fatalf("retry Stop() unexpected error: %v", err)
	}
	_, _, revokeCalls, cleanupCalls, _, _ = session.callState()
	if revokeCalls != 2 || cleanupCalls != 1 {
		t.Fatalf("retry Stop() calls = revoke:%d cleanup:%d, want retained generation cleanup", revokeCalls, cleanupCalls)
	}
}

func TestL7PodmanTopologyMissingSessionFailsClosedForStartAndExec(t *testing.T) {
	factory := &fakeNetworkTopologyFactory{prepareErr: errors.New("stale topology unavailable")}
	runner := &topologyCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner:        runner,
		ExecRunner:             runner,
		NetworkTopologyFactory: factory,
	})
	target := sandboxruntime.Target{ID: testContainerID, Name: "hal-l7", Runtime: sandboxruntime.RuntimeState{
		Driver: sandboxruntime.DriverRootlessPodman, RuntimeID: testContainerID,
	}}

	if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: target}); !errors.Is(err, rootlesspodman.ErrNetworkTopologySessionMissing) {
		t.Fatalf("Start() error = %v, want ErrNetworkTopologySessionMissing", err)
	}
	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: target, Args: []string{"true"}}); !errors.Is(err, rootlesspodman.ErrNetworkTopologySessionMissing) {
		t.Fatalf("Exec() error = %v, want ErrNetworkTopologySessionMissing", err)
	}
	if len(runner.lifecycleRequests) != 0 || len(runner.execRequests) != 0 {
		t.Fatalf("missing-session requests reached Podman: lifecycle=%#v exec=%#v", runner.lifecycleRequests, runner.execRequests)
	}
}

func TestL7PodmanTopologyRejectsWildcardOrInconsistentProxyEnvironment(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "wildcard", env: proxyEnvironment("http://0.0.0.0:31077")},
		{name: "hostname", env: proxyEnvironment("http://proxy.internal:31077")},
		{name: "inconsistent endpoints", env: map[string]string{
			"HTTP_PROXY": testProxyEndpoint, "HTTPS_PROXY": "http://169.254.77.2:31078",
			"http_proxy": testProxyEndpoint, "https_proxy": testProxyEndpoint,
		}},
		{name: "uncontrolled key", env: func() map[string]string {
			env := proxyEnvironment(testProxyEndpoint)
			env["NO_PROXY"] = "example.com"
			return env
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newFakeNetworkTopologySession(nil)
			session.proxyEnv = tt.env
			driver, created, runner := createPreparedTopologyDriver(t, session)
			started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
			if err != nil {
				t.Fatalf("Start() unexpected error: %v", err)
			}
			if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: *started, Args: []string{"true"}}); !errors.Is(err, rootlesspodman.ErrNetworkTopologyProxyEnvironmentInvalid) {
				t.Fatalf("Exec() error = %v, want ErrNetworkTopologyProxyEnvironmentInvalid", err)
			}
			if len(runner.execRequests) != 0 {
				t.Fatalf("invalid proxy environment reached Podman: %#v", runner.execRequests)
			}
		})
	}
}

func testNetworkTopologyIdentity() rootlesspodman.NetworkTopologyIdentity {
	return rootlesspodman.NetworkTopologyIdentity{
		SandboxID:            "sandbox-a",
		ExecutionID:          "execution-a",
		WorkerID:             "worker-a",
		RuntimeDriver:        sandboxruntime.DriverRootlessPodman,
		RuntimeGenerationID:  "runtime-generation-a",
		PlanID:               "plan-a",
		PolicySnapshotID:     "policy-snapshot-a",
		ProxySessionID:       "proxy-session-a",
		ProxyGenerationID:    "proxy-generation-a",
		TopologyGenerationID: "topology-generation-a",
		RuleGenerationID:     "rule-generation-a",
	}
}

func testPastaCreateArgs() []string {
	return testPastaCreateArgsFor("169.254.77.2")
}

func testPastaCreateArgsFor(guestAddress string) []string {
	return []string{"--network", "pasta:--no-map-gw,--address=192.0.2.3/24,--gateway=192.0.2.1,--address=fd00:6861:6c::2/64,--gateway=fd00:6861:6c::1,--map-host-loopback=" + guestAddress + ",-t,none,-u,none,-T,none,-U,none"}
}

func proxyEnvironment(endpoint string) map[string]string {
	return map[string]string{
		"HTTP_PROXY": endpoint, "HTTPS_PROXY": endpoint,
		"http_proxy": endpoint, "https_proxy": endpoint,
	}
}

func assertExplicitSafePastaCreateArgs(t *testing.T, args []string) {
	t.Helper()
	if !containsArgPair(args, "--network", testPastaCreateArgs()[1]) {
		t.Fatalf("Create() args = %#v, want explicit bounded pasta mapping", args)
	}
	joined := strings.ToLower(strings.Join(args, "\x00"))
	for _, forbidden := range []string{
		"--privileged", "--cap-add", "net_admin", "net_raw", "docker.sock", "podman.sock",
		"--publish", "--publish-all", "--network=host", "\x00host\x00", "\x00bridge\x00",
		"--ipv4-only", "--ipv6-only",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Create() args = %#v, contain forbidden topology token %q", args, forbidden)
		}
	}
	if countArg(args, "--cap-drop=ALL") != 1 || !containsArgPair(args, "--security-opt", "no-new-privileges") {
		t.Fatalf("Create() args = %#v, want one all-capability drop and no-new-privileges", args)
	}
}

func countArg(args []string, value string) int {
	count := 0
	for _, arg := range args {
		if arg == value {
			count++
		}
	}
	return count
}

func assertAdvisoryActiveNetworkProof(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target.Runtime.Metadata == nil || target.Runtime.Metadata.NetworkEnforcement == nil {
		t.Fatalf("active target metadata = %#v, want network proof", target.Runtime.Metadata)
	}
	proof := target.Runtime.Metadata.NetworkEnforcement
	if proof.Orchestration == nil || proof.Orchestration.Status != "active" || proof.Orchestration.Proxy == nil || len(proof.Orchestration.Rules) != 1 {
		t.Fatalf("active orchestration = %#v, want proxy plus inspected rule proof", proof.Orchestration)
	}
	if proof.Result == nil || proof.Result.Outcome != "best_effort" || proof.Result.EnforcementMode != "best_effort" {
		t.Fatalf("rootless result = %#v, want advisory best_effort", proof.Result)
	}
	if proof.Result.Capability != nil {
		t.Fatalf("rootless result capability = %#v, want no strict/enforcing upgrade", proof.Result.Capability)
	}
}

func containsArgPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func containsArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func createPreparedTopologyDriver(t *testing.T, session *fakeNetworkTopologySession) (*rootlesspodman.Driver, *sandboxruntime.Target, *topologyCommandRunner) {
	t.Helper()
	runner := &topologyCommandRunner{}
	driver := newTopologyDriver(runner, session, nil)
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-l7"})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	return driver, created, runner
}

func newTopologyDriver(runner *topologyCommandRunner, session *fakeNetworkTopologySession, sequence *topologySequence) *rootlesspodman.Driver {
	return rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner,
		ExecRunner:      runner,
		NetworkTopologyFactory: &fakeNetworkTopologyFactory{
			sequence: sequence,
			preparation: rootlesspodman.NetworkTopologyPreparation{
				Identity: testNetworkTopologyIdentity(), CreateArgs: testPastaCreateArgs(), Session: session,
			},
		},
		NetworkTopologyCleanupTimeout: 250 * time.Millisecond,
	})
}

type fakeNetworkTopologyFactory struct {
	sequence    *topologySequence
	preparation rootlesspodman.NetworkTopologyPreparation
	prepareErr  error
}

func (f *fakeNetworkTopologyFactory) PrepareNetworkTopology(_ context.Context, req rootlesspodman.NetworkTopologyPrepareRequest) (rootlesspodman.NetworkTopologyPreparation, error) {
	if f.sequence != nil {
		f.sequence.add("prepare")
	}
	if req.SandboxName == "" {
		return rootlesspodman.NetworkTopologyPreparation{}, errors.New("sandbox name missing")
	}
	return f.preparation, f.prepareErr
}

type fakeNetworkTopologySession struct {
	mu                    sync.Mutex
	sequence              *topologySequence
	proof                 rootlesspodman.NetworkTopologyProof
	proxyEnv              map[string]string
	loss                  chan struct{}
	activateErr           error
	inspectErr            error
	revokeErr             error
	cleanupErr            error
	activateCalls         int
	inspectCalls          int
	revokeCalls           int
	cleanupCalls          int
	lastRevokeContextErr  error
	lastCleanupContextErr error
	revokeRequests        []rootlesspodman.NetworkTopologyTargetRequest
	cleanupRequests       []rootlesspodman.NetworkTopologyTargetRequest
}

func newFakeNetworkTopologySession(sequence *topologySequence) *fakeNetworkTopologySession {
	identity := testNetworkTopologyIdentity()
	return &fakeNetworkTopologySession{
		sequence: sequence,
		proof: rootlesspodman.NetworkTopologyProof{
			Identity:       identity,
			RuntimeID:      testContainerID,
			RuleDigest:     "0123456789abcdef",
			ProxyActive:    true,
			RulesInspected: true,
		},
		proxyEnv: proxyEnvironment(testProxyEndpoint),
		loss:     make(chan struct{}),
	}
}

func (s *fakeNetworkTopologySession) Activate(_ context.Context, req rootlesspodman.NetworkTopologyTargetRequest) (rootlesspodman.NetworkTopologyProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activateCalls++
	if s.sequence != nil {
		s.sequence.add("activate")
	}
	if req.Target.Runtime.RuntimeID == "" {
		return rootlesspodman.NetworkTopologyProof{}, errors.New("runtime id missing")
	}
	return s.proof, s.activateErr
}

func (s *fakeNetworkTopologySession) Inspect(_ context.Context, _ rootlesspodman.NetworkTopologyTargetRequest) (rootlesspodman.NetworkTopologyProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inspectCalls++
	if s.sequence != nil {
		s.sequence.add("inspect")
	}
	return s.proof, s.inspectErr
}

func (s *fakeNetworkTopologySession) ProxyEnvironment(_ rootlesspodman.NetworkTopologyTargetRequest) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneStringMapForTopologyTest(s.proxyEnv)
}

func (s *fakeNetworkTopologySession) Revoke(ctx context.Context, req rootlesspodman.NetworkTopologyTargetRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeCalls++
	s.revokeRequests = append(s.revokeRequests, req)
	s.lastRevokeContextErr = ctx.Err()
	if s.sequence != nil {
		s.sequence.add("revoke")
	}
	return s.revokeErr
}

func (s *fakeNetworkTopologySession) Cleanup(ctx context.Context, req rootlesspodman.NetworkTopologyTargetRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupCalls++
	s.cleanupRequests = append(s.cleanupRequests, req)
	s.lastCleanupContextErr = ctx.Err()
	if s.sequence != nil {
		s.sequence.add("cleanup")
	}
	return s.cleanupErr
}

func (s *fakeNetworkTopologySession) topologyRequests() (revoke, cleanup []rootlesspodman.NetworkTopologyTargetRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rootlesspodman.NetworkTopologyTargetRequest(nil), s.revokeRequests...), append([]rootlesspodman.NetworkTopologyTargetRequest(nil), s.cleanupRequests...)
}

func (s *fakeNetworkTopologySession) Loss() <-chan struct{} { return s.loss }

func (s *fakeNetworkTopologySession) callState() (activate, inspect, revoke, cleanup int, revokeContextErr, cleanupContextErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activateCalls, s.inspectCalls, s.revokeCalls, s.cleanupCalls, s.lastRevokeContextErr, s.lastCleanupContextErr
}

type topologyCommandRunner struct {
	mu                sync.Mutex
	sequence          *topologySequence
	lifecycleRequests []rootlesspodman.CommandRequest
	execRequests      []rootlesspodman.CommandRequest
	errByOperation    map[string]error
}

func (r *topologyCommandRunner) RunLifecycleCommand(_ context.Context, req rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lifecycleRequests = append(r.lifecycleRequests, req)
	if r.sequence != nil {
		r.sequence.add("podman_" + req.Operation)
	}
	if req.Operation == rootlesspodman.OperationCreate {
		return rootlesspodman.CommandResult{Stdout: testContainerID + "\n"}, nil
	}
	return rootlesspodman.CommandResult{}, r.errByOperation[req.Operation]
}

func (r *topologyCommandRunner) RunExecCommand(_ context.Context, req rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.execRequests = append(r.execRequests, req)
	if r.sequence != nil {
		r.sequence.add("podman_exec")
	}
	return rootlesspodman.CommandResult{}, nil
}

func (r *topologyCommandRunner) lifecycleOperations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	operations := make([]string, 0, len(r.lifecycleRequests))
	for _, req := range r.lifecycleRequests {
		operations = append(operations, req.Operation)
	}
	return operations
}

func countOperation(operations []string, want string) int {
	count := 0
	for _, operation := range operations {
		if operation == want {
			count++
		}
	}
	return count
}

type topologySequence struct {
	mu     sync.Mutex
	values []string
}

func (s *topologySequence) add(value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = append(s.values, value)
}

func (s *topologySequence) snapshot() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.values...)
}

func cloneStringMapForTopologyTest(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
