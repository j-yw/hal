//go:build linux && podman_integration && network_enforcement_live && l7_linux_network_integration

package rootlesspodman_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman/l7network"
)

func TestL7PreparedLinuxRootlessPodmanNetworkTopology(t *testing.T) {
	for _, marker := range []string{"HAL_NETWORK_ENFORCEMENT_LIVE", "HAL_NETWORK_ENFORCEMENT_LIVE_PROXY", "HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL", "HAL_L7_LINUX_NETWORK_INTEGRATION"} {
		if os.Getenv(marker) != "1" {
			t.Fatalf("%s=1 is required", marker)
		}
	}
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Fatal("HAL_PODMAN_TEST_IMAGE must name an already-local image")
	}
	podmanPath := requiredTool(t, "podman")
	nsenterPath := requiredTool(t, "nsenter")
	ipPath := requiredTool(t, "ip")
	nftPath := requiredTool(t, "nft")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, podmanPath, "image", "exists", image).Run(); err != nil {
		t.Fatal("selected image is not already local")
	}

	httpFixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "fixture-ok") }))
	defer httpFixture.Close()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan struct{})
	t.Cleanup(func() {
		_ = echoListener.Close()
		select {
		case <-echoDone:
		case <-time.After(time.Second):
			t.Error("controlled TCP fixture did not stop")
		}
	})
	var tcpFixtureDeliveries atomic.Int64
	go func() {
		defer close(echoDone)
		for {
			connection, acceptErr := echoListener.Accept()
			if acceptErr != nil {
				return
			}
			tcpFixtureDeliveries.Add(1)
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(connection)
		}
	}()
	udpFixture, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	t.Cleanup(func() {
		_ = udpFixture.Close()
		select {
		case <-udpDone:
		case <-time.After(time.Second):
			t.Error("controlled UDP fixture did not stop")
		}
	})
	var udpFixtureDeliveries atomic.Int64
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 32)
		for {
			count, address, readErr := udpFixture.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			udpFixtureDeliveries.Add(1)
			_, _ = udpFixture.WriteTo(buffer[:count], address)
		}
	}()
	udpControl, err := net.DialTimeout("udp", udpFixture.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = udpControl.SetDeadline(time.Now().Add(time.Second))
	if _, err = udpControl.Write([]byte("fixture")); err != nil {
		_ = udpControl.Close()
		t.Fatal(err)
	}
	udpReply := make([]byte, len("fixture"))
	if _, err = io.ReadFull(udpControl, udpReply); err != nil || string(udpReply) != "fixture" {
		_ = udpControl.Close()
		t.Fatal("controlled UDP fixture is not locally reachable")
	}
	_ = udpControl.Close()

	request := networkenforcement.PlanRequest{ID: "l7-plan-a", Source: networkenforcement.PlanSourceRuntime, Operation: "l7_topology",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{ID: "l7-policy-a", Version: "v1", Preset: networkenforcement.PolicyPresetAllowListed, RuleSetID: "l7-rules-a"},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{Preset: networkenforcement.PolicyPresetAllowListed, AllowlistMode: networkenforcement.AllowlistModeEnforce, RuleSetID: "l7-rules-a",
			DefaultPosture: networkenforcement.DefaultPostureDenyByDefault, PrivateNetwork: networkenforcement.PostureBlock, MetadataEndpoint: networkenforcement.PostureBlock,
			TCP: networkenforcement.PostureBlock, UDP: networkenforcement.PostureBlock, ICMP: networkenforcement.PostureBlock,
			HTTP: networkenforcement.ProxyRoutingModeRouteViaProxy, HTTPS: networkenforcement.ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "l7-proxy-session-a", ProxyMechanism: networkenforcement.EnforcementMechanismProxy,
			FirewallMode: networkenforcement.FirewallIntentModeApply, FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
			AllowlistRules: []networkenforcement.AllowlistRule{{ID: "l7-allow-a", Category: networkenforcement.AllowlistRuleCategoryDomain, Value: "allowed.test"}}}}
	plan := networkenforcement.BuildPlan(request)
	policy := networkenforcement.NewPolicyProxyPolicyInput(plan, request.RequestedPolicy.AllowlistRules)
	httpAddress := strings.TrimPrefix(httpFixture.URL, "http://")
	echoAddress := echoListener.Addr().String()
	adapter, err := policyproxy.New(policyproxy.Config{Policy: policy, ListenAddress: "127.0.0.1:0",
		Resolver: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(address)
			target := httpAddress
			if port == "443" {
				target = echoAddress
			}
			return (&net.Dialer{}).DialContext(dialCtx, network, target)
		}})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := l7network.NewProductionProxy(adapter)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := l7network.NewProductionNamespaceResolver(l7network.ProductionNamespaceResolverOptions{LifecycleRunner: rootlesspodman.DefaultCommandRunner{}, PodmanPath: podmanPath, NSenterPath: nsenterPath, IPPath: ipPath, MaxOutputBytes: 256 << 10})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := linuxrules.NewProductionExecutor(linuxrules.ProductionExecutorOptions{NSenterPath: nsenterPath, NFTPath: nftPath})
	if err != nil {
		t.Fatal(err)
	}
	rules := linuxrules.NewAdapter(executor, linuxrules.AdapterOptions{})
	identity := rootlesspodman.NetworkTopologyIdentity{SandboxID: "l7-sandbox-a", ExecutionID: "l7-execution-a", WorkerID: "l7-worker-a", RuntimeDriver: rootlesspodman.DriverID, RuntimeGenerationID: "l7-runtime-a", PlanID: plan.ID, PolicySnapshotID: plan.PolicySnapshot.ID, ProxySessionID: plan.Proxy.ProxySessionID, ProxyGenerationID: "l7-proxy-generation-a", TopologyGenerationID: "l7-topology-a", RuleGenerationID: "l7-rule-a"}
	guestProxyAddress := "169.254.77.2"
	factory, err := l7network.NewFactory(l7network.FactoryOptions{Identity: identity, Plan: plan, Proxy: proxy, NamespaceResolver: resolver, Rules: rules,
		RawPacketVerifierFactory: l7network.NewProductionRawPacketVerifierFactory(rootlesspodman.DefaultCommandRunner{}, podmanPath), GuestProxyAddress: guestProxyAddress, TableName: "hal_l7_live_a"})
	if err != nil {
		t.Fatal(err)
	}
	runner := rootlesspodman.DefaultCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{LifecycleRunner: runner, ExecRunner: runner, CopyRunner: runner, PodmanPath: podmanPath, Image: image, WorkDir: "/", JobExecutionSupported: true, NetworkTopologyFactory: factory})
	containerName := "hal-l7-live-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatal(err)
	}
	exactID := target.Runtime.RuntimeID
	cleanupTarget := *target
	deletePending := true
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cleanupErr := runL7PodmanExactContainerCleanup(deletePending, func() error { return driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: cleanupTarget}) }, func() error { return proveL7PodmanExactContainerAbsent(cleanupCtx, podmanPath, exactID) })
		if cleanupErr != nil {
			t.Errorf("exact cleanup failed: %v", cleanupErr)
		}
	})
	if !validL7PodmanExactContainerID(exactID) {
		t.Fatal("Podman did not return an exact container ID")
	}
	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatal(err)
	}
	cleanupTarget = *target

	probePath := buildL7Probe(t, ctx)
	if err := driver.CopyIn(ctx, sandboxruntime.CopyRequest{Target: *target, SourcePath: probePath, DestinationPath: "/tmp/l7probe"}); err != nil {
		t.Fatal(err)
	}
	runProbe := func(name string, args ...string) {
		t.Helper()
		command := append([]string{"/tmp/l7probe"}, args...)
		if _, err := driver.Exec(ctx, sandboxruntime.ExecRequest{Target: *target, Args: command}); err != nil {
			t.Fatalf("%s probe failed: %v", name, err)
		}
	}
	runProbe("allowed HTTP", "http", "http://allowed.test/ok")
	runProbe("allowed CONNECT", "connect", "allowed.test:443")
	if tcpFixtureDeliveries.Load() == 0 || udpFixtureDeliveries.Load() == 0 {
		t.Fatal("controlled local denial fixtures were not reachable before workload probes")
	}
	tcpBaseline := tcpFixtureDeliveries.Load()
	udpBaseline := udpFixtureDeliveries.Load()
	_, tcpPort, err := net.SplitHostPort(echoListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, udpPort, err := net.SplitHostPort(udpFixture.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	runProbe("controlled mapped direct TCP denial", "tcp", net.JoinHostPort(guestProxyAddress, tcpPort))
	runProbe("controlled mapped direct UDP denial", "udp", net.JoinHostPort(guestProxyAddress, udpPort))
	if tcpFixtureDeliveries.Load() != tcpBaseline || udpFixtureDeliveries.Load() != udpBaseline {
		t.Fatal("default-drop rules allowed delivery to a controlled mapped direct fixture")
	}
	runProbe("ICMP", "icmp")
	runProbe("AF_PACKET raw socket permission", "packet")
	correlation := networkenforcement.EnforcementCorrelation{SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID, RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID, ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID, TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID}
	verifier := rootlesspodman.NewPodmanRawPacketIsolationVerifier(rootlesspodman.PodmanRawPacketIsolationVerifierOptions{LifecycleRunner: runner, PodmanPath: podmanPath, Identity: identity, Target: *target})
	if proof, err := verifier.VerifyRawPacketIsolation(ctx, correlation); err != nil || !networkenforcement.RawPacketIsolationProofMatches(proof, correlation) {
		t.Fatal("post-AF_PACKET capability reinspection failed")
	}
	if _, err := (networkenforcement.ProxyListenerLifecycleRunner{Adapter: adapter}).Stop(ctx, plan, nil); err != nil {
		t.Fatal("proxy loss injection failed")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, execErr := driver.Exec(ctx, sandboxruntime.ExecRequest{Target: *target, Args: []string{"/tmp/l7probe", "http", "http://allowed.test/ok"}})
		if execErr != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy loss did not revoke proof before exec")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatal(err)
	}
	deletePending = false
	if err := proveL7PodmanExactContainerAbsent(ctx, podmanPath, exactID); err != nil {
		t.Fatal(err)
	}
	if _, ok := adapter.Endpoint(); ok {
		t.Fatal("policy proxy listener remained after cleanup")
	}
	runL7PreparedRestartReconciliation(t, image, podmanPath, nsenterPath, ipPath, nftPath)
}

func requiredTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is required", name)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}
func buildL7Probe(t *testing.T, ctx context.Context) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l7probe")
	command := exec.CommandContext(ctx, "go", "build", "-o", path, "./testdata/l7probe")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build local L7 probe: %s", strings.TrimSpace(string(output)))
	}
	return path
}

type l7RestartJournal struct {
	Identity  rootlesspodman.NetworkTopologyIdentity `json:"identity"`
	Target    sandboxruntime.Target                  `json:"target"`
	ProxyPort uint16                                 `json:"proxyPort"`
}

func TestL7PreparedLinuxRootlessPodmanRestartChild(t *testing.T) {
	if os.Getenv("HAL_L7_RESTART_CHILD_TOKEN") != "explicit-child" {
		t.Fatal("restart child helper requires explicit token")
	}
	journalPath := strings.TrimSpace(os.Getenv("HAL_L7_RESTART_CHILD_JOURNAL"))
	containerName := strings.TrimSpace(os.Getenv("HAL_L7_RESTART_CHILD_NAME"))
	if journalPath == "" || containerName == "" {
		t.Fatal("restart child helper inputs missing")
	}
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Fatal("restart child image missing")
	}
	runL7RestartChild(t, journalPath, containerName, image, requiredTool(t, "podman"), requiredTool(t, "nsenter"), requiredTool(t, "ip"), requiredTool(t, "nft"))
}

func runL7RestartChild(t *testing.T, journalPath, containerName, image, podmanPath, nsenterPath, ipPath, nftPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plan, policy := restartPlanAndPolicy()
	adapter, err := policyproxy.New(policyproxy.Config{Policy: policy, ListenAddress: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := l7network.NewProductionProxy(adapter)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := l7network.NewProductionNamespaceResolver(l7network.ProductionNamespaceResolverOptions{LifecycleRunner: rootlesspodman.DefaultCommandRunner{}, PodmanPath: podmanPath, NSenterPath: nsenterPath, IPPath: ipPath, MaxOutputBytes: 256 << 10})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := linuxrules.NewProductionExecutor(linuxrules.ProductionExecutorOptions{NSenterPath: nsenterPath, NFTPath: nftPath})
	if err != nil {
		t.Fatal(err)
	}
	identity := restartIdentity(plan)
	factory, err := l7network.NewFactory(l7network.FactoryOptions{Identity: identity, Plan: plan, Proxy: proxy, NamespaceResolver: resolver, Rules: linuxrules.NewAdapter(executor, linuxrules.AdapterOptions{}), RawPacketVerifierFactory: l7network.NewProductionRawPacketVerifierFactory(rootlesspodman.DefaultCommandRunner{}, podmanPath), GuestProxyAddress: "169.254.77.3", TableName: "hal_l7_restart_a"})
	if err != nil {
		t.Fatal(err)
	}
	runner := rootlesspodman.DefaultCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{LifecycleRunner: runner, ExecRunner: runner, PodmanPath: podmanPath, Image: image, WorkDir: "/", JobExecutionSupported: true, NetworkTopologyFactory: factory})
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, ok := adapter.Endpoint()
	if !ok {
		t.Fatal("restart child listener unavailable")
	}
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port64 == 0 {
		t.Fatal("restart child listener port unavailable")
	}
	journal := l7RestartJournal{Identity: identity, Target: *target, ProxyPort: uint16(port64)}
	payload, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func runL7PreparedRestartReconciliation(t *testing.T, image, podmanPath, nsenterPath, ipPath, nftPath string) {
	t.Helper()
	journalPath := filepath.Join(t.TempDir(), "restart.json")
	containerName := "hal-l7-restart-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	restartPlan, _ := restartPlanAndPolicy()
	cleanupIdentity := restartIdentity(restartPlan)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cleanupExactID := ""
	deletePending := true
	t.Cleanup(func() {
		if !deletePending {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if !validL7PodmanExactContainerID(cleanupExactID) {
			var err error
			cleanupExactID, err = removeOwnedL7PodmanRestartContainerWithRunner(cleanupCtx, podmanPath, containerName, cleanupIdentity, func(runCtx context.Context, executable string, args ...string) ([]byte, error) {
				return exec.CommandContext(runCtx, executable, args...).Output()
			})
			if err != nil {
				t.Errorf("restart fallback cleanup uncertain: %v", err)
				return
			}
		} else if err := exec.CommandContext(cleanupCtx, podmanPath, "container", "rm", "--force", cleanupExactID).Run(); err != nil {
			t.Errorf("restart exact-container cleanup failed")
			return
		}
		if err := proveL7PodmanExactContainerAbsent(cleanupCtx, podmanPath, cleanupExactID); err != nil {
			t.Errorf("restart exact-container cleanup absence unverified")
		}
	})
	command := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestL7PreparedLinuxRootlessPodmanRestartChild$", "-test.count=1")
	command.Env = append(os.Environ(), "HAL_L7_RESTART_CHILD_TOKEN=explicit-child", "HAL_L7_RESTART_CHILD_JOURNAL="+journalPath, "HAL_L7_RESTART_CHILD_NAME="+containerName)
	if err := command.Run(); err != nil {
		t.Fatal("restart child failed")
	}
	payload, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal("restart journal unavailable")
	}
	var journal l7RestartJournal
	if json.Unmarshal(payload, &journal) != nil || journal.ProxyPort == 0 || !validL7PodmanExactContainerID(journal.Target.ID) {
		t.Fatal("restart journal invalid")
	}
	cleanupExactID = journal.Target.ID
	if connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(journal.ProxyPort))), 100*time.Millisecond); err == nil {
		connection.Close()
		t.Fatal("restart child listener survived process exit")
	}
	resolver, err := l7network.NewProductionNamespaceResolver(l7network.ProductionNamespaceResolverOptions{LifecycleRunner: rootlesspodman.DefaultCommandRunner{}, PodmanPath: podmanPath, NSenterPath: nsenterPath, IPPath: ipPath, MaxOutputBytes: 256 << 10})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := linuxrules.NewProductionExecutor(linuxrules.ProductionExecutorOptions{NSenterPath: nsenterPath, NFTPath: nftPath})
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := l7network.NewReconciler(l7network.ReconcilerOptions{Identity: journal.Identity, NamespaceResolver: resolver, Rules: linuxrules.NewAdapter(executor, linuxrules.AdapterOptions{}), RawPacketVerifierFactory: l7network.NewProductionRawPacketVerifierFactory(rootlesspodman.DefaultCommandRunner{}, podmanPath), Runtime: l7network.ProductionRuntimeReconciler{Runner: rootlesspodman.DefaultCommandRunner{}, PodmanPath: podmanPath}, GuestProxyAddress: "169.254.77.3", ProxyPort: journal.ProxyPort, TableName: "hal_l7_restart_a"})
	if err != nil {
		t.Fatal(err)
	}
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: journal.Identity, Target: journal.Target}
	mismatch := req
	mismatch.Target.ID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mismatch.Target.Runtime.RuntimeID = mismatch.Target.ID
	if err := reconciler.Reconcile(ctx, mismatch); err == nil {
		t.Fatal("restart reconciler accepted mismatched target")
	}
	inspectOutput, err := exec.CommandContext(ctx, podmanPath, "inspect", "--format", "{{.State.Running}}", journal.Target.ID).Output()
	if err != nil || strings.TrimSpace(string(inspectOutput)) != "true" {
		t.Fatal("mismatch changed exact retained container")
	}
	if err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("restart reconcile failed: %v", err)
	}
	deletePending = false
	if err := proveL7PodmanExactContainerAbsent(ctx, podmanPath, journal.Target.ID); err != nil {
		t.Fatal("restart exact-container absence failed")
	}
}

func restartPlanAndPolicy() (networkenforcement.Plan, networkenforcement.PolicyProxyPolicyInput) {
	request := networkenforcement.PlanRequest{ID: "l7-restart-plan-a", Source: networkenforcement.PlanSourceRuntime, Operation: "l7_topology", PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{ID: "l7-restart-policy-a", Version: "v1", Preset: networkenforcement.PolicyPresetAllowListed, RuleSetID: "l7-restart-rules-a"}, RequestedPolicy: networkenforcement.RequestedNetworkPosture{Preset: networkenforcement.PolicyPresetAllowListed, DefaultPosture: networkenforcement.DefaultPostureDenyByDefault, AllowlistMode: networkenforcement.AllowlistModeEnforce, RuleSetID: "l7-restart-rules-a", PrivateNetwork: networkenforcement.PostureBlock, MetadataEndpoint: networkenforcement.PostureBlock, TCP: networkenforcement.PostureBlock, UDP: networkenforcement.PostureBlock, ICMP: networkenforcement.PostureBlock, HTTP: networkenforcement.ProxyRoutingModeRouteViaProxy, HTTPS: networkenforcement.ProxyRoutingModeRouteViaProxy, ProxySessionID: "l7-restart-proxy-session-a", ProxyMechanism: networkenforcement.EnforcementMechanismProxy, FirewallMode: networkenforcement.FirewallIntentModeApply, FirewallMechanism: networkenforcement.EnforcementMechanismFirewall, AllowlistRules: []networkenforcement.AllowlistRule{{ID: "l7-restart-allow-a", Category: networkenforcement.AllowlistRuleCategoryDomain, Value: "allowed.test"}}}}
	plan := networkenforcement.BuildPlan(request)
	return plan, networkenforcement.NewPolicyProxyPolicyInput(plan, request.RequestedPolicy.AllowlistRules)
}
func restartIdentity(plan networkenforcement.Plan) rootlesspodman.NetworkTopologyIdentity {
	return rootlesspodman.NetworkTopologyIdentity{SandboxID: "l7-restart-sandbox-a", ExecutionID: "l7-restart-execution-a", WorkerID: "l7-restart-worker-a", RuntimeDriver: rootlesspodman.DriverID, RuntimeGenerationID: "l7-restart-runtime-a", PlanID: plan.ID, PolicySnapshotID: plan.PolicySnapshot.ID, ProxySessionID: plan.Proxy.ProxySessionID, ProxyGenerationID: "l7-restart-proxy-generation-a", TopologyGenerationID: "l7-restart-topology-a", RuleGenerationID: "l7-restart-rule-a"}
}
