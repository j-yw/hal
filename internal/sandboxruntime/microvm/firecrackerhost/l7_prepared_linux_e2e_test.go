//go:build linux && firecracker_live && network_enforcement_live && l7_linux_network_integration

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
)

const (
	l7PreparedDistributionEnv      = "HAL_L7_DISTRIBUTION_DIR"
	l7PreparedFirecrackerEnv       = "HAL_FIRECRACKER_LIVE_FIRECRACKER"
	l7PreparedFirecrackerVersion   = "Firecracker v1.15.1"
	l7PreparedFirecrackerSHA256    = "7e8b57e88c459396d4680d83dcdd8c7f72305447cb55b11f4ac98ad70a3f7825"
	l7PreparedFirecrackerManifest  = "v1.15.1"
	l7PreparedBootTimeout          = 45 * time.Second
	l7PreparedOperationTimeout     = 30 * time.Second
	l7PreparedContainmentPollLimit = 15 * time.Second
)

var errL7PreparedAssetResolution = errors.New("L7 prepared asset resolution failed")

// TestL7PreparedLinuxFirecrackerNetworkTopologyE2E is the selected live lane
// for the complete explicit L7 composition. The build tags and marker checks
// keep it out of every default path; once selected, prerequisites fail rather
// than skip.
func TestL7PreparedLinuxFirecrackerNetworkTopologyE2E(t *testing.T) {
	prerequisites := requireL7PreparedFirecrackerPrerequisites(t)
	root, err := os.MkdirTemp("/tmp", "hal-l7-fc-e2e-")
	if err != nil {
		t.Fatal("create private L7 acceptance root failed")
	}
	var cleanupDriver *microvm.Driver
	var cleanupTarget *sandboxruntime.Target
	cleanupPending := false
	deleteConfirmed := false
	preserveRecoveryState := false
	t.Cleanup(func() {
		var cleanupFailures error
		if cleanupPending && !deleteConfirmed && cleanupDriver != nil && cleanupTarget != nil {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), l7PreparedOperationTimeout)
			stopped, stopErr := cleanupDriver.Stop(stopCtx, sandboxruntime.LifecycleRequest{Target: *cleanupTarget})
			stopCancel()
			if stopErr != nil {
				cleanupFailures = errors.Join(cleanupFailures, errors.New("L7 cleanup stop failed"))
			}
			if stopped == nil {
				cleanupFailures = errors.Join(cleanupFailures, errors.New("L7 cleanup stop proof missing"))
			} else {
				copy := *stopped
				cleanupTarget = &copy
			}

			deleteCtx, deleteCancel := context.WithTimeout(context.Background(), l7PreparedOperationTimeout)
			deleteErr := cleanupDriver.Delete(deleteCtx, sandboxruntime.LifecycleRequest{Target: *cleanupTarget})
			deleteCancel()
			if deleteErr != nil {
				cleanupFailures = errors.Join(cleanupFailures, errors.New("L7 cleanup delete failed"))
			}
		}
		if cleanupFailures == nil && !preserveRecoveryState {
			if err := os.RemoveAll(root); err != nil {
				cleanupFailures = errors.Join(cleanupFailures, errors.New("L7 cleanup root removal failed"))
			}
		}
		if cleanupFailures != nil {
			t.Error("L7 E2E cleanup failed; preserving L7 recovery state")
		}
	})
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("secure private L7 acceptance root failed")
	}
	stateRoot := l7PreparedPrivateDir(t, root, "firecracker")
	topologyState := l7PreparedPrivateDir(t, root, "topology")
	coordinatorState := l7PreparedPrivateDir(t, root, "coordinator")

	plan := l7PreparedNetworkPlan()
	adapter, err := policyproxy.New(policyproxy.Config{
		Policy:        networkenforcement.NewPolicyProxyPolicyInput(plan, l7PreparedAllowlistRules()),
		ListenAddress: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal("construct production L7 policy proxy failed")
	}
	proxy, err := l7network.NewProductionProxy(adapter)
	if err != nil {
		t.Fatal("construct Firecracker L7 proxy adapter failed")
	}
	lifecycle, err := linuxtopology.New(linuxtopology.Config{
		Enabled: true,
		Tools: linuxtopology.ToolPaths{
			Unshare: prerequisites.tools["unshare"], Pasta: prerequisites.tools["pasta"],
			Nsenter: prerequisites.tools["nsenter"], IP: prerequisites.tools["ip"],
			NC: prerequisites.tools["nc"], Keeper: prerequisites.tools["sleep"],
		},
		Environment: []string{"LANG=C", "LC_ALL=C"}, StateDir: topologyState,
		CleanupTimeout: 5 * time.Second, InspectionTimeout: 5 * time.Second,
		InspectionInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal("construct production L7 namespace topology failed")
	}
	topology, err := l7network.NewLinuxTopology(lifecycle)
	if err != nil {
		t.Fatal("construct Firecracker L7 topology adapter failed")
	}
	tap, err := l7network.NewLinuxTAP(l7network.TAPOptions{
		IPPath: prerequisites.tools["ip"], SysctlPath: prerequisites.tools["sysctl"],
		NsenterPath: prerequisites.tools["nsenter"], CleanupTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal("construct production L7 TAP adapter failed")
	}
	nft, err := linuxrules.NewProductionExecutor(linuxrules.ProductionExecutorOptions{
		NSenterPath: prerequisites.tools["nsenter"], NFTPath: prerequisites.tools["nft"],
	})
	if err != nil {
		t.Fatal("construct production L7 nft adapter failed")
	}

	descriptor := prerequisites.distribution.Descriptor
	config := microvm.DefaultConfig()
	config.HypervisorPath = prerequisites.firecracker
	config.LaunchDescriptor = &descriptor
	config.CPUCount = 1
	config.MemoryMiB = 512
	config.GuestWorkDir = "/workspace"
	driver, err := NewL7LiveDriver(L7LiveDriverOptions{
		Live: LiveDriverOptions{
			Config: config, BaseStateDir: stateRoot,
			BootAcceptancePoller: NewAPISocketBootAcceptancePoller(),
			BootTimeout:          l7PreparedBootTimeout, BootPollInterval: 10 * time.Millisecond,
			GuestTimeout: l7PreparedBootTimeout, GuestPollInterval: 10 * time.Millisecond,
			ProductionVsock: true,
		},
		Intent: &l7PreparedIntentResolver{plan: plan},
		Assets: &l7PreparedAssetResolver{distribution: prerequisites.distribution},
		Topology: l7network.Options{
			Proxy: proxy, Topology: topology, TAP: tap,
			Rules:    linuxrules.NewAdapter(nft, linuxrules.AdapterOptions{}),
			StateDir: coordinatorState, CleanupTimeout: 5 * time.Second,
		},
		NamespaceStarter: NewOSExecNamespaceProcessStarter(),
		NSenterPath:      prerequisites.tools["nsenter"],
	})
	if err != nil {
		t.Fatal("construct explicit production L7 Firecracker driver failed")
	}
	cleanupDriver = driver

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: "l7-prepared-firecracker"})
	if err != nil {
		t.Fatal("create L7 Firecracker target failed")
	}
	cleanupCopy := *target
	cleanupTarget = &cleanupCopy
	cleanupPending = true
	if target.ID == "" || target.ID != target.Runtime.RuntimeID || target.Provider != "firecracker" ||
		target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatal("created L7 Firecracker target identity is not exact")
	}

	started, err := driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatal("start complete L7 Firecracker topology failed")
	}
	cleanupCopy = *started
	cleanupTarget = &cleanupCopy
	if started.Status != string(l7network.StatusActive) || started.Runtime.Metadata == nil ||
		started.Runtime.Metadata.GuestReadiness == nil ||
		started.Runtime.Metadata.GuestReadiness.State != sandboxruntime.RuntimeGuestReadinessStateReady {
		t.Fatal("started L7 Firecracker target lacks active proof-required readiness")
	}
	inspected, err := driver.Inspect(ctx, sandboxruntime.InspectRequest{Target: *started})
	if err != nil || inspected == nil || inspected.Status != string(l7network.StatusActive) {
		t.Fatal("fresh L7 Firecracker host and guest proof inspection failed")
	}
	cleanupCopy = *inspected
	cleanupTarget = &cleanupCopy
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: *inspected, Args: []string{"/bin/busybox", "true"}, WorkDir: config.GuestWorkDir,
	})
	if err != nil || result == nil || result.ExitCode != 0 {
		t.Fatal("proof-gated L7 Firecracker guest work failed")
	}

	// Stopping the exact retained listener publishes loss. The coordinator
	// quarantines first; the contained controller then stops/reaps Firecracker,
	// removes rules/TAP/topology, and releases the exact listener generation.
	if _, err := (networkenforcement.ProxyListenerLifecycleRunner{Adapter: adapter}).Stop(ctx, plan, nil); err != nil {
		t.Fatal("inject exact L7 proxy generation loss failed")
	}
	stopped := waitForL7PreparedContainedTarget(t, driver, *cleanupTarget)
	cleanupCopy = *stopped
	cleanupTarget = &cleanupCopy
	if _, active := adapter.Endpoint(); active {
		preserveRecoveryState = true
		t.Fatal("L7 policy proxy remained active before final runtime deletion")
	}
	if err := driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: *stopped}); err != nil {
		t.Fatal("delete contained L7 Firecracker target failed")
	}
	deleteConfirmed = true
	entries, err := os.ReadDir(stateRoot)
	if err != nil || len(entries) != 0 {
		preserveRecoveryState = true
		t.Fatal("L7 Firecracker private runtime state remained after delete")
	}
	cleanupPending = false
}

type l7PreparedFirecrackerPrerequisites struct {
	firecracker  string
	distribution localresolver.VerifiedDistribution
	tools        map[string]string
}

func requireL7PreparedFirecrackerPrerequisites(t *testing.T) l7PreparedFirecrackerPrerequisites {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("L7 Firecracker network topology acceptance requires Linux x86_64")
	}
	for _, marker := range []string{
		"HAL_FIRECRACKER_LIVE", "HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY", "HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
		"HAL_L7_LINUX_NETWORK_INTEGRATION",
	} {
		if os.Getenv(marker) != "1" {
			t.Fatalf("%s=1 is required", marker)
		}
	}
	for _, device := range []string{"/dev/kvm", "/dev/net/tun"} {
		file, err := os.OpenFile(device, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("L7 Firecracker acceptance requires writable kernel devices")
		}
		if err := file.Close(); err != nil {
			t.Fatal("L7 Firecracker acceptance could not close a kernel device")
		}
	}

	firecrackerPath := strings.TrimSpace(os.Getenv(l7PreparedFirecrackerEnv))
	if !filepath.IsAbs(firecrackerPath) || filepath.Clean(firecrackerPath) != firecrackerPath {
		t.Fatalf("%s must name the pinned executable", l7PreparedFirecrackerEnv)
	}
	info, err := os.Stat(firecrackerPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 ||
		l7PreparedFileSHA256(firecrackerPath) != l7PreparedFirecrackerSHA256 {
		t.Fatal("L7 Firecracker acceptance requires the content-locked executable")
	}
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer versionCancel()
	output, err := exec.CommandContext(versionCtx, firecrackerPath, "--version").Output()
	if err != nil || l7PreparedFirstLine(output) != l7PreparedFirecrackerVersion {
		t.Fatal("L7 Firecracker executable version does not match the lock")
	}

	distributionRoot := strings.TrimSpace(os.Getenv(l7PreparedDistributionEnv))
	if distributionRoot == "" {
		t.Fatalf("%s is required", l7PreparedDistributionEnv)
	}
	distribution, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{RootDir: distributionRoot})
	if err != nil || distribution.Manifest.ImageProfile != assetbuild.ImageProfileL7Network ||
		distribution.Manifest.Architecture != "x86_64" ||
		distribution.Manifest.Versions.Firecracker != l7PreparedFirecrackerManifest {
		t.Fatal("installed L7 distribution failed the production lock")
	}
	profile, ok := distribution.L7Profile()
	if !ok || !localresolver.VerifiedL7ProfileMatches(&profile, &distribution.Descriptor) {
		t.Fatal("installed L7 distribution lacks the verified network profile")
	}

	tools := make(map[string]string)
	for _, name := range []string{"unshare", "pasta", "nsenter", "ip", "nc", "sleep", "sysctl", "nft"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("L7 Firecracker acceptance requires %s", name)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatalf("L7 Firecracker acceptance could not resolve %s", name)
		}
		tools[name] = filepath.Clean(path)
	}
	return l7PreparedFirecrackerPrerequisites{firecracker: firecrackerPath, distribution: distribution, tools: tools}
}

type l7PreparedIntentResolver struct{ plan networkenforcement.Plan }

func (resolver *l7PreparedIntentResolver) ResolveL7RuntimeIntent(
	ctx context.Context,
	runtimeID string,
) (l7network.PrepareRequest, error) {
	if err := ctx.Err(); err != nil {
		return l7network.PrepareRequest{}, err
	}
	identity := l7network.Identity{
		SandboxID: "l7-fc-sandbox", ExecutionID: "l7-fc-execution", WorkerID: "l7-fc-worker",
		RuntimeGenerationID: runtimeID, PlanID: "l7-fc-plan", PolicySnapshotID: "l7-fc-policy",
		ProxySessionID: "l7-fc-proxy-session", ProxyGenerationID: "l7-fc-proxy-generation",
		TopologyGenerationID: "l7-fc-topology-generation", RuleGenerationID: "l7-fc-rule-generation",
	}
	return l7network.PrepareRequest{Identity: identity, Plan: resolver.plan}, nil
}

type l7PreparedAssetResolver struct {
	distribution localresolver.VerifiedDistribution
}

func (resolver *l7PreparedAssetResolver) AcquireL7RuntimeAssets(
	ctx context.Context,
	_ l7network.Identity,
) (L7RuntimeAssets, error) {
	if err := ctx.Err(); err != nil {
		return L7RuntimeAssets{}, err
	}
	profile, ok := resolver.distribution.L7Profile()
	if !ok {
		return L7RuntimeAssets{}, errL7PreparedAssetResolution
	}
	lease, err := resolver.distribution.AcquireL7AssetLease()
	if err != nil {
		return L7RuntimeAssets{}, errL7PreparedAssetResolution
	}
	descriptor := resolver.distribution.Descriptor
	return L7RuntimeAssets{
		LaunchDescriptor: &descriptor, VerifiedL7Profile: &profile, VerifiedL7Assets: lease,
	}, nil
}

func l7PreparedNetworkPlan() networkenforcement.Plan {
	return networkenforcement.BuildPlan(networkenforcement.PlanRequest{
		ID: "l7-fc-plan", Source: networkenforcement.PlanSourceRuntime, Operation: "l7_firecracker_topology",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{
			ID: "l7-fc-policy", Version: "v1", Preset: networkenforcement.PolicyPresetAllowListed,
			RuleSetID: "l7-fc-rules",
		},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{
			Preset: networkenforcement.PolicyPresetAllowListed, DefaultPosture: networkenforcement.DefaultPostureDenyByDefault,
			AllowlistMode: networkenforcement.AllowlistModeEnforce, RuleSetID: "l7-fc-rules",
			PrivateNetwork: networkenforcement.PostureBlock, MetadataEndpoint: networkenforcement.PostureBlock,
			TCP: networkenforcement.PostureBlock, UDP: networkenforcement.PostureBlock, ICMP: networkenforcement.PostureBlock,
			HTTP: networkenforcement.ProxyRoutingModeRouteViaProxy, HTTPS: networkenforcement.ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "l7-fc-proxy-session", ProxyMechanism: networkenforcement.EnforcementMechanismProxy,
			FirewallMode: networkenforcement.FirewallIntentModeApply, FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
			AllowlistRules: l7PreparedAllowlistRules(),
		},
	})
}

func l7PreparedAllowlistRules() []networkenforcement.AllowlistRule {
	return []networkenforcement.AllowlistRule{{
		ID: "l7-fc-allow", Category: networkenforcement.AllowlistRuleCategoryDomain, Value: "allowed.invalid",
	}}
}

func waitForL7PreparedContainedTarget(
	t *testing.T,
	driver *microvm.Driver,
	target sandboxruntime.Target,
) *sandboxruntime.Target {
	t.Helper()
	deadline := time.Now().Add(l7PreparedContainmentPollLimit)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		inspected, _ := driver.Inspect(ctx, sandboxruntime.InspectRequest{Target: target})
		cancel()
		if inspected != nil {
			target = *inspected
			if inspected.Status == string(l7network.StatusStopped) {
				return inspected
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("L7 proxy loss did not complete exact Firecracker containment")
	return nil
}

func l7PreparedPrivateDir(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal("create private L7 acceptance directory failed")
	}
	return path
}

func l7PreparedFileSHA256(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func l7PreparedFirstLine(payload []byte) string {
	line, _, _ := strings.Cut(string(payload), "\n")
	return strings.TrimSpace(line)
}
