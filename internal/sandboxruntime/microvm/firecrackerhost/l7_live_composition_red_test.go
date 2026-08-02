package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

func TestL7LiveDriverConstructionIsExplicitAndFailsBeforeMutation(t *testing.T) {
	intent := &l7CompositionIntentResolver{}
	assets := &l7CompositionAssetResolver{}
	starter := &l7CompositionNamespaceStarter{}

	driver, err := NewL7LiveDriver(L7LiveDriverOptions{
		Live:             LiveDriverOptions{},
		Intent:           intent,
		Assets:           assets,
		NamespaceStarter: starter,
		NSenterPath:      filepath.Join(string(filepath.Separator), "usr", "bin", "nsenter"),
	})
	if driver != nil || err == nil {
		t.Fatalf("NewL7LiveDriver(incomplete) = %#v, %v, want fail-closed construction", driver, err)
	}
	if intent.calls != 0 || assets.calls != 0 || starter.calls != 0 {
		t.Fatalf("construction crossed live boundary: intent=%d assets=%d starts=%d", intent.calls, assets.calls, starter.calls)
	}
	assertL7CompositionSanitizedError(t, err)
}

func TestL7LiveDriverDefaultPathsRemainInert(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "..", "..", "cmd"),
		filepath.Join("..", "..", "..", "sandboxworker"),
		filepath.Join("..", "..", "..", "sandboxexec"),
	}
	for _, root := range files {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			payload, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(payload), "NewL7LiveDriver(") {
				t.Fatalf("default production path %s enabled explicit L7 live construction", filepath.Base(path))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Existing generic construction remains planning-only unless its own
	// explicit LiveStart dependencies are supplied.
	options, err := NewLiveBackendOptions(LiveDriverOptions{})
	if err == nil || options.LiveStart {
		t.Fatalf("NewLiveBackendOptions(zero) = %#v, %v, want inert rejection", options, err)
	}
}

func TestL7LiveDriverReachesConcreteCoordinatorBeforeAnyVMStart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only explicit composition")
	}
	proxy := &l7CompositionProxy{}
	intent := &l7CompositionDynamicIntentResolver{}
	assets := &l7CompositionAssetResolver{}
	starter := &l7CompositionNamespaceStarter{}
	tap, err := l7network.NewLinuxTAP(l7network.TAPOptions{
		IPPath: "/usr/bin/ip", SysctlPath: "/usr/sbin/sysctl", NsenterPath: "/usr/bin/nsenter",
		Command: l7CompositionNamespaceCommand{},
	})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := NewL7LiveDriver(L7LiveDriverOptions{
		Live: LiveDriverOptions{
			Config: liveDriverValidConfig(), BaseStateDir: firecrackerHostShortSocketTestRoot(t),
			CapabilityDetector: liveDriverAvailableDetector{}, BootAcceptancePoller: &fakeBootAcceptancePoller{},
		},
		Intent: intent, Assets: assets, NamespaceStarter: starter, NSenterPath: "/usr/bin/nsenter",
		Topology: l7network.Options{
			Proxy: proxy, Topology: l7CompositionTopology{}, TAP: tap,
			Rules:    linuxrules.NewAdapter(l7CompositionNFTExecutor{}, linuxrules.AdapterOptions{}),
			StateDir: t.TempDir(),
		},
	})
	if err != nil {
		t.Fatalf("NewL7LiveDriver() error = %v", err)
	}
	target, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "l7-composed-order"})
	if err != nil {
		t.Fatal(err)
	}
	if target.ID == "" || target.ID != target.Runtime.RuntimeID || target.Provider != "firecracker" ||
		target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatalf("Create() target identity = %#v, want exact Firecracker runtime binding", target)
	}
	intent.runtimeID = target.Runtime.RuntimeID
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *target})
	if started != nil || err == nil {
		t.Fatalf("Start(proxy failure) = %#v, %v, want contained failure", started, err)
	}
	if intent.calls != 1 || proxy.starts != 1 {
		t.Fatalf("composition calls = intent:%d proxy:%d, want concrete coordinator ordering", intent.calls, proxy.starts)
	}
	if assets.calls != 0 || starter.calls != 0 {
		t.Fatalf("VM boundary crossed before topology proof: assets=%d starts=%d", assets.calls, starter.calls)
	}
	assertL7CompositionSanitizedError(t, err)
}

func TestL7ProcessTrackerRequiresAttemptedUnambiguousNoProcessProof(t *testing.T) {
	tracker := &l7ProcessTracker{lifecycle: NewProcessLifecycleManager(l7CompositionStartErrorRunner{
		err: ErrNamespaceProcessStartFailed,
	})}
	if tracker.absenceConfirmed() {
		t.Fatal("unused tracker claimed no-process termination")
	}
	if _, err := tracker.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{}); err == nil {
		t.Fatal("StartProcess(unambiguous failure) error = nil")
	}
	if !tracker.absenceConfirmed() {
		t.Fatal("contained namespace start failure did not prove process absence")
	}

	tracker = &l7ProcessTracker{lifecycle: NewProcessLifecycleManager(l7CompositionStartErrorRunner{
		err: errors.Join(ErrNamespaceProcessStartFailed, ErrNamespaceProcessCleanupIncomplete),
	})}
	if _, err := tracker.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{}); err == nil {
		t.Fatal("StartProcess(ambiguous failure) error = nil")
	}
	if tracker.absenceConfirmed() {
		t.Fatal("ambiguous namespace start failure claimed no-process termination")
	}
}

func TestL7TerminatedBindingRetriesRetainedNamespaceProcessCleanup(t *testing.T) {
	identity := l7RuntimeControllerIdentity("retained-process")
	process := &l7CompositionRetryCleanupProcess{killFailures: 1}
	runner := &NamespaceProcessRunner{retained: process, cleanupTimeout: time.Second}
	lifecycle := NewProcessLifecycleManager(runner)
	tracker := &l7ProcessTracker{lifecycle: lifecycle, attempted: true, uncertain: true}
	runtime := &productionL7FirecrackerRuntime{
		identity: identity, lifecycle: lifecycle, tracker: tracker,
	}

	if binding, err := runtime.TerminatedVMBinding(identity, sandboxruntime.Target{}); binding != nil || err == nil {
		t.Fatalf("TerminatedVMBinding(first retained cleanup) = %T, %v; want retained failure", binding, err)
	}
	if binding, err := runtime.TerminatedVMBinding(identity, sandboxruntime.Target{}); binding == nil || err != nil {
		t.Fatalf("TerminatedVMBinding(retry) = %T, %v; want exact no-process proof", binding, err)
	}
	if process.killCalls != 2 || process.waitCalls != 2 || runner.retained != nil {
		t.Fatalf("retained cleanup = kills:%d waits:%d retained:%T; want two exact attempts and release",
			process.killCalls, process.waitCalls, runner.retained)
	}
	if !tracker.absenceConfirmed() {
		t.Fatal("successful retained cleanup did not establish process absence")
	}
}

func TestL7PreparedLinuxE2ECleanupIsAuditableAndPreservesFailedRecovery(t *testing.T) {
	payload, err := os.ReadFile("l7_prepared_linux_e2e_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	for _, forbidden := range []string{
		"t.Cleanup(func() { _ = os.RemoveAll(root) })",
		"stopped, _ := driver.Stop",
		"_ = driver.Delete",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("prepared Linux E2E silently discards cleanup evidence: %q", forbidden)
		}
	}
	for _, required := range []string{
		"cleanupFailures = errors.Join",
		"preserving L7 recovery state",
		"if cleanupFailures == nil",
		"preserveRecoveryState = true",
		"deleteConfirmed := false",
		"cleanupPending && !deleteConfirmed",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("prepared Linux E2E lacks auditable cleanup marker %q", required)
		}
	}
	disarm := strings.Index(source, "cleanupPending = false")
	proxyAudit := strings.Index(source, "if _, active := adapter.Endpoint()")
	deleteBoundary := strings.LastIndex(source, "if err := driver.Delete(")
	stateAudit := strings.Index(source, "entries, err := os.ReadDir(stateRoot)")
	if disarm < 0 || proxyAudit < 0 || deleteBoundary < 0 || stateAudit < 0 ||
		proxyAudit > deleteBoundary || deleteBoundary > stateAudit || disarm < stateAudit {
		t.Fatalf("prepared Linux E2E cleanup ordering = proxy:%d delete:%d state:%d disarm:%d; want live audit before delete and evidence audit before disarm",
			proxyAudit, deleteBoundary, stateAudit, disarm)
	}
}

func TestL7FirecrackerFactoryComposesNamespaceAndProofRequiredVsockWithoutStarting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only explicit composition")
	}
	identity := l7RuntimeControllerIdentity("factory")
	namespace := &l7CompositionNamespaceProvider{}
	starter := &l7CompositionNamespaceStarter{}
	factory := &productionL7FirecrackerFactory{
		live: LiveDriverOptions{
			BootAcceptancePoller: &fakeBootAcceptancePoller{},
		},
		baseStateDir: firecrackerHostShortSocketTestRoot(t), namespaceStarter: starter,
		nsenterPath: "/usr/bin/nsenter",
	}
	runtimeController, err := factory.NewL7FirecrackerRuntime(context.Background(), l7FirecrackerRuntimeRequest{
		Identity: identity, TopologyGenerationID: identity.TopologyGenerationID,
		LiveConfigProvider: &l7LiveConfigSlot{runtimeGenerationID: identity.RuntimeGenerationID}, Namespace: namespace,
	})
	if err != nil {
		t.Fatalf("NewL7FirecrackerRuntime() error = %v", err)
	}
	composed, ok := runtimeController.(*productionL7FirecrackerRuntime)
	if !ok || composed.lifecycle == nil || composed.tracker == nil || composed.bridge == nil {
		t.Fatalf("runtime = %T, want concrete lifecycle/tracker/bridge composition", runtimeController)
	}
	runner, ok := composed.lifecycle.runner.(*NamespaceProcessRunner)
	if !ok || runner.namespace != namespace || runner.starter != starter {
		t.Fatalf("lifecycle runner = %#v, want exact namespace-bound runner", composed.lifecycle.runner)
	}
	if !composed.bridge.requireIsolationProof || !composed.bridge.requireNetworkProof ||
		composed.bridge.isolationProofGeneration != identity.TopologyGenerationID {
		t.Fatalf("bridge proof config = isolation:%t network:%t generation:%q",
			composed.bridge.requireIsolationProof, composed.bridge.requireNetworkProof, composed.bridge.isolationProofGeneration)
	}
	if namespace.calls != 0 || starter.calls != 0 {
		t.Fatalf("construction mutated live state: namespace=%d starts=%d", namespace.calls, starter.calls)
	}
}

func TestL7LiveDriverRejectsNonLinuxBeforeLiveResolution(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux fail-closed construction is covered by cross-compile")
	}
	intent := &l7CompositionIntentResolver{}
	assets := &l7CompositionAssetResolver{}
	driver, err := NewL7LiveDriver(L7LiveDriverOptions{Intent: intent, Assets: assets})
	if driver != nil || err == nil {
		t.Fatalf("NewL7LiveDriver(non-Linux) = %#v, %v, want unsupported", driver, err)
	}
	if intent.calls != 0 || assets.calls != 0 {
		t.Fatal("non-Linux construction resolved live intent or assets")
	}
}

type l7CompositionIntentResolver struct{ calls int }

func (resolver *l7CompositionIntentResolver) ResolveL7RuntimeIntent(context.Context, string) (l7network.PrepareRequest, error) {
	resolver.calls++
	return l7network.PrepareRequest{}, errors.New("private endpoint=/run/private")
}

type l7CompositionDynamicIntentResolver struct {
	calls     int
	runtimeID string
}

func (resolver *l7CompositionDynamicIntentResolver) ResolveL7RuntimeIntent(_ context.Context, runtimeID string) (l7network.PrepareRequest, error) {
	resolver.calls++
	if runtimeID == "" || runtimeID != resolver.runtimeID {
		return l7network.PrepareRequest{}, errors.New("private runtime mismatch")
	}
	identity := l7RuntimeControllerIdentity("composition")
	identity.RuntimeGenerationID = runtimeID
	return l7network.PrepareRequest{Identity: identity, Plan: l7RuntimeControllerPlan(identity)}, nil
}

type l7CompositionAssetResolver struct{ calls int }

func (resolver *l7CompositionAssetResolver) AcquireL7RuntimeAssets(context.Context, l7network.Identity) (L7RuntimeAssets, error) {
	resolver.calls++
	return L7RuntimeAssets{}, errors.New("private asset=/home/private/rootfs")
}

type l7CompositionNamespaceStarter struct{ calls int }

func (starter *l7CompositionNamespaceStarter) StartNamespaceProcess(context.Context, NamespaceProcessStartRequest) (HostProcess, error) {
	starter.calls++
	return nil, errors.New("pid=4242 socket=/run/private.sock")
}

type l7CompositionStartErrorRunner struct{ err error }

func (runner l7CompositionStartErrorRunner) StartHostProcess(context.Context, firecracker.ProcessRunnerStartRequest) (HostProcess, error) {
	return nil, runner.err
}

type l7CompositionRetryCleanupProcess struct {
	killCalls    int
	waitCalls    int
	killFailures int
}

func (*l7CompositionRetryCleanupProcess) Signal(context.Context, ProcessSignal) error { return nil }

func (process *l7CompositionRetryCleanupProcess) Kill(context.Context) error {
	process.killCalls++
	if process.killFailures > 0 {
		process.killFailures--
		return errors.New("private retained cleanup failure")
	}
	return nil
}

func (process *l7CompositionRetryCleanupProcess) Wait(context.Context) error {
	process.waitCalls++
	return nil
}

type l7CompositionNamespaceProvider struct{ calls int }

func (provider *l7CompositionNamespaceProvider) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	provider.calls++
	return nil, nil, errors.New("private namespace descriptors")
}

type l7CompositionProxy struct{ starts int }

func (proxy *l7CompositionProxy) Start(context.Context, networkenforcement.Plan) (l7network.ProxyGeneration, error) {
	proxy.starts++
	return nil, errors.New("private proxy endpoint")
}

func (*l7CompositionProxy) Endpoint(l7network.ProxyGeneration) (string, error) {
	return "", errors.New("private proxy endpoint")
}

func (*l7CompositionProxy) Active(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error {
	return errors.New("private proxy endpoint")
}

func (*l7CompositionProxy) Stop(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error {
	return nil
}

type l7CompositionTopology struct{}

func (l7CompositionTopology) Start(context.Context, linuxtopology.StartRequest) (l7network.TopologySession, error) {
	return nil, errors.New("private topology")
}

func (l7CompositionTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	return linuxtopology.Metadata{}, errors.New("private topology")
}

type l7CompositionNamespaceCommand struct{}

func (l7CompositionNamespaceCommand) Run(context.Context, l7network.NamespaceLease, l7network.NamespaceCommandRequest, int64) ([]byte, error) {
	return nil, errors.New("private namespace command")
}

type l7CompositionNFTExecutor struct{}

func (l7CompositionNFTExecutor) ApplyBatch(context.Context, linuxrules.NamespaceHandle, []byte) error {
	return errors.New("private nft batch")
}

func (l7CompositionNFTExecutor) ListTableJSON(context.Context, linuxrules.NamespaceHandle, linuxrules.TableQuery, int64) ([]byte, error) {
	return nil, errors.New("private nft inspection")
}

func assertL7CompositionSanitizedError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil")
	}
	for _, forbidden := range []string{"/run/", "/home/", "4242", "private.sock", "endpoint="} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
	var operation *microvm.OperationError
	if !errors.As(err, &operation) && !errors.Is(err, ErrL7LiveCompositionInvalid) {
		t.Fatalf("error = %T %v, want structured or stable L7 construction error", err, err)
	}
}
