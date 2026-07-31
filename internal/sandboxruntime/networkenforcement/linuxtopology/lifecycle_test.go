package linuxtopology

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testEndpoint = "127.0.0.1:43123"
	testGuestIP  = "192.0.2.2"
	testIface    = "halpasta0"
)

func testIdentity(generation string) Identity {
	return Identity{
		SandboxID:            "sandbox-l7",
		ExecutionID:          "execution-l7",
		WorkerID:             "worker-l7",
		RuntimeID:            "runtime-l7",
		PlanID:               "plan-l7",
		PolicySnapshotID:     "policy-l7",
		ProxySessionID:       "proxy-l7",
		ProxyGenerationID:    "proxy-generation-l7",
		TopologyGenerationID: generation,
	}
}

func testRequest(generation string) StartRequest {
	return StartRequest{
		Identity: testIdentity(generation),
		Mapping: Mapping{
			ProxyEndpoint:      testEndpoint,
			GuestProxyAddress:  testGuestIP,
			NamespaceInterface: testIface,
		},
	}
}

func testTools() ToolPaths {
	return ToolPaths{
		Unshare: "/opt/hal/bin/unshare",
		Pasta:   "/opt/hal/bin/pasta",
		Nsenter: "/opt/hal/bin/nsenter",
		IP:      "/opt/hal/bin/ip",
		NC:      "/opt/hal/bin/nc",
		Keeper:  "/opt/hal/bin/sleep",
	}
}

type fakeProcess struct {
	mu             sync.Mutex
	pid            int
	done           chan struct{}
	terminated     bool
	terminateCount int
	cleanupCtxErr  error
	hadDeadline    bool
	terminateErr   error
	events         *[]string
	role           ProcessRole
	once           sync.Once
}

func newFakeProcess(pid int, role ProcessRole, events *[]string) *fakeProcess {
	return &fakeProcess{pid: pid, done: make(chan struct{}), events: events, role: role}
}

func (p *fakeProcess) PID() int { return p.pid }

func (p *fakeProcess) Done() <-chan struct{} { return p.done }

func (p *fakeProcess) Terminate(ctx context.Context) error {
	p.mu.Lock()
	p.terminateCount++
	p.cleanupCtxErr = ctx.Err()
	_, p.hadDeadline = ctx.Deadline()
	if !p.terminated {
		p.terminated = true
		*p.events = append(*p.events, "stop:"+string(p.role))
	}
	p.mu.Unlock()
	p.once.Do(func() { close(p.done) })
	return p.terminateErr
}

func (p *fakeProcess) exit() { p.once.Do(func() { close(p.done) }) }

type fakeStarter struct {
	mu           sync.Mutex
	events       []string
	specs        []ProcessSpec
	processes    map[ProcessRole][]*fakeProcess
	failRole     ProcessRole
	failErr      error
	nextPID      int
	terminateErr map[ProcessRole]error
}

func newFakeStarter() *fakeStarter {
	return &fakeStarter{processes: make(map[ProcessRole][]*fakeProcess), terminateErr: make(map[ProcessRole]error), nextPID: 4100}
}

func (f *fakeStarter) Start(_ context.Context, spec ProcessSpec) (ProcessHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "start:"+string(spec.Role))
	f.specs = append(f.specs, cloneProcessSpec(spec))
	if spec.Role == f.failRole {
		return nil, f.failErr
	}
	f.nextPID++
	p := newFakeProcess(f.nextPID, spec.Role, &f.events)
	p.terminateErr = f.terminateErr[spec.Role]
	f.processes[spec.Role] = append(f.processes[spec.Role], p)
	return p, nil
}

func (f *fakeStarter) latest(role ProcessRole) *fakeProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := f.processes[role]
	if len(items) == 0 {
		return nil
	}
	return items[len(items)-1]
}

func (f *fakeStarter) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.specs)
}

func (f *fakeStarter) eventSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

type fakeRunner struct {
	mu            sync.Mutex
	events        *[]string
	specs         []ProcessSpec
	output        []byte
	addressOutput []byte
	v4RouteOutput []byte
	v6RouteOutput []byte
	err           error
}

type fakeReachabilityProber struct {
	mu         sync.Mutex
	calls      int
	mappings   []Mapping
	identities []Identity
	err        error
}

func (f *fakeReachabilityProber) Probe(_ context.Context, _ *NamespaceHandle, identity Identity, mapping Mapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.mappings = append(f.mappings, mapping)
	f.identities = append(f.identities, identity)
	return f.err
}

func (f *fakeRunner) Run(_ context.Context, spec ProcessSpec) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events != nil {
		*f.events = append(*f.events, "run:"+string(spec.Role))
	}
	f.specs = append(f.specs, cloneProcessSpec(spec))
	output := f.output
	joined := strings.Join(spec.Args, " ")
	if string(f.output) == string(goodLinkJSON()) {
		switch {
		case strings.Contains(joined, " address show"):
			output = goodAddressJSON()
			if f.addressOutput != nil {
				output = f.addressOutput
			}
		case strings.Contains(joined, " -4 route show"):
			output = goodIPv4RouteJSON()
			if f.v4RouteOutput != nil {
				output = f.v4RouteOutput
			}
		case strings.Contains(joined, " -6 route show"):
			output = goodIPv6RouteJSON()
			if f.v6RouteOutput != nil {
				output = f.v6RouteOutput
			}
		}
	}
	return append([]byte(nil), output...), f.err
}

func goodLinkJSON() []byte {
	return []byte(`[
		{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"]},
		{"ifindex":7,"ifname":"halpasta0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"]}
	]`)
}

func goodAddressJSON() []byte {
	return []byte(`[
		{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},
		{"ifindex":7,"ifname":"halpasta0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"},{"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"},{"family":"inet6","local":"fe80::10","prefixlen":64,"scope":"link"}]}
	]`)
}

func goodIPv4RouteJSON() []byte {
	return []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"halpasta0"},{"dst":"192.0.2.0/24","dev":"halpasta0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10"}]`)
}

func goodIPv6RouteJSON() []byte {
	return []byte(`[{"dst":"default","gateway":"2001:db8::1","dev":"halpasta0"},{"dst":"2001:db8::/64","dev":"halpasta0","protocol":"kernel"},{"dst":"fe80::/64","dev":"halpasta0","protocol":"kernel"}]`)
}

func goodAddressEvidence() interfaceAddressEvidence {
	evidence, valid := inspectAddressEvidence(goodAddressJSON(), testIface)
	if !valid {
		panic("invalid fixed address evidence")
	}
	return evidence
}

type fakeNamespaces struct {
	mu     sync.Mutex
	t      *testing.T
	base   *NamespaceHandle
	opened []*NamespaceHandle
	events *[]string
	failAt int
	err    error
}

func newFakeNamespaces(t *testing.T, events *[]string) *fakeNamespaces {
	t.Helper()
	user, err := os.CreateTemp(t.TempDir(), "user-ns-")
	if err != nil {
		t.Fatal(err)
	}
	netns, err := os.CreateTemp(t.TempDir(), "net-ns-")
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceHandle(user, netns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	return &fakeNamespaces{t: t, base: base, events: events}
}

func (f *fakeNamespaces) Open(_ int) (*NamespaceHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events != nil {
		*f.events = append(*f.events, "open:namespaces")
	}
	if f.failAt > 0 && len(f.opened)+1 == f.failAt {
		return nil, f.err
	}
	handle, err := f.base.Duplicate()
	if err != nil {
		f.t.Fatal(err)
	}
	f.opened = append(f.opened, handle)
	return handle, nil
}

func (f *fakeNamespaces) allClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, handle := range f.opened {
		if !handle.Closed() {
			return false
		}
	}
	return true
}

func newTestLifecycle(t *testing.T, starter *fakeStarter, runner *fakeRunner, namespaces *fakeNamespaces) *Lifecycle {
	t.Helper()
	if runner.events == nil {
		runner.events = &starter.events
	}
	if namespaces.events == nil {
		namespaces.events = &starter.events
	}
	lifecycle, err := New(Config{
		Enabled:            true,
		Tools:              testTools(),
		Starter:            starter,
		Runner:             runner,
		OpenNamespaces:     namespaces.Open,
		Reachability:       &fakeReachabilityProber{},
		CleanupTimeout:     250 * time.Millisecond,
		InspectionTimeout:  250 * time.Millisecond,
		InspectionInterval: time.Millisecond,
		OutputLimit:        8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func TestLinuxTopologyDefaultIsDisabledAndStartsNothing(t *testing.T) {
	starter := newFakeStarter()
	lifecycle, err := New(Config{Starter: starter})
	if err != nil {
		t.Fatal(err)
	}
	_, err = lifecycle.Start(context.Background(), testRequest("topology-gen-1"))
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("Start error = %v, want ErrDisabled", err)
	}
	if got := starter.startCount(); got != 0 {
		t.Fatalf("process starts = %d, want 0", got)
	}
}

func TestLinuxTopologyRejectsUnsafeInputsBeforeProcessStart(t *testing.T) {
	tests := []struct {
		name      string
		mutateCfg func(*Config)
		mutateReq func(*StartRequest)
		want      error
	}{
		{name: "empty identity", mutateReq: func(r *StartRequest) { r.Identity.PlanID = "" }, want: ErrInvalidIdentity},
		{name: "empty proxy generation", mutateReq: func(r *StartRequest) { r.Identity.ProxyGenerationID = "" }, want: ErrInvalidIdentity},
		{name: "unsafe identity", mutateReq: func(r *StartRequest) { r.Identity.SandboxID = "../sandbox" }, want: ErrInvalidIdentity},
		{name: "duplicate identity", mutateReq: func(r *StartRequest) { r.Identity.PlanID = r.Identity.RuntimeID }, want: ErrInvalidIdentity},
		{name: "relative tool", mutateCfg: func(c *Config) { c.Tools.Pasta = "bin/pasta" }, want: ErrInvalidTools},
		{name: "unclean tool", mutateCfg: func(c *Config) { c.Tools.IP = "/opt/../tmp/ip" }, want: ErrInvalidTools},
		{name: "non loopback endpoint", mutateReq: func(r *StartRequest) { r.Mapping.ProxyEndpoint = "198.51.100.2:80" }, want: ErrInvalidMapping},
		{name: "missing endpoint port", mutateReq: func(r *StartRequest) { r.Mapping.ProxyEndpoint = "127.0.0.1:0" }, want: ErrInvalidMapping},
		{name: "unsafe guest address", mutateReq: func(r *StartRequest) { r.Mapping.GuestProxyAddress = "127.0.0.1" }, want: ErrInvalidMapping},
		{name: "mismatched mapping family", mutateReq: func(r *StartRequest) { r.Mapping.GuestProxyAddress = "2001:db8::2" }, want: ErrInvalidMapping},
		{name: "unsafe interface", mutateReq: func(r *StartRequest) { r.Mapping.NamespaceInterface = "bad;if" }, want: ErrInvalidMapping},
		{name: "uncontrolled environment", mutateCfg: func(c *Config) { c.Environment = []string{"PATH=/tmp/unsafe"} }, want: ErrInvalidTools},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			starter := newFakeStarter()
			runner := &fakeRunner{output: goodLinkJSON()}
			namespaces := newFakeNamespaces(t, &starter.events)
			cfg := Config{
				Enabled: true, Tools: testTools(), Starter: starter, Runner: runner,
				OpenNamespaces: namespaces.Open,
			}
			if tt.mutateCfg != nil {
				tt.mutateCfg(&cfg)
			}
			lifecycle, err := New(cfg)
			if err == nil {
				req := testRequest("topology-gen-1")
				if tt.mutateReq != nil {
					tt.mutateReq(&req)
				}
				_, err = lifecycle.Start(context.Background(), req)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if got := starter.startCount(); got != 0 {
				t.Fatalf("process starts = %d, want 0", got)
			}
		})
	}
}

func TestLinuxTopologyStartsKeeperThenExactPastaMappingAndInspects(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)

	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lifecycle.Stop(context.Background(), testIdentity("topology-gen-1")) })

	wantEvents := []string{
		"start:keeper", "open:namespaces", "start:mapping", "open:namespaces", "open:namespaces",
		"run:inspection", "run:inspection", "run:inspection", "run:inspection",
	}
	if got := starter.eventSnapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("events = %#v, want %#v", got, wantEvents)
	}
	if len(starter.specs) != 2 {
		t.Fatalf("start specs = %d, want 2", len(starter.specs))
	}
	keeper := starter.specs[0]
	if keeper.Path != testTools().Unshare || keeper.Role != ProcessRoleKeeper {
		t.Fatalf("keeper = %#v", keeper)
	}
	wantKeeperArgs := []string{"--user", "--map-current-user", "--net", "--", testTools().Keeper, "infinity"}
	if !reflect.DeepEqual(keeper.Args, wantKeeperArgs) {
		t.Fatalf("keeper argv = %#v, want %#v", keeper.Args, wantKeeperArgs)
	}
	if len(keeper.Env) != 0 || len(keeper.ExtraFiles) != 0 {
		t.Fatalf("keeper inherited environment or files: %#v", keeper)
	}

	mapping := starter.specs[1]
	wantMappingArgs := []string{
		"--foreground", "--quiet",
		"--config-net",
		"--no-copy-routes",
		"--userns", "/proc/4101/ns/user",
		"--netns", "/proc/4101/ns/net",
		"--map-host-loopback", testGuestIP,
		"--no-map-gw",
		"-t", "none", "-u", "none", "-T", "none", "-U", "none",
		"-I", testIface,
	}
	if mapping.Path != testTools().Pasta || mapping.Role != ProcessRoleMapping || !reflect.DeepEqual(mapping.Args, wantMappingArgs) {
		t.Fatalf("mapping spec = %#v, want argv %#v", mapping, wantMappingArgs)
	}
	if len(mapping.Env) != 0 || len(mapping.ExtraFiles) != 0 {
		t.Fatalf("mapping environment/files = %#v", mapping)
	}
	joined := strings.Join(mapping.Args, " ")
	for _, forbidden := range []string{"--map-guest-addr", " --ipv4-only", " --ipv6-only", " -4", " -6", testEndpoint} {
		if strings.Contains(" "+joined, forbidden) {
			t.Fatalf("mapping argv contains forbidden value %q: %q", forbidden, joined)
		}
	}

	if len(runner.specs) != 4 {
		t.Fatalf("inspection specs = %d, want 4", len(runner.specs))
	}
	inspection := runner.specs[0]
	wantInspectionArgs := []string{
		"--preserve-credentials",
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--", testTools().IP, "-json", "link", "show",
	}
	if inspection.Path != testTools().Nsenter || inspection.Role != ProcessRoleInspection || !reflect.DeepEqual(inspection.Args, wantInspectionArgs) {
		t.Fatalf("inspection spec = %#v, want argv %#v", inspection, wantInspectionArgs)
	}
	if len(inspection.ExtraFiles) != 2 || inspection.OutputLimit != 8<<10 {
		t.Fatalf("inspection files/limit = %#v", inspection)
	}
	if len(inspection.Env) != 0 {
		t.Fatalf("inspection inherited environment: %#v", inspection.Env)
	}

	metadata := session.Metadata()
	if metadata.Status != StatusPrepared || !metadata.StructuralInspected || !metadata.MappingReachable || metadata.Identity != testIdentity("topology-gen-1") {
		t.Fatalf("metadata = %#v", metadata)
	}
	owned, err := session.NamespaceHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	if !owned.Correlates(namespaces.base) {
		t.Fatal("session namespace handle did not preserve owning device/inode correlation")
	}
}

func TestLinuxTopologyRequiresExactStructuralAndReachabilityProof(t *testing.T) {
	if !validAddressInspection([]byte(`[
		{"ifindex":1,"ifname":"lo","addr_info":[
			{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},
			{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}
		]},
		{"ifindex":7,"ifname":"halpasta0","addr_info":[
			{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"},
			{"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"},
			{"family":"inet6","local":"fe80::10","prefixlen":64,"scope":"link"}
		]}
	]`), testIface) {
		t.Fatal("exact dual-stack address inspection rejected")
	}
	if !validRouteInspection(
		goodIPv4RouteJSON(),
		goodIPv6RouteJSON(), testIface, goodAddressEvidence(),
	) {
		t.Fatal("exact dual-stack route inspection rejected")
	}
	for name, output := range map[string][]byte{
		"extra interface": []byte(`[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"]},{"ifindex":7,"ifname":"halpasta0","flags":["UP"]},{"ifindex":8,"ifname":"unexpected0","flags":["UP"]}]`),
		"missing IPv6":    []byte(`[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},{"ifindex":7,"ifname":"halpasta0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"}]}]`),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "extra interface" && validLinkInspection(output, testIface) {
				t.Fatal("inspection accepted an extra interface")
			}
			if name == "missing IPv6" && validAddressInspection(output, testIface) {
				t.Fatal("inspection accepted a missing address family")
			}
		})
	}
	for name, ipv4 := range map[string][]byte{
		"duplicate route":       []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"halpasta0"},{"dst":"192.0.2.0/24","dev":"halpasta0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10"},{"dst":"192.0.2.0/24","dev":"halpasta0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10"}]`),
		"second prefix variant": []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"halpasta0"},{"dst":"192.0.2.0/24","dev":"halpasta0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10"},{"dst":"192.0.2.0/24","dev":"halpasta0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","metric":1}]`),
		"zero prefix":           []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"halpasta0"},{"dst":"0.0.0.0/0","dev":"halpasta0","scope":"link"}]`),
		"bad protocol":          []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"halpasta0","protocol":"redirect"},{"dst":"192.0.2.0/24","dev":"halpasta0","scope":"link"}]`),
	} {
		t.Run(name, func(t *testing.T) {
			if validRouteInspection(ipv4, goodIPv6RouteJSON(), testIface, goodAddressEvidence()) {
				t.Fatal("inspection accepted route drift")
			}
		})
	}
	duplicateAddress := []byte(`[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},{"ifindex":7,"ifname":"halpasta0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"},{"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"},{"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"}]}]`)
	if validAddressInspection(duplicateAddress, testIface) {
		t.Fatal("inspection accepted duplicate address drift")
	}
}

func TestLinuxTopologyRejectsUnexpectedMetadataAndMismatchedRoutes(t *testing.T) {
	metadataRoute := []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"halpasta0"},{"dst":"192.0.2.0/24","dev":"halpasta0","scope":"link"},{"dst":"169.254.169.254/32","dev":"halpasta0","scope":"link"}]`)
	if validRouteInspection(metadataRoute, goodIPv6RouteJSON(), testIface, goodAddressEvidence()) {
		t.Fatal("route proof accepted an unjustified metadata route")
	}

	starter := newFakeStarter()
	runner := &fakeRunner{
		output: goodLinkJSON(),
		addressOutput: []byte(`[
			{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},
			{"ifindex":7,"ifname":"halpasta0","addr_info":[{"family":"inet","local":"198.51.100.10","prefixlen":24,"scope":"global"},{"family":"inet6","local":"2001:db8:1::10","prefixlen":64,"scope":"global"},{"family":"inet6","local":"fe80::10","prefixlen":64,"scope":"link"}]}
		]`),
	}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	if session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-route-mismatch")); !errors.Is(err, ErrInspectionFailed) || session != nil {
		t.Fatalf("mismatched address/route proof = %#v, %v, want nil ErrInspectionFailed", session, err)
	}
}

func TestLinuxTopologyRejectsNonCanonicalHostLoopback(t *testing.T) {
	request := testRequest("topology-gen-loopback-correlation")
	request.Mapping.ProxyEndpoint = "127.0.0.2:43123"
	if validMapping(request.Mapping) {
		t.Fatal("mapping accepted a non-canonical IPv4 host loopback")
	}
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	if session, err := lifecycle.Start(context.Background(), request); !errors.Is(err, ErrInvalidMapping) || session != nil {
		t.Fatalf("Start = %#v, %v, want nil ErrInvalidMapping", session, err)
	}
	if starter.startCount() != 0 {
		t.Fatal("invalid loopback mapping crossed the process boundary")
	}
}

func TestLinuxTopologyReachabilityFailureNeverPublishesActive(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	prober := &fakeReachabilityProber{err: errors.New("dial endpoint secret")}
	lifecycle, err := New(Config{
		Enabled: true, Tools: testTools(), Starter: starter, Runner: runner,
		OpenNamespaces: namespaces.Open, Reachability: prober,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-probe"))
	if !errors.Is(err, ErrInspectionFailed) || session != nil {
		t.Fatalf("Start = %#v, %v, want nil ErrInspectionFailed", session, err)
	}
	if prober.calls == 0 {
		t.Fatal("reachability boundary was not called")
	}
	if len(prober.identities) == 0 || prober.identities[0] != testIdentity("topology-gen-probe") {
		t.Fatalf("probe identity = %#v", prober.identities)
	}
}

func TestLinuxTopologyProductionProbeUsesStructuredArgvAndEmptyEnvironment(t *testing.T) {
	runner := &fakeRunner{}
	namespaces := newFakeNamespaces(t, nil)
	handle, err := namespaces.base.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	prober := commandReachabilityProber{runner: runner, tools: testTools(), limit: 4096}
	if err := prober.Probe(context.Background(), handle, testIdentity("topology-gen-probe-argv"), testRequest("topology-gen-probe-argv").Mapping); err != nil {
		t.Fatal(err)
	}
	if len(runner.specs) != 1 {
		t.Fatalf("probe specs = %d, want 1", len(runner.specs))
	}
	spec := runner.specs[0]
	want := []string{
		"--preserve-credentials", "--user=/proc/self/fd/3", "--net=/proc/self/fd/4",
		"--", testTools().NC, "-4", "-z", "-w", "2", testGuestIP, "43123",
	}
	if spec.Role != ProcessRoleProbe || spec.Path != testTools().Nsenter || !reflect.DeepEqual(spec.Args, want) {
		t.Fatalf("probe spec = %#v, want argv %#v", spec, want)
	}
	if len(spec.Env) != 0 || len(spec.ExtraFiles) != 2 || spec.OutputLimit != 4096 {
		t.Fatalf("probe live boundary = %#v", spec)
	}
}

func TestLinuxTopologyPublicJSONOmitsAllLiveState(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lifecycle.Stop(context.Background(), testIdentity("topology-gen-json")) })

	values := []any{
		Config{Enabled: true, Tools: testTools(), Environment: []string{"LANG=C.UTF-8"}, StateDir: "/private/state-secret"},
		testRequest("topology-gen-json"), testTools(), starter.specs[0], starter.specs[1],
		runner.specs[0], session, session.Metadata(), namespaces.opened[0],
	}
	for _, value := range values {
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %T: %v", value, err)
		}
		text := string(payload)
		for _, leak := range []string{
			testEndpoint, testGuestIP, testIface, "/opt/hal", "/proc/", "43123",
			"4101", "device", "inode", "argv", "extraFiles",
			"state-secret", `"active"`,
		} {
			if strings.Contains(text, leak) {
				t.Fatalf("%T JSON leaked %q: %s", value, leak, text)
			}
		}
	}
}

func TestLinuxTopologyStructuralInspectionRejectsDrift(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{name: "missing loopback", output: `[{"ifindex":7,"ifname":"halpasta0","flags":["UP"]}]`},
		{name: "loopback down", output: `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK"]},{"ifindex":7,"ifname":"halpasta0","flags":["UP"]}]`},
		{name: "mapping missing", output: `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"]}]`},
		{name: "mapping down", output: `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"]},{"ifindex":7,"ifname":"halpasta0","flags":["BROADCAST"]}]`},
		{name: "duplicate index", output: `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"]},{"ifindex":1,"ifname":"halpasta0","flags":["UP"]}]`},
		{name: "malformed", output: `{not-json`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			starter := newFakeStarter()
			runner := &fakeRunner{output: []byte(tt.output)}
			namespaces := newFakeNamespaces(t, &starter.events)
			lifecycle := newTestLifecycle(t, starter, runner, namespaces)
			_, err := lifecycle.Start(context.Background(), testRequest("topology-gen-drift"))
			if !errors.Is(err, ErrInspectionFailed) {
				t.Fatalf("Start error = %v, want ErrInspectionFailed", err)
			}
			if got := starter.eventSnapshot(); !reflect.DeepEqual(got[len(got)-2:], []string{"stop:mapping", "stop:keeper"}) {
				t.Fatalf("cleanup tail = %#v, want reverse process cleanup", got)
			}
			if !namespaces.allClosed() {
				t.Fatal("namespace handles remained open after inspection failure")
			}
		})
	}
}

func TestLinuxTopologyNotifiesSanitizedMappingAndKeeperLoss(t *testing.T) {
	for _, role := range []ProcessRole{ProcessRoleMapping, ProcessRoleKeeper} {
		t.Run(string(role), func(t *testing.T) {
			starter := newFakeStarter()
			runner := &fakeRunner{output: goodLinkJSON()}
			namespaces := newFakeNamespaces(t, &starter.events)
			lifecycle := newTestLifecycle(t, starter, runner, namespaces)
			session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-loss"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = lifecycle.Stop(context.Background(), testIdentity("topology-gen-loss")) })

			starter.latest(role).exit()
			select {
			case loss := <-session.Losses():
				if loss.TopologyGenerationID != "topology-gen-loss" || loss.Component != role || loss.Reason != LossReasonProcessExited {
					t.Fatalf("loss = %#v", loss)
				}
				payload, err := json.Marshal(loss)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(payload), "pid") || strings.Contains(string(payload), "/proc/") {
					t.Fatalf("loss JSON leaked live state: %s", payload)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for loss notification")
			}
			if got := session.Metadata().Status; got != StatusLost {
				t.Fatalf("status = %q, want lost", got)
			}
		})
	}
}

func TestLinuxTopologyStopUsesIndependentBoundedContextAndReverseCleanup(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	_, err := lifecycle.Start(context.Background(), testRequest("topology-gen-cancel"))
	if err != nil {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	metadata, err := lifecycle.Stop(canceled, testIdentity("topology-gen-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Status != StatusStopped {
		t.Fatalf("status = %q, want stopped", metadata.Status)
	}
	if got := starter.eventSnapshot(); !reflect.DeepEqual(got[len(got)-2:], []string{"stop:mapping", "stop:keeper"}) {
		t.Fatalf("cleanup tail = %#v, want reverse cleanup", got)
	}
	for _, role := range []ProcessRole{ProcessRoleMapping, ProcessRoleKeeper} {
		process := starter.latest(role)
		if process.cleanupCtxErr != nil || !process.hadDeadline {
			t.Fatalf("%s cleanup context err/deadline = %v/%v", role, process.cleanupCtxErr, process.hadDeadline)
		}
	}
	if !namespaces.allClosed() {
		t.Fatal("owning namespace handles remained open")
	}
}

func TestLinuxTopologyCleanupUncertaintyIsSanitizedAndNotStopped(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	_, err := lifecycle.Start(context.Background(), testRequest("topology-gen-cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	starter.latest(ProcessRoleMapping).terminateErr = errors.New("kill pid=9876 endpoint=127.0.0.1:43123 token=secret")

	metadata, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-cleanup"))
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Stop error = %v, want ErrCleanupIncomplete", err)
	}
	if metadata.Status != StatusCleanupIncomplete {
		t.Fatalf("status = %q, want cleanup_incomplete", metadata.Status)
	}
	for _, leak := range []string{"9876", testEndpoint, "secret", "kill"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("cleanup error leaked %q: %v", leak, err)
		}
	}
}

func TestLinuxTopologyPartialStartCleansInReverseAndSanitizesErrors(t *testing.T) {
	t.Run("mapping start", func(t *testing.T) {
		starter := newFakeStarter()
		starter.failRole = ProcessRoleMapping
		starter.failErr = errors.New("fork failed pid=4411 /proc/4411/ns/net token=secret")
		runner := &fakeRunner{output: goodLinkJSON()}
		namespaces := newFakeNamespaces(t, &starter.events)
		lifecycle := newTestLifecycle(t, starter, runner, namespaces)
		_, err := lifecycle.Start(context.Background(), testRequest("topology-gen-partial"))
		if !errors.Is(err, ErrStartFailed) {
			t.Fatalf("error = %v, want ErrStartFailed", err)
		}
		for _, leak := range []string{"4411", "/proc/", "secret", "fork failed"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("public error leaked %q: %v", leak, err)
			}
		}
		if got := starter.eventSnapshot(); !reflect.DeepEqual(got, []string{"start:keeper", "open:namespaces", "start:mapping", "stop:keeper"}) {
			t.Fatalf("events = %#v", got)
		}
		if !namespaces.allClosed() {
			t.Fatal("namespace handles remained open")
		}
	})

	t.Run("namespace open", func(t *testing.T) {
		starter := newFakeStarter()
		runner := &fakeRunner{output: goodLinkJSON()}
		namespaces := newFakeNamespaces(t, &starter.events)
		namespaces.failAt = 1
		namespaces.err = errors.New("open /proc/991/ns/user: permission denied")
		lifecycle := newTestLifecycle(t, starter, runner, namespaces)
		_, err := lifecycle.Start(context.Background(), testRequest("topology-gen-partial-open"))
		if !errors.Is(err, ErrStartFailed) || strings.Contains(err.Error(), "/proc/") {
			t.Fatalf("unsafe namespace-open error = %v", err)
		}
		if got := starter.eventSnapshot(); !reflect.DeepEqual(got, []string{"start:keeper", "open:namespaces", "stop:keeper"}) {
			t.Fatalf("events = %#v", got)
		}
	})
}

func TestLinuxTopologyStaleOrMismatchedGenerationCannotCleanNewSession(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)

	_, err := lifecycle.Start(context.Background(), testRequest("topology-gen-old"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-old")); err != nil {
		t.Fatal(err)
	}
	_, err = lifecycle.Start(context.Background(), testRequest("topology-gen-new"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lifecycle.Stop(context.Background(), testIdentity("topology-gen-new")) })
	before := len(starter.eventSnapshot())

	if _, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-old")); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale Stop error = %v, want ErrStaleGeneration", err)
	}
	mismatch := testIdentity("topology-gen-new")
	mismatch.ProxySessionID = "proxy-other"
	if _, err := lifecycle.Stop(context.Background(), mismatch); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("mismatched Stop error = %v, want ErrIdentityMismatch", err)
	}
	if after := len(starter.eventSnapshot()); after != before {
		t.Fatalf("stale/mismatched cleanup changed events: before=%d after=%d", before, after)
	}
}

func TestLinuxTopologySameSessionChangedProxyGenerationIsRejected(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	request := testRequest("topology-gen-proxy-correlation")
	if _, err := lifecycle.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = lifecycle.Stop(context.Background(), request.Identity) })
	before := starter.startCount()
	changed := request
	changed.Identity.ProxyGenerationID = "proxy-generation-other"
	if _, err := lifecycle.Start(context.Background(), changed); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("changed proxy generation error = %v, want ErrIdentityMismatch", err)
	}
	if got := starter.startCount(); got != before {
		t.Fatalf("changed proxy generation started processes: before=%d after=%d", before, got)
	}
}

func TestLinuxTopologyConcurrentStartAndStopAreIdempotent(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)

	const callers = 24
	sessions := make(chan *Session, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-concurrent"))
			sessions <- session
			errs <- err
		}()
	}
	wg.Wait()
	close(sessions)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first *Session
	for session := range sessions {
		if first == nil {
			first = session
		} else if first != session {
			t.Fatal("idempotent concurrent Start returned different sessions")
		}
	}
	if got := starter.startCount(); got != 2 {
		t.Fatalf("process starts = %d, want keeper+mapping once", got)
	}

	errs = make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-concurrent"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []ProcessRole{ProcessRoleMapping, ProcessRoleKeeper} {
		if got := starter.latest(role).terminateCount; got != 1 {
			t.Fatalf("%s terminate count = %d, want 1", role, got)
		}
	}
}
