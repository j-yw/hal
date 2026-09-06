//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

// The real L7 coordinator and TAP parser issue the opaque descriptor. Every
// host/network operation is an in-memory fake; only its private journal uses
// ordinary temporary files. These fixtures are not live inspection evidence.
func minimalL7ConfigTestExpectation(t *testing.T, endpoint string) *minimalL7ConfigExpectation {
	t.Helper()
	identity := l7RuntimeControllerIdentity("minimal-config")
	proxy := &minimalL7ConfigTestProxy{endpoint: endpoint, loss: make(chan struct{})}
	tap, err := l7network.NewLinuxTAP(l7network.TAPOptions{
		IPPath: "/usr/bin/ip", SysctlPath: "/usr/bin/sysctl", NsenterPath: "/usr/bin/nsenter",
		Command: &minimalL7ConfigTestTAP{},
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := l7network.New(l7network.Options{
		Enabled: true, Proxy: proxy, Topology: &minimalL7ConfigTestTopology{}, TAP: tap,
		Rules: minimalL7ConfigTestRules{}, GuestIsolation: minimalL7ConfigTestNoGuest{},
		VMTermination: minimalL7ConfigTestNoGuest{}, StateDir: t.TempDir(), CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := coordinator.Prepare(context.Background(), l7network.PrepareRequest{
		Identity: identity, Plan: l7RuntimeControllerPlan(identity),
	})
	if err != nil {
		t.Fatalf("prepare fake-backed real L7 session: %v", err)
	}
	t.Cleanup(func() {
		if err := session.AbortBeforeVM(context.Background(), identity); err != nil {
			t.Errorf("fake L7 session cleanup: %v", err)
		}
		// Stop closes the fake proxy generation, allowing the real loss watcher
		// to finish; do not leave one watcher per fixture blocked forever.
		select {
		case <-session.Loss():
		case <-time.After(time.Second):
			t.Error("fake L7 loss watcher did not finish after cleanup")
		}
	})
	metadata := session.Metadata()
	if metadata.Status != l7network.StatusHostPrepared || metadata.RawPacketIsolationVerified {
		t.Fatalf("unexpected fake-backed preparation status: %#v", metadata)
	}
	descriptor, err := session.LaunchDescriptor(identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.ProcessNamespace(identity); err != nil {
		t.Fatalf("same-session namespace view: %v", err)
	}
	return &minimalL7ConfigExpectation{descriptor: descriptor,
		runtimeGeneration: identity.RuntimeGenerationID, topologyGeneration: identity.TopologyGenerationID}
}

type minimalL7ConfigTestProxy struct {
	endpoint string
	loss     chan struct{}
	stop     sync.Once
}

func (p *minimalL7ConfigTestProxy) Address() string       { return p.endpoint }
func (p *minimalL7ConfigTestProxy) Loss() <-chan struct{} { return p.loss }
func (p *minimalL7ConfigTestProxy) Start(context.Context, networkenforcement.Plan) (l7network.ProxyGeneration, error) {
	return p, nil
}
func (p *minimalL7ConfigTestProxy) Endpoint(g l7network.ProxyGeneration) (string, error) {
	if g != p {
		return "", errors.New("wrong fake proxy generation")
	}
	return p.endpoint, nil
}
func (p *minimalL7ConfigTestProxy) Active(_ context.Context, _ networkenforcement.Plan, g l7network.ProxyGeneration) error {
	if g != p {
		return errors.New("wrong fake proxy generation")
	}
	return nil
}
func (p *minimalL7ConfigTestProxy) Stop(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error {
	p.stop.Do(func() { close(p.loss) })
	return nil
}

type minimalL7ConfigTestTopology struct {
	identity linuxtopology.Identity
	losses   chan linuxtopology.Loss
}

func (s *minimalL7ConfigTestTopology) Start(_ context.Context, request linuxtopology.StartRequest) (l7network.TopologySession, error) {
	s.identity, s.losses = request.Identity, make(chan linuxtopology.Loss)
	return s, nil
}
func (*minimalL7ConfigTestTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}
func (s *minimalL7ConfigTestTopology) Metadata() linuxtopology.Metadata {
	return linuxtopology.Metadata{Identity: s.identity, Status: linuxtopology.StatusPrepared,
		StructuralInspected: true, MappingReachable: true}
}
func (s *minimalL7ConfigTestTopology) Losses() <-chan linuxtopology.Loss { return s.losses }
func (*minimalL7ConfigTestTopology) BorrowNamespace() (l7network.NamespaceLease, error) {
	return minimalL7ConfigTestNamespace{}, nil
}

type minimalL7ConfigTestNamespace struct{}

func (minimalL7ConfigTestNamespace) RuleNamespace() linuxrules.NamespaceHandle {
	// Fake adapter correlation only; no syscall consumes these numbers.
	return linuxrules.NewNamespaceHandle(10, 11)
}
func (minimalL7ConfigTestNamespace) Close() error { return nil }
func (minimalL7ConfigTestNamespace) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	panic("pure config test must not duplicate namespace files")
}

type minimalL7ConfigTestRules struct{}

func (r minimalL7ConfigTestRules) ApplyAndInspect(ctx context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	return r.Inspect(ctx, expected)
}
func (minimalL7ConfigTestRules) Inspect(_ context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	var fields struct {
		Correlation networkenforcement.EnforcementCorrelation `json:"correlation"`
		RuleDigest  string                                    `json:"ruleDigest"`
	}
	payload, err := expected.MarshalJSON()
	if err != nil {
		return networkenforcement.RuleLifecycleMetadata{}, err
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return networkenforcement.RuleLifecycleMetadata{}, err
	}
	c := fields.Correlation
	return networkenforcement.RuleLifecycleMetadata{ID: c.RuleGenerationID, PlanID: c.PlanID,
		Status: networkenforcement.LifecycleStatusActive, Correlation: &c,
		Inspection: &networkenforcement.InspectedRuleProof{
			ID: "fake-minimal-config-rules", RuleDigest: fields.RuleDigest,
			Status: networkenforcement.RuleInspectionStatusInspected, InspectedAtUnixMilli: 1000, Correlation: &c,
			Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
			CapabilityLabels: []string{"default_deny"}, ReasonCode: networkenforcement.LifecycleReasonRuleInspected},
		ReasonCode: networkenforcement.LifecycleReasonActive}, nil
}
func (minimalL7ConfigTestRules) Quarantine(context.Context, linuxrules.ExpectedRuleSet) error {
	return nil
}
func (minimalL7ConfigTestRules) Cleanup(context.Context, linuxrules.ExpectedRuleSet) error {
	return nil
}

type minimalL7ConfigTestNoGuest struct{}

func (minimalL7ConfigTestNoGuest) VerifyRunningGuestRawPacketIsolation(context.Context, l7network.RunningGuestRawPacketIsolationRequest) (l7network.RunningGuestRawPacketIsolationProof, error) {
	panic("pure config test must not inspect a guest")
}
func (minimalL7ConfigTestNoGuest) VerifyVMTermination(context.Context, l7network.VMTerminationRequest) (l7network.VMTerminationProof, error) {
	panic("pure config test must not inspect a VM")
}

// Record the real TAP adapter's configuration commands and answer only its
// exact read-only inspection forms. No process, network or namespace is used.
type minimalL7ConfigTestTAP struct {
	name, mac, ipv4, ipv6, route4, route6, source4, source6 string
	removed                                                 bool
}

func (f *minimalL7ConfigTestTAP) Run(_ context.Context, _ l7network.NamespaceLease, request l7network.NamespaceCommandRequest, _ int64) ([]byte, error) {
	a := request.Args
	key := strings.Join(a, " ")
	encode := func(value any) ([]byte, error) { return json.Marshal(value) }
	switch {
	case len(a) == 6 && a[0] == "tuntap" && a[1] == "add":
		f.name = a[3]
	case len(a) == 6 && a[0] == "link" && a[1] == "set" && a[4] == "address":
		f.mac = a[5]
	case key == "link set dev "+f.name+" addrgenmode none", key == "link set dev "+f.name+" up":
	case len(a) == 6 && a[0] == "address" && a[1] == "add":
		f.ipv4 = a[2]
	case len(a) == 8 && a[0] == "-6" && a[1] == "address" && a[2] == "add":
		f.ipv6 = a[3]
	case len(a) == 7 && a[0] == "route" && a[1] == "add":
		f.route4, f.source4 = a[2], a[6]
	case len(a) == 8 && a[0] == "-6" && a[1] == "route" && a[2] == "add":
		f.route6, f.source6 = a[3], a[7]
	case key == "-w net.ipv4.ip_forward=1", key == "-w net.ipv6.conf.all.forwarding=1":
	case key == "-n net.ipv4.ip_forward", key == "-n net.ipv6.conf.all.forwarding":
		return []byte("1\n"), nil
	case key == "-d -j link show dev "+f.name:
		return encode([]any{map[string]any{"ifindex": 41, "ifname": f.name, "address": f.mac,
			"flags": []string{"UP"}, "link_type": "ether",
			"linkinfo": map[string]any{"info_kind": "tun", "info_data": map[string]string{"type": "tap"}}}})
	case key == "-j address show dev "+f.name:
		four, err4 := netip.ParsePrefix(f.ipv4)
		six, err6 := netip.ParsePrefix(f.ipv6)
		if err4 != nil || err6 != nil {
			return nil, errors.New("fake TAP addresses not configured")
		}
		return encode([]any{map[string]any{"ifname": f.name, "addr_info": []any{
			map[string]any{"family": "inet", "local": four.Addr().String(), "prefixlen": four.Bits()},
			map[string]any{"family": "inet6", "local": six.Addr().String(), "prefixlen": six.Bits()}}}})
	case key == "-j -4 route show dev "+f.name:
		return encode([]any{map[string]string{"dst": f.route4, "dev": f.name, "prefsrc": f.source4}})
	case key == "-j -6 route show dev "+f.name:
		return encode([]any{map[string]string{"dst": f.route6, "dev": f.name, "prefsrc": f.source6}})
	case key == "link delete dev "+f.name:
		f.removed = true
	case key == "-j link show" && f.removed:
		return []byte("[]"), nil
	default:
		return nil, errors.New("unexpected fake TAP command")
	}
	return nil, nil
}
