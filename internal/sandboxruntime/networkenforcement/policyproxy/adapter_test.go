//go:build linux

package policyproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestL6PolicyProxyHTTPAllowDenyBoundsRedactionAndNoAmbientProxy(t *testing.T) {
	upstream := newHTTPFixture(t)
	var dialCount atomic.Int32
	var recordsMu sync.Mutex
	var records []networkenforcement.PolicyProxyDecisionLogRecord

	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{
			"203.0.113.10:80": upstream,
		}, &dialCount),
		sink: func(record networkenforcement.PolicyProxyDecisionLogRecord) {
			recordsMu.Lock()
			defer recordsMu.Unlock()
			records = append(records, record)
		},
		limits: Limits{
			MaxRequestBodyBytes:  32,
			MaxResponseBodyBytes: 32,
		},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })

	t.Setenv("HTTP_PROXY", "http://ambient.invalid:65535")
	t.Setenv("HTTPS_PROXY", "http://ambient.invalid:65535")
	client := proxyClient(t, endpoint)

	req, err := http.NewRequest(http.MethodPost, "http://allowed.test/ok", strings.NewReader("small"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer proxy-secret-canary")
	req.Header.Set("Authorization", "Bearer origin-secret-canary")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("allowed request error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "upstream-ok" {
		t.Fatalf("allowed response = status %d body %q", resp.StatusCode, body)
	}

	resp, err = client.Get("http://blocked.test/deny")
	if err != nil {
		t.Fatalf("denied request error: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	oversizeReq, err := http.NewRequest(http.MethodPost, "http://allowed.test/ok", strings.NewReader(strings.Repeat("r", 33)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(oversizeReq)
	if err != nil {
		t.Fatalf("oversize request error: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize request status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}

	resp, err = client.Get("http://allowed.test/large")
	if err != nil {
		t.Fatalf("oversize response error: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("oversize response status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	if got := dialCount.Load(); got != 3 {
		t.Fatalf("dial count = %d, want 3 allowed upstream attempts", got)
	}
	recordsMu.Lock()
	gotRecords := append([]networkenforcement.PolicyProxyDecisionLogRecord(nil), records...)
	recordsMu.Unlock()
	if len(gotRecords) != 4 {
		t.Fatalf("decision records = %d, want 4", len(gotRecords))
	}
	payload := fmt.Sprintf("%#v", gotRecords)
	for _, secret := range []string{
		"allowed.test",
		"blocked.test",
		"proxy-secret-canary",
		"origin-secret-canary",
		upstream,
	} {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(secret)) {
			t.Fatalf("decision records leaked %q: %s", secret, payload)
		}
	}
}

func TestL6PolicyProxyCONNECTAllowAndDenial(t *testing.T) {
	echo := newTCPEchoFixture(t)
	var dialCount atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{
			"203.0.113.10:443": echo,
		}, &dialCount),
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })

	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	response.Body.Close()
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "ping" {
		t.Fatalf("CONNECT reply = %q", reply)
	}

	denied, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	if _, err := io.WriteString(denied, "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	deniedResponse, err := http.ReadResponse(bufio.NewReader(denied), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	deniedResponse.Body.Close()
	if deniedResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("denied CONNECT status = %d, want 403", deniedResponse.StatusCode)
	}
	if got := dialCount.Load(); got != 1 {
		t.Fatalf("dial count = %d, want 1", got)
	}
}

func TestL6PolicyProxyRejectsDNSRebindingMixedAndUnsafeAnswersBeforeDial(t *testing.T) {
	tests := []struct {
		name  string
		addrs []netip.Addr
	}{
		{name: "loopback", addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "private IPv4", addrs: []netip.Addr{netip.MustParseAddr("10.0.0.8")}},
		{name: "private IPv6", addrs: []netip.Addr{netip.MustParseAddr("fd00::8")}},
		{name: "link local", addrs: []netip.Addr{netip.MustParseAddr("169.254.2.3")}},
		{name: "metadata", addrs: []netip.Addr{netip.MustParseAddr("169.254.169.254")}},
		{name: "unspecified", addrs: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
		{name: "multicast", addrs: []netip.Addr{netip.MustParseAddr("ff02::1")}},
		{name: "mixed", addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("127.0.0.1")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dialCount atomic.Int32
			adapter := newTestAdapter(t, testAdapterOptions{
				resolve: func(context.Context, string, string) ([]netip.Addr, error) {
					return append([]netip.Addr(nil), tt.addrs...), nil
				},
				dial: func(context.Context, string, string) (net.Conn, error) {
					dialCount.Add(1)
					return nil, errors.New("must not dial")
				},
			})
			endpoint := startAdapter(t, adapter)
			t.Cleanup(func() { stopAdapter(t, adapter) })
			resp, err := proxyClient(t, endpoint).Get("http://allowed.test/rebind")
			if err != nil {
				t.Fatalf("request error: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if got := dialCount.Load(); got != 0 {
				t.Fatalf("dial count = %d, want 0", got)
			}
		})
	}
}

func TestL6PolicyProxyLifecycleCleanupCancellationAndProxyOnlyProof(t *testing.T) {
	adapter := newTestAdapter(t, testAdapterOptions{})
	plan := testPolicy().PlanMetadata()
	service := networkenforcement.PolicyProxyLifecycleService{Adapter: adapter}
	started, err := service.StartPolicyProxy(context.Background(), networkenforcement.NewPolicyProxyLifecycleRequest(plan, networkenforcement.PolicyProxyLifecycleProof{}, networkenforcement.PolicyProxyLifecycleProof{}))
	if err != nil {
		t.Fatalf("StartPolicyProxy error: %v", err)
	}
	active, err := service.ActivePolicyProxy(context.Background(), networkenforcement.NewPolicyProxyLifecycleRequest(plan, started, started))
	if err != nil {
		t.Fatalf("ActivePolicyProxy error: %v", err)
	}
	if active.Status != networkenforcement.LifecycleStatusActive {
		t.Fatalf("active status = %q", active.Status)
	}
	result := networkenforcement.ResultFromPolicyProxyLifecycleProof(plan, active)
	if result.EnforcementMode != networkenforcement.ResultModeProxy {
		t.Fatalf("result mode = %q, want proxy", result.EnforcementMode)
	}
	if len(result.Mechanisms) != 1 || result.Mechanisms[0] != networkenforcement.EnforcementMechanismProxy {
		t.Fatalf("mechanisms = %#v, want proxy only", result.Mechanisms)
	}
	for _, unsafe := range []string{"firewall", "runtime", "proxy_firewall"} {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%#v", result)), unsafe) {
			t.Fatalf("proxy-only result overclaims %q: %#v", unsafe, result)
		}
	}

	endpoint, ok := adapter.Endpoint()
	if !ok {
		t.Fatal("active adapter endpoint unavailable")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, err := service.StopPolicyProxy(canceled, networkenforcement.NewPolicyProxyLifecycleRequest(plan, started, active))
	if err != nil {
		t.Fatalf("StopPolicyProxy with canceled context error: %v", err)
	}
	if stopped.Status != networkenforcement.LifecycleStatusStopped {
		t.Fatalf("stopped status = %q", stopped.Status)
	}
	if _, err := net.DialTimeout("tcp", endpoint, 100*time.Millisecond); err == nil {
		t.Fatal("listener still accepts connections after stop")
	}
	if _, err := service.StopPolicyProxy(canceled, networkenforcement.NewPolicyProxyLifecycleRequest(plan, started, stopped)); err != nil {
		t.Fatalf("idempotent StopPolicyProxy error: %v", err)
	}
}

type testAdapterOptions struct {
	resolve ResolverFunc
	dial    DialFunc
	sink    func(networkenforcement.PolicyProxyDecisionLogRecord)
	limits  Limits
}

func newTestAdapter(t *testing.T, options testAdapterOptions) *Adapter {
	t.Helper()
	config := Config{
		Policy:        testPolicy(),
		ListenAddress: "127.0.0.1:0",
		Resolver:      options.resolve,
		DialContext:   options.dial,
		DecisionSink:  options.sink,
		Limits:        options.limits,
	}
	adapter, err := New(config)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	return adapter
}

func testPolicy() networkenforcement.PolicyProxyPolicyInput {
	request := networkenforcement.PlanRequest{
		ID:        "l6-plan",
		Source:    networkenforcement.PlanSourceRuntime,
		Operation: "l6-policy-proxy",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{
			ID:        "l6-policy",
			Version:   "v1",
			Preset:    networkenforcement.PolicyPresetAllowListed,
			RuleSetID: "l6-rules",
		},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{
			Preset:           networkenforcement.PolicyPresetAllowListed,
			AllowlistMode:    networkenforcement.AllowlistModeEnforce,
			RuleSetID:        "l6-rules",
			PrivateNetwork:   networkenforcement.PostureBlock,
			MetadataEndpoint: networkenforcement.PostureBlock,
			HTTP:             networkenforcement.ProxyRoutingModeRouteViaProxy,
			HTTPS:            networkenforcement.ProxyRoutingModeRouteViaProxy,
			ProxySessionID:   "l6-proxy-session",
			ProxyMechanism:   networkenforcement.EnforcementMechanismProxy,
			AllowlistRules: []networkenforcement.AllowlistRule{
				{ID: "allow-domain", Category: networkenforcement.AllowlistRuleCategoryDomain, Value: "allowed.test"},
			},
		},
	}
	return networkenforcement.NewPolicyProxyPolicyInput(networkenforcement.BuildPlan(request), request.RequestedPolicy.AllowlistRules)
}

func startAdapter(t *testing.T, adapter *Adapter) string {
	t.Helper()
	plan := testPolicy().PlanMetadata()
	runner := networkenforcement.ProxyListenerLifecycleRunner{Adapter: adapter}
	result, err := runner.Start(context.Background(), plan)
	if err != nil {
		t.Fatalf("Start error: %v (%#v)", err, result)
	}
	endpoint, ok := adapter.Endpoint()
	if !ok || endpoint == "" {
		t.Fatal("Endpoint unavailable after start")
	}
	return endpoint
}

func stopAdapter(t *testing.T, adapter *Adapter) {
	t.Helper()
	plan := testPolicy().PlanMetadata()
	runner := networkenforcement.ProxyListenerLifecycleRunner{Adapter: adapter}
	if _, err := runner.Stop(context.Background(), plan, nil); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

func proxyClient(t *testing.T, endpoint string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + endpoint)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func mappingDialer(t *testing.T, mapping map[string]string, calls *atomic.Int32) DialFunc {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		target, ok := mapping[address]
		if !ok {
			return nil, errors.New("unexpected destination")
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, target)
	}
}

func newHTTPFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("upstream received Proxy-Authorization")
		}
		switch r.URL.Path {
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("x", 33))
		default:
			_, _ = io.WriteString(w, "upstream-ok")
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return listener.Addr().String()
}

func newTCPEchoFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestL6PolicyProxyResponseBodiesAreNotPartiallyPublishedWhenOversize(t *testing.T) {
	upstream := newHTTPFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"203.0.113.10:80": upstream}, &calls),
		limits: Limits{
			MaxResponseBodyBytes: 8,
		},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	resp, err := proxyClient(t, endpoint).Get("http://allowed.test/large")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if bytes.Contains(body, []byte("xxxxxxxx")) {
		t.Fatalf("oversize upstream body partially published: %q", body)
	}
}
