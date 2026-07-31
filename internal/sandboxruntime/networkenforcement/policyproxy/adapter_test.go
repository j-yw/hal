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
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

const (
	l6TestNetwork       = "tcp"
	l6TestListenAddress = "127.0.0.1:0"
)

func TestL6PolicyProxyHTTPAllowDenyBoundsRedactionAndNoAmbientProxy(t *testing.T) {
	upstream := newHTTPFixture(t)
	var dialCount atomic.Int32
	var recordsMu sync.Mutex
	var records []networkenforcement.PolicyProxyDecisionLogRecord

	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{
			"93.184.216.34:80": upstream,
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
	req.Header.Set("Connection", "X-Secret-Hop")
	req.Header.Set("X-Secret-Hop", "hop-secret-canary")
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
	if got := resp.Header.Get("X-Upstream-Hop"); got != "" {
		t.Fatalf("dynamic response hop header leaked: %q", got)
	}

	resp, err = client.Get("http://blocked.test/deny")
	if err != nil {
		t.Fatalf("denied request error: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
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
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize request status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}

	resp, err = client.Get("http://allowed.test/large")
	if err != nil {
		t.Fatalf("oversize response error: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("oversize response status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	if got := dialCount.Load(); got != 2 {
		t.Fatalf("dial count = %d, want 2 allowed upstream attempts", got)
	}
	var gotRecords []networkenforcement.PolicyProxyDecisionLogRecord
	waitFor(t, time.Second, func() bool {
		recordsMu.Lock()
		defer recordsMu.Unlock()
		gotRecords = append([]networkenforcement.PolicyProxyDecisionLogRecord(nil), records...)
		return len(gotRecords) == 4
	})
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

func TestL6PolicyProxyConstructionOwnsImmutableAllowlistRules(t *testing.T) {
	policy := testPolicy()
	upstream := newHTTPFixture(t)
	var dialCount atomic.Int32
	adapter, err := New(Config{
		Policy:        policy,
		ListenAddress: l6TestListenAddress,
		Resolver: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		DialContext: mappingDialer(t, map[string]string{
			"93.184.216.34:80": upstream,
		}, &dialCount),
	})
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowlistRules[0].Value = "denied.test"

	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	allowed, err := proxyClient(t, endpoint).Get("http://allowed.test/immutable")
	if err != nil {
		t.Fatal(err)
	}
	_ = allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("allowed status after caller mutation = %d, want 200", allowed.StatusCode)
	}
	denied, err := proxyClient(t, endpoint).Get("http://denied.test/immutable")
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status after caller mutation = %d, want 403", denied.StatusCode)
	}
	if got := dialCount.Load(); got != 1 {
		t.Fatalf("dial count after caller mutation = %d, want 1", got)
	}
}

func TestL6PolicyProxyAcquiresConnectionCapacityBeforeAccept(t *testing.T) {
	probe := newAcceptProbeListener()
	limited := newConnectionLimitListener(probe, 1)
	t.Cleanup(func() { _ = limited.Close() })

	firstResult := make(chan listenerAcceptResult, 1)
	go func() {
		conn, err := limited.Accept()
		firstResult <- listenerAcceptResult{conn: conn, err: err}
	}()
	select {
	case <-probe.called:
	case <-time.After(time.Second):
		t.Fatal("first bounded Accept did not reach the underlying listener")
	}
	firstServer, firstPeer := net.Pipe()
	t.Cleanup(func() { _ = firstPeer.Close() })
	probe.accepted <- firstServer
	first := <-firstResult
	if first.err != nil {
		t.Fatal(first.err)
	}

	secondResult := make(chan listenerAcceptResult, 1)
	go func() {
		conn, err := limited.Accept()
		secondResult <- listenerAcceptResult{conn: conn, err: err}
	}()
	select {
	case <-probe.called:
		t.Fatal("underlying listener accepted beyond the configured connection capacity")
	case <-time.After(50 * time.Millisecond):
	}
	if err := first.conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe.called:
	case <-time.After(time.Second):
		t.Fatal("closing the first connection did not release listener capacity")
	}
	secondServer, secondPeer := net.Pipe()
	t.Cleanup(func() { _ = secondPeer.Close() })
	probe.accepted <- secondServer
	second := <-secondResult
	if second.err != nil {
		t.Fatal(second.err)
	}
	_ = second.conn.Close()

	adapter := newTestAdapter(t, testAdapterOptions{limits: Limits{MaxConcurrent: 1}})
	startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	adapter.mu.Lock()
	_, bounded := adapter.listener.(*connectionLimitListener)
	adapter.mu.Unlock()
	if !bounded {
		t.Fatal("production listener does not enforce pre-handler connection capacity")
	}
}

func TestL6PolicyProxyRejectsOversizedConfigurationBeforeAllocation(t *testing.T) {
	oversizedInt := int(^uint(0) >> 1)
	oversizedInt64 := int64(^uint64(0) >> 1)
	tests := []struct {
		name   string
		limits Limits
	}{
		{name: "headers", limits: Limits{MaxHeaderBytes: maxHeaderBytes + 1}},
		{name: "response headers", limits: Limits{MaxResponseHeaderBytes: maxResponseHeaderBytes + 1}},
		{name: "request body overflow", limits: Limits{MaxRequestBodyBytes: oversizedInt64}},
		{name: "response body", limits: Limits{MaxResponseBodyBytes: maxResponseBodyBytes + 1}},
		{name: "CONNECT bytes overflow", limits: Limits{MaxConnectBytes: oversizedInt64}},
		{name: "resolver answers", limits: Limits{MaxResolvedAddresses: maxResolvedAddresses + 1}},
		{name: "concurrency allocation", limits: Limits{MaxConcurrent: oversizedInt}},
		{
			name: "aggregate buffered memory",
			limits: Limits{
				MaxRequestBodyBytes:  maxRequestBodyBytes,
				MaxResponseBodyBytes: maxResponseBodyBytes,
				MaxConcurrent:        maxConcurrentRequests,
			},
		},
		{name: "read header timeout", limits: Limits{ReadHeaderTimeout: maxConfiguredTimeout + time.Second}},
		{name: "read timeout", limits: Limits{ReadTimeout: maxConfiguredTimeout + time.Second}},
		{name: "write timeout", limits: Limits{WriteTimeout: maxConfiguredTimeout + time.Second}},
		{name: "idle timeout", limits: Limits{IdleTimeout: maxConfiguredTimeout + time.Second}},
		{name: "request timeout", limits: Limits{RequestTimeout: maxConfiguredTimeout + time.Second}},
		{name: "CONNECT timeout", limits: Limits{ConnectTimeout: maxConfiguredTimeout + time.Second}},
		{name: "shutdown timeout", limits: Limits{ShutdownTimeout: maxConfiguredTimeout + time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := New(Config{
				Policy:        testPolicy(),
				ListenAddress: "127.0.0.1:0",
				Limits:        tt.limits,
			})
			if adapter != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New = (%#v, %v), want nil ErrInvalidConfig", adapter, err)
			}
		})
	}
}

func TestL6PolicyProxyAggregateLimitAccountsForParsedHeaderWorkingSets(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
	}{
		{
			name: "request headers",
			limits: Limits{
				MaxHeaderBytes:         maxHeaderBytes,
				MaxResponseHeaderBytes: 1,
				MaxRequestBodyBytes:    1,
				MaxResponseBodyBytes:   1,
				MaxConnectBytes:        1,
				MaxResolvedAddresses:   1,
				MaxConcurrent:          8,
			},
		},
		{
			name: "response headers",
			limits: Limits{
				MaxHeaderBytes:         1,
				MaxResponseHeaderBytes: maxResponseHeaderBytes,
				MaxRequestBodyBytes:    1,
				MaxResponseBodyBytes:   1,
				MaxConnectBytes:        1,
				MaxResolvedAddresses:   1,
				MaxConcurrent:          8,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validAggregateBufferLimit(normalizeLimits(tt.limits)) {
				t.Fatal("parsed header working set exceeded aggregate buffer budget")
			}
		})
	}
}

func TestL6PolicyProxyAggregateLimitAccountsForRequestHeaderReadAllowance(t *testing.T) {
	limits := normalizeLimits(Limits{
		MaxHeaderBytes:         2 << 10,
		MaxResponseHeaderBytes: 1,
		MaxRequestBodyBytes:    1,
		MaxResponseBodyBytes:   1,
		MaxConnectBytes:        1,
		MaxResolvedAddresses:   1,
		MaxConcurrent:          maxConcurrentRequests,
	})
	if validAggregateBufferLimit(limits) {
		t.Fatal("request header read allowance exceeded aggregate buffer budget")
	}
}

func TestL6PolicyProxyAggregateLimitAccountsForParsedTrailers(t *testing.T) {
	limits := normalizeLimits(Limits{
		MaxHeaderBytes:         1,
		MaxResponseHeaderBytes: 1,
		MaxRequestBodyBytes:    1,
		MaxResponseBodyBytes:   1,
		MaxConnectBytes:        1,
		MaxResolvedAddresses:   1,
		MaxConcurrent:          maxConcurrentRequests,
	})
	if validAggregateBufferLimit(limits) {
		t.Fatal("parsed request and response trailer working sets exceeded aggregate buffer budget")
	}
}

func TestL6PolicyProxyBoundedBodyUsesOneFixedBuffer(t *testing.T) {
	body, tooLarge, err := readBounded(strings.NewReader("ab"), 2)
	if err != nil || tooLarge || string(body) != "ab" {
		t.Fatalf("readBounded exact body = (%q, %t, %v), want exact allowed body", body, tooLarge, err)
	}
	if cap(body) != 3 {
		t.Fatalf("readBounded capacity = %d, want fixed limit+1 capacity 3", cap(body))
	}
	if body, tooLarge, err = readBounded(strings.NewReader("abc"), 2); err != nil || !tooLarge || body != nil {
		t.Fatalf("readBounded oversized body = (%q, %t, %v), want nil oversized body", body, tooLarge, err)
	}
}

type listenerAcceptResult struct {
	conn net.Conn
	err  error
}

type acceptProbeListener struct {
	accepted  chan net.Conn
	called    chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newAcceptProbeListener() *acceptProbeListener {
	return &acceptProbeListener{
		accepted: make(chan net.Conn),
		called:   make(chan struct{}),
		closed:   make(chan struct{}),
	}
}

func (l *acceptProbeListener) Accept() (net.Conn, error) {
	select {
	case l.called <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *acceptProbeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *acceptProbeListener) Addr() net.Addr { return &net.TCPAddr{} }

type blockingCloseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (c *blockingCloseConn) Close() error {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		<-c.release
	}
	return c.Conn.Close()
}

func TestL6PolicyProxyReframesBufferedChunkedTrailerAndExpectRequest(t *testing.T) {
	upstream := newHTTPFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"93.184.216.34:80": upstream}, &calls),
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	req, err := http.NewRequest(http.MethodPost, "http://allowed.test/framing", strings.NewReader("framed"))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Header.Set("Expect", "100-continue")
	req.Trailer = http.Header{"X-Trailer-Canary": []string{"trailer-secret"}}
	resp, err := proxyClient(t, endpoint).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("framed request status = %d", resp.StatusCode)
	}
}

func TestL6PolicyProxyClosesEmptyUpstreamRequestAndStripsRawResponseHopHeaders(t *testing.T) {
	listener, err := net.Listen(l6TestNetwork, l6TestListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	requests := make(chan *http.Request, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		request, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			return
		}
		requests <- request
		_, _ = io.WriteString(conn,
			"HTTP/1.1 200 OK\r\n"+
				"Content-Length: 2\r\n"+
				"Connection: X-Upstream-Hop, close\r\n"+
				"X-Upstream-Hop: upstream-hop-canary\r\n"+
				"\r\nok",
		)
	}()

	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"93.184.216.34:80": listener.Addr().String()}, &calls),
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	resp, err := proxyClient(t, endpoint).Get("http://allowed.test/empty")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("raw upstream response = status %d body %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Upstream-Hop"); got != "" {
		t.Fatalf("dynamic raw response hop header leaked: %q", got)
	}

	select {
	case request := <-requests:
		request.Body.Close()
		if !request.Close {
			t.Fatal("upstream request did not contain Connection: close")
		}
		if len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 {
			t.Fatalf("empty upstream request retained framing: transfer=%v trailer=%v", request.TransferEncoding, request.Trailer)
		}
		if got := request.Header.Get("Expect"); got != "" {
			t.Fatalf("empty upstream request retained Expect: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for raw upstream request")
	}
}

func TestL6PolicyProxyRejectsInterimResponsesAndBoundsHeaderTerminatorExactly(t *testing.T) {
	upstream := newHTTPFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"93.184.216.34:80": upstream}, &calls),
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	resp, err := proxyClient(t, endpoint).Get("http://allowed.test/early")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("interim response status = %d, want 502", resp.StatusCode)
	}

	const exactHeader = "HTTP/1.1 204 No Content\r\n\r\n"
	left, right := net.Pipe()
	go func(conn net.Conn) {
		_, _ = io.WriteString(conn, exactHeader)
		_ = conn.Close()
	}(right)
	reader, _, err := boundedResponseReader(left, int64(len(exactHeader)))
	if err != nil {
		t.Fatalf("exact bounded header error: %v", err)
	}
	parsed, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	parsed.Body.Close()
	left.Close()

	left, right = net.Pipe()
	go func(conn net.Conn) {
		_, _ = io.WriteString(conn, exactHeader)
		_ = conn.Close()
	}(right)
	if _, _, err := boundedResponseReader(left, int64(len(exactHeader)-1)); err == nil {
		t.Fatal("header terminator beyond exact limit was accepted")
	}
	left.Close()
}

func TestL6PolicyProxyScansConnectionTokensWithoutSecondMIMEParse(t *testing.T) {
	header := []byte("HTTP/1.1 200 OK\r\n" +
		"Connection: X-First,\r\n" +
		" X-Second\r\n" +
		"Connection: X-Third\r\n\r\n")
	tokens, err := responseConnectionTokens(header)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(tokens, ","), "X-First,X-Second,X-Third"; got != want {
		t.Fatalf("connection tokens = %q, want %q", got, want)
	}
}

func TestL6PolicyProxyCONNECTAllowAndDenial(t *testing.T) {
	echo := newTCPEchoFixture(t)
	var dialCount atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{
			"93.184.216.34:443": echo,
		}, &dialCount),
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })

	conn, err := net.Dial(l6TestNetwork, endpoint)
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

	denied, err := net.Dial(l6TestNetwork, endpoint)
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

func TestL6PolicyProxyCONNECTDialUsesConnectTimeout(t *testing.T) {
	const connectTimeout = 50 * time.Millisecond
	var dialBudget time.Duration
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("fixture dial missing deadline")
			}
			dialBudget = time.Until(deadline)
			return nil, errors.New("fixture dial failed")
		},
		limits: Limits{
			RequestTimeout: time.Second,
			ConnectTimeout: connectTimeout,
		},
	})
	response := httptest.NewRecorder()
	adapter.ServeHTTP(response, &http.Request{
		Method:     http.MethodConnect,
		RequestURI: "allowed.test:443",
		Host:       "allowed.test:443",
		Header:     make(http.Header),
	})
	if response.Code != http.StatusBadGateway {
		t.Fatalf("CONNECT dial failure status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if dialBudget <= 0 || dialBudget > 2*connectTimeout {
		t.Fatalf("CONNECT dial budget = %v, want bounded by %v", dialBudget, connectTimeout)
	}
}

func TestL6PolicyProxyCONNECTPreservesPipelinedBytesAfterHijack(t *testing.T) {
	echo := newTCPEchoFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"93.184.216.34:443": echo}, &calls),
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	conn, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\nping"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "ping" {
		t.Fatalf("pipelined CONNECT reply = %q", reply)
	}
}

func TestL6PolicyProxyCONNECTForwardsUpstreamHalfCloseThroughConnectionLimit(t *testing.T) {
	listener, err := net.Listen(l6TestNetwork, l6TestListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	upstreamRead := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			upstreamRead <- acceptErr
			return
		}
		defer conn.Close()
		if _, writeErr := io.WriteString(conn, "done"); writeErr != nil {
			upstreamRead <- writeErr
			return
		}
		closeWriter, ok := conn.(interface{ CloseWrite() error })
		if !ok {
			upstreamRead <- errors.New("fixture connection cannot half-close")
			return
		}
		if closeErr := closeWriter.CloseWrite(); closeErr != nil {
			upstreamRead <- closeErr
			return
		}
		var payload [1]byte
		_, readErr := io.ReadFull(conn, payload[:])
		if readErr == nil && payload[0] != 'x' {
			readErr = errors.New("unexpected client payload")
		}
		upstreamRead <- readErr
	}()

	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{
			"93.184.216.34:443": listener.Addr().String(),
		}, &calls),
		limits: Limits{MaxConcurrent: 1},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	conn, reader := openCONNECT(t, endpoint)
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "done" {
		t.Fatalf("CONNECT half-close payload = %q", payload)
	}
	var extra [1]byte
	if _, err := reader.Read(extra[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("CONNECT upstream half-close read = %v, want EOF", err)
	}
	if _, err := conn.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-upstreamRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT client write did not survive upstream half-close")
	}
}

func TestL6PolicyProxyCONNECTRejectsNonAuthorityRequestTargets(t *testing.T) {
	for _, target := range []string{"/", "*", "http://allowed.test:443/"} {
		t.Run(target, func(t *testing.T) {
			echo := newTCPEchoFixture(t)
			var calls atomic.Int32
			adapter := newTestAdapter(t, testAdapterOptions{
				dial: mappingDialer(t, map[string]string{"93.184.216.34:443": echo}, &calls),
			})
			endpoint := startAdapter(t, adapter)
			t.Cleanup(func() { stopAdapter(t, adapter) })
			conn, err := net.Dial(l6TestNetwork, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n", target); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("CONNECT target %q status = %d, want 400", target, response.StatusCode)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("CONNECT target %q dialed upstream %d times", target, got)
			}
		})
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
		{name: "CGNAT", addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
		{name: "NAT64 private", addrs: []netip.Addr{netip.MustParseAddr("64:ff9b::a00:1")}},
		{name: "NAT64 metadata", addrs: []netip.Addr{netip.MustParseAddr("64:ff9b::a9fe:a9fe")}},
		{name: "NAT64 local use", addrs: []netip.Addr{netip.MustParseAddr("64:ff9b:1::a9fe:a9fe")}},
		{name: "deprecated IPv6 site local", addrs: []netip.Addr{netip.MustParseAddr("fec0::1")}},
		{name: "zoned", addrs: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}},
		{name: "mixed", addrs: []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}},
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
			_, _ = io.Copy(io.Discard, resp.Body)
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

func TestL6PolicyProxyAllowsPublicWellKnownNAT64Destinations(t *testing.T) {
	address := netip.MustParseAddr("64:ff9b::5db8:d822")
	if category := unsafeResolvedAddressCategory(address); category != "" {
		t.Fatalf("public NAT64 address classified as %q", category)
	}
}

func TestL6PolicyProxyBoundsResolverAnswersAndSlowRequestBodies(t *testing.T) {
	var dialCount atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		resolve: func(context.Context, string, string) ([]netip.Addr, error) {
			addrs := make([]netip.Addr, 17)
			for i := range addrs {
				addrs[i] = netip.MustParseAddr("93.184.216.34")
			}
			return addrs, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialCount.Add(1)
			return nil, errors.New("must not dial")
		},
		limits: Limits{ReadTimeout: 100 * time.Millisecond, WriteTimeout: 200 * time.Millisecond},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	resp, err := proxyClient(t, endpoint).Get("http://allowed.test/many")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("resolver overflow status = %d, want 502", resp.StatusCode)
	}

	conn, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	if _, err := io.WriteString(conn, "POST http://allowed.test/slow HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 10\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("slow request body was not bounded: %s", elapsed)
	}
	if got := dialCount.Load(); got != 0 {
		t.Fatalf("slow/overflow requests dialed upstream %d times", got)
	}
}

func TestL6PolicyProxyEmitsOneFinalSanitizedDecisionForResolutionAndParseDenials(t *testing.T) {
	var records []networkenforcement.PolicyProxyDecisionLogRecord
	adapter := newTestAdapter(t, testAdapterOptions{
		resolve: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("must not dial")
		},
		sink: func(record networkenforcement.PolicyProxyDecisionLogRecord) {
			records = append(records, record)
		},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	resp, err := proxyClient(t, endpoint).Get("http://allowed.test/metadata")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if len(records) != 1 {
		t.Fatalf("resolution decision records = %d, want 1", len(records))
	}
	if records[0].Action != networkenforcement.PolicyProxyDecisionActionDeny ||
		records[0].ReasonCode != networkenforcement.PolicyProxyDecisionReasonResolvedDestinationBlocked ||
		records[0].DestinationCategory != networkenforcement.AllowlistRuleCategoryMetadataEndpoint {
		t.Fatalf("resolution decision = %#v", records[0])
	}

	conn, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET /origin-form HTTP/1.1\r\nHost: allowed.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	conn.Close()
	if len(records) != 2 {
		t.Fatalf("all decision records = %d, want 2", len(records))
	}
	if records[1].Action != networkenforcement.PolicyProxyDecisionActionDeny ||
		records[1].ReasonCode != networkenforcement.PolicyProxyDecisionReasonProxyUnsupported {
		t.Fatalf("parse decision = %#v", records[1])
	}
	for _, record := range records {
		payload := fmt.Sprintf("%#v", record)
		if strings.Contains(payload, "169.254.169.254") || strings.Contains(payload, "allowed.test") {
			t.Fatalf("decision leaked destination: %s", payload)
		}
	}
}

func TestL6PolicyProxyLifecycleClosesOrdinaryHTTPUpstreamConnections(t *testing.T) {
	for _, tt := range []struct {
		name    string
		cleanup func(*testing.T, *Adapter)
	}{
		{
			name: "stop",
			cleanup: func(t *testing.T, adapter *Adapter) {
				t.Helper()
				stopAdapter(t, adapter)
			},
		},
		{
			name: "unexpected serve failure",
			cleanup: func(t *testing.T, adapter *Adapter) {
				t.Helper()
				adapter.mu.Lock()
				listener := adapter.listener
				adapter.mu.Unlock()
				if listener == nil {
					t.Fatal("active listener unavailable")
				}
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
				waitFor(t, time.Second, func() bool {
					_, active := adapter.Endpoint()
					return !active
				})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen(l6TestNetwork, l6TestListenAddress)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				request, readErr := http.ReadRequest(bufio.NewReader(conn))
				if readErr != nil {
					_ = conn.Close()
					return
				}
				_ = request.Body.Close()
				accepted <- conn
			}()

			var calls atomic.Int32
			adapter := newTestAdapter(t, testAdapterOptions{
				dial: mappingDialer(t, map[string]string{
					"93.184.216.34:80": listener.Addr().String(),
				}, &calls),
				limits: Limits{
					RequestTimeout:  5 * time.Second,
					ShutdownTimeout: 50 * time.Millisecond,
				},
			})
			endpoint := startAdapter(t, adapter)
			t.Cleanup(func() { stopAdapter(t, adapter) })
			requestDone := make(chan error, 1)
			go func() {
				response, requestErr := proxyClient(t, endpoint).Get("http://allowed.test/stall")
				if response != nil {
					_ = response.Body.Close()
				}
				requestDone <- requestErr
			}()

			var upstream net.Conn
			select {
			case upstream = <-accepted:
			case <-time.After(time.Second):
				t.Fatal("proxy did not publish the ordinary HTTP request upstream")
			}
			defer upstream.Close()
			tt.cleanup(t, adapter)

			if err := upstream.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var extra [1]byte
			if _, err := upstream.Read(extra[:]); err == nil {
				t.Fatal("ordinary HTTP upstream connection remained readable after cleanup")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("ordinary HTTP upstream connection remained open after cleanup")
			}
			select {
			case <-requestDone:
			case <-time.After(time.Second):
				t.Fatal("ordinary HTTP handler remained alive after cleanup")
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
	if _, err := net.DialTimeout(l6TestNetwork, endpoint, 100*time.Millisecond); err == nil {
		t.Fatal("listener still accepts connections after stop")
	}
	if _, err := service.StopPolicyProxy(canceled, networkenforcement.NewPolicyProxyLifecycleRequest(plan, started, stopped)); err != nil {
		t.Fatalf("idempotent StopPolicyProxy error: %v", err)
	}
}

func TestL6PolicyProxyStartWaitsForStopCleanup(t *testing.T) {
	adapter := newTestAdapter(t, testAdapterOptions{})
	startAdapter(t, adapter)
	request := networkenforcement.ProxyListenerLifecycleRequest{
		Plan: networkenforcement.NewSanitizedPlan(testPolicy().PlanMetadata()),
	}

	serverSide, peerSide := net.Pipe()
	t.Cleanup(func() { _ = peerSide.Close() })
	blocking := &blockingCloseConn{
		Conn:    serverSide,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseCleanup := func() {
		releaseOnce.Do(func() { close(blocking.release) })
	}
	t.Cleanup(releaseCleanup)
	adapter.mu.Lock()
	adapter.connections[blocking] = struct{}{}
	adapter.mu.Unlock()

	stopDone := make(chan error, 1)
	go func() {
		_, err := adapter.StopProxyListener(context.Background(), request)
		stopDone <- err
	}()
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("Stop did not reach owned connection cleanup")
	}

	startDone := make(chan error, 1)
	go func() {
		_, err := adapter.StartProxyListener(context.Background(), request)
		startDone <- err
	}()
	select {
	case err := <-startDone:
		releaseCleanup()
		<-stopDone
		if err == nil {
			stopAdapter(t, adapter)
		}
		t.Fatal("Start completed while the prior generation was still cleaning up")
	case <-time.After(50 * time.Millisecond):
	}

	releaseCleanup()
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	stopAdapter(t, adapter)
}

func TestL6PolicyProxyStopWaitsForUnexpectedServeFailureCleanup(t *testing.T) {
	adapter := newTestAdapter(t, testAdapterOptions{})
	startAdapter(t, adapter)
	request := networkenforcement.ProxyListenerLifecycleRequest{
		Plan: networkenforcement.NewSanitizedPlan(testPolicy().PlanMetadata()),
	}

	serverSide, peerSide := net.Pipe()
	t.Cleanup(func() { _ = peerSide.Close() })
	blocking := &blockingCloseConn{
		Conn:    serverSide,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseCleanup := func() {
		releaseOnce.Do(func() { close(blocking.release) })
	}
	t.Cleanup(releaseCleanup)
	adapter.mu.Lock()
	adapter.connections[blocking] = struct{}{}
	listener := adapter.listener
	adapter.mu.Unlock()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("unexpected Serve failure did not reach owned connection cleanup")
	}

	stopDone := make(chan error, 1)
	go func() {
		_, err := adapter.StopProxyListener(context.Background(), request)
		stopDone <- err
	}()
	select {
	case <-stopDone:
		releaseCleanup()
		t.Fatal("Stop returned before unexpected Serve failure cleanup completed")
	case <-time.After(50 * time.Millisecond):
	}
	releaseCleanup()
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
}

func TestL6PolicyProxyLifecycleRejectsMismatchedPolicySnapshotAndCannotRelabelProof(t *testing.T) {
	adapter := newTestAdapter(t, testAdapterOptions{})
	configured := testPolicy().PlanMetadata()
	forged := configured
	forgedSnapshot := *configured.PolicySnapshot
	forgedSnapshot.ID = "forged-policy"
	forgedSnapshot.Version = "forged-version"
	forgedSnapshot.RuleSetID = "forged-rules"
	forged.PolicySnapshot = &forgedSnapshot
	forgedAllowlist := *configured.Allowlist
	forgedAllowlist.RuleSetID = "forged-rules"
	forgedAllowlist.RuleIDs = []string{"forged-rule"}
	forged.Allowlist = &forgedAllowlist

	forgedRequest := networkenforcement.ProxyListenerLifecycleRequest{
		Plan: networkenforcement.NewSanitizedPlan(forged),
	}
	prepared, err := adapter.PrepareProxyListener(context.Background(), forgedRequest)
	if err == nil {
		t.Fatal("PrepareProxyListener accepted a mismatched policy snapshot")
	}
	if prepared.PolicySnapshot == nil || prepared.PolicySnapshot.ID != configured.PolicySnapshot.ID {
		t.Fatalf("failed prepare metadata relabeled policy snapshot: %#v", prepared.PolicySnapshot)
	}

	endpoint := startAdapter(t, adapter)
	active, err := adapter.ActiveProxyListener(context.Background(), forgedRequest)
	if err == nil {
		t.Fatal("ActiveProxyListener accepted a mismatched policy snapshot")
	}
	if active.PolicySnapshot == nil || active.PolicySnapshot.ID != configured.PolicySnapshot.ID {
		t.Fatalf("failed active metadata relabeled policy snapshot: %#v", active.PolicySnapshot)
	}

	stopped, err := adapter.StopProxyListener(context.Background(), forgedRequest)
	if err == nil {
		t.Fatal("StopProxyListener accepted a mismatched policy snapshot")
	}
	if stopped.PolicySnapshot == nil || stopped.PolicySnapshot.ID != configured.PolicySnapshot.ID {
		t.Fatalf("failed stop metadata relabeled policy snapshot: %#v", stopped.PolicySnapshot)
	}
	probe, err := net.DialTimeout(l6TestNetwork, endpoint, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("mismatched stop closed the configured listener: %v", err)
	}
	_ = probe.Close()
	stopAdapter(t, adapter)
}

func TestL6PolicyProxyDecisionSinkPanicCannotWeakenDecisions(t *testing.T) {
	upstream := newHTTPFixture(t)
	var dialCount atomic.Int32
	var sinkCalls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"93.184.216.34:80": upstream}, &dialCount),
		sink: func(networkenforcement.PolicyProxyDecisionLogRecord) {
			if sinkCalls.Add(1) == 1 {
				panic("sink panic canary")
			}
		},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	client := proxyClient(t, endpoint)
	for i := 0; i < 3; i++ {
		resp, err := client.Get("http://allowed.test/ok")
		if err != nil {
			t.Fatalf("request %d error: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d", i, resp.StatusCode)
		}
	}
	if got := dialCount.Load(); got != 3 {
		t.Fatalf("dial count = %d, want 3; sink altered enforcement", got)
	}
}

func TestL6PolicyProxyStopRejectsTunnelHijackedAfterCleanupSnapshot(t *testing.T) {
	echo := newTCPEchoFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial:   mappingDialer(t, map[string]string{"93.184.216.34:443": echo}, &calls),
		limits: Limits{ShutdownTimeout: 100 * time.Millisecond},
	})
	reached := make(chan struct{})
	release := make(chan struct{})
	adapter.beforeTunnelTrack = func() {
		close(reached)
		<-release
	}
	endpoint := startAdapter(t, adapter)
	conn, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	<-reached
	stopAdapter(t, adapter)
	close(release)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(conn).ReadByte(); err == nil {
		t.Fatal("late hijacked tunnel remained open after stop")
	}
}

func TestL6PolicyProxyUnexpectedServeFailureClearsProofAndOwnedTunnels(t *testing.T) {
	echo := newTCPEchoFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{"93.184.216.34:443": echo}, &calls),
	})
	endpoint := startAdapter(t, adapter)
	conn, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}

	adapter.mu.Lock()
	listener := adapter.listener
	adapter.mu.Unlock()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		_, active := adapter.Endpoint()
		return !active
	})
	plan := testPolicy().PlanMetadata()
	_, err = adapter.ActiveProxyListener(context.Background(), networkenforcement.ProxyListenerLifecycleRequest{
		Plan: networkenforcement.NewSanitizedPlan(plan),
	})
	if err == nil {
		t.Fatal("unexpected serve failure retained active proof")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected serve failure retained owned tunnel")
	}
}

func TestL6PolicyProxyCONNECTNeverPublishesBeyondExactByteLimit(t *testing.T) {
	echo := newTCPEchoFixture(t)
	var calls atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial:   mappingDialer(t, map[string]string{"93.184.216.34:443": echo}, &calls),
		limits: Limits{MaxConnectBytes: 4},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })
	conn, reader := openCONNECT(t, endpoint)
	defer conn.Close()
	if _, err := io.WriteString(conn, "abcde"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcd" {
		t.Fatalf("bounded CONNECT reply = %q", got)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	extra := make([]byte, 1)
	if n, _ := conn.Read(extra); n != 0 {
		t.Fatalf("CONNECT published byte beyond limit: %q", extra[:n])
	}
}

func TestL6BoundedTunnelCopyCapsEitherDirectionAndPreservesExactBoundary(t *testing.T) {
	for _, tt := range []struct {
		name    string
		payload string
	}{
		{name: "client to upstream oversize", payload: "abcde"},
		{name: "upstream to client oversize", payload: "vwxyz"},
		{name: "exact boundary", payload: "1234"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sourceReader, sourceWriter := net.Pipe()
			destinationReader, destinationWriter := net.Pipe()
			defer sourceReader.Close()
			defer sourceWriter.Close()
			defer destinationReader.Close()
			defer destinationWriter.Close()
			done := make(chan tunnelCopyResult, 1)
			go boundedTunnelCopy(destinationWriter, sourceReader, sourceReader, 4, done)
			go func() {
				_, _ = io.WriteString(sourceWriter, tt.payload)
				_ = sourceWriter.Close()
			}()
			got := make([]byte, 4)
			if _, err := io.ReadFull(destinationReader, got); err != nil {
				t.Fatal(err)
			}
			<-done
			_ = destinationReader.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			var extra [1]byte
			if n, _ := destinationReader.Read(extra[:]); n != 0 {
				t.Fatalf("published beyond limit: %q", extra[:n])
			}
			if string(got) != tt.payload[:4] {
				t.Fatalf("bounded payload = %q, want %q", got, tt.payload[:4])
			}
		})
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
	if options.resolve == nil {
		options.resolve = func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
	}
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
	listener, err := net.Listen(l6TestNetwork, l6TestListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("upstream received Proxy-Authorization")
		}
		if got := r.Header.Get("X-Secret-Hop"); got != "" {
			t.Errorf("upstream received Connection-nominated hop header")
		}
		if r.URL.Path == "/framing" {
			if len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.Header.Get("Expect") != "" {
				t.Errorf("upstream received stale framing: transfer=%v trailer=%v expect=%q", r.TransferEncoding, r.Trailer, r.Header.Get("Expect"))
			}
		}
		switch r.URL.Path {
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("x", 33))
		case "/headers":
			w.Header().Set("X-Large", strings.Repeat("h", 512))
			_, _ = io.WriteString(w, "small")
		case "/early":
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "final")
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

func openCONNECT(t *testing.T, endpoint string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		conn.Close()
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	return conn, reader
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}

func newTCPEchoFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen(l6TestNetwork, l6TestListenAddress)
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
		dial: mappingDialer(t, map[string]string{"93.184.216.34:80": upstream}, &calls),
		limits: Limits{
			MaxResponseBodyBytes:   8,
			MaxResponseHeaderBytes: 256,
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
	resp, err = proxyClient(t, endpoint).Get("http://allowed.test/headers")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("oversize header status = %d, want 502", resp.StatusCode)
	}
}
