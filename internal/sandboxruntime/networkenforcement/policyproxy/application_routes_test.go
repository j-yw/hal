//go:build linux

package policyproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute"
)

func TestL8D3PolicyProxyReservedOriginRouteDispatchesWithoutGenericDial(t *testing.T) {
	route := &l8D3PolicyProxyRoute{}
	adapter := newL8D3PolicyProxyAdapter(t, route, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("generic dial must not run")
	})
	request := httptest.NewRequest(http.MethodPost, "http://runtime-route.invalid/.well-known/hal/credential-http/v1/service/deployments/model/responses?api-version=v1", bytes.NewReader([]byte(`{"model":"model"}`)))
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.RequestURI = "/.well-known/hal/credential-http/v1/service/deployments/model/responses?api-version=v1"
	request.Host = "runtime-route.invalid"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("api-key", "opaque-ticket")
	response := httptest.NewRecorder()

	adapter.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != `{"ok":true}` {
		t.Fatalf("reserved response = %d %q", response.Code, response.Body.String())
	}
	got := route.LastRequest()
	if got.Metadata.Method != http.MethodPost || got.Metadata.ContentType != "application/json" || got.Metadata.ContentLength != int64(len(`{"model":"model"}`)) {
		t.Fatalf("request metadata = %#v", got.Metadata)
	}
	if got.Target.Authority != "runtime-route.invalid" || got.Target.Path != "/.well-known/hal/credential-http/v1/service/deployments/model/responses" || got.Target.RawQuery != "api-version=v1" {
		t.Fatalf("request target = %v", got.Target)
	}
	if got.Headers.ValueCount("api-key") != 1 {
		t.Fatal("reserved route did not receive sole ticket header")
	}
	destination := make([]byte, len("opaque-ticket"))
	if count, err := got.Headers.CopyValue("api-key", 0, destination); err != nil || count != len(destination) || string(destination) != "opaque-ticket" {
		t.Fatalf("CopyValue() = (%d, %v, %q)", count, err, destination)
	}
	if rendered := fmt.Sprintf("%#v", got.Headers); rendered != "policyproxy.applicationRequestHeaders{live}" || stringsContains(rendered, "opaque-ticket") {
		t.Fatalf("header accessor formatting = %q", rendered)
	}
	if _, err := json.Marshal(got.Headers); !errors.Is(err, applicationroute.ErrLiveRouteStateNotSerializable) {
		t.Fatalf("Marshal(header accessor) error = %v, want denial", err)
	}
}

func TestL8D3PolicyProxyReservedPrefixFailsClosedWithoutHandler(t *testing.T) {
	dialed := false
	adapter := newL8D3PolicyProxyAdapter(t, nil, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	})
	request := httptest.NewRequest(http.MethodPost, "http://runtime-route.invalid/.well-known/hal/credential-http/v1/service", nil)
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.RequestURI = "/.well-known/hal/credential-http/v1/service"
	request.Host = "runtime-route.invalid"
	response := httptest.NewRecorder()
	adapter.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("reserved no-handler status = %d, want 403", response.Code)
	}
	if dialed {
		t.Fatal("reserved no-handler request reached generic dialer")
	}
}

func TestL8D3PolicyProxyTicketOnGenericCONNECTFailsClosed(t *testing.T) {
	dialed := false
	adapter := newL8D3PolicyProxyAdapter(t, &l8D3PolicyProxyRoute{}, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	})
	request := httptest.NewRequest(http.MethodConnect, "http://allowed.test:443", nil)
	request.RequestURI = "allowed.test:443"
	request.Host = "allowed.test:443"
	request.Header.Set("api-key", "opaque-ticket")
	response := httptest.NewRecorder()
	adapter.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("ticket CONNECT status = %d, want 403", response.Code)
	}
	if dialed {
		t.Fatal("ticket CONNECT reached generic dialer")
	}
}

func TestL8D3PolicyProxyApplicationRouteLifecycleAndTypedNil(t *testing.T) {
	var typedNilRoute *l8D3PolicyProxyRoute
	config := l8D3PolicyProxyConfig(t)
	config.ApplicationRoutes = typedNilRoute
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(typed nil route) error = %v, want invalid config", err)
	}

	route := &l8D3PolicyProxyRoute{startErr: errors.New("raw start api-key=canary")}
	adapter := newL8D3PolicyProxyAdapterUnstarted(t, route, nil)
	request := l8D3LifecycleRequest()
	metadata, err := adapter.StartProxyListener(context.Background(), request)
	if err == nil || metadata.Status != "failed" || stringsContains(err.Error(), "canary") {
		t.Fatalf("route start = (%#v, %v), want sanitized failure", metadata, err)
	}
	if route.StartCount() != 1 || route.CloseCount() != 1 {
		t.Fatalf("route rollback counts = start %d close %d", route.StartCount(), route.CloseCount())
	}
}

func TestL8D3PolicyProxySnapshotsValidatedApplicationRouteDefinitions(t *testing.T) {
	route := &l8D3PolicyProxyRoute{}
	adapter := newL8D3PolicyProxyAdapterUnstarted(t, route, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("generic dial must not run")
	})
	route.SetDefinitions([]applicationroute.Definition{{
		ID: "replacement-route", Prefix: "/.well-known/hal/replacement/",
		Limits: applicationroute.StreamLimits{
			MaxRequestHeaderBytes: 1, MaxRequestBodyBytes: 1,
			MaxResponseHeaderBytes: 1, MaxResponseBodyBytes: 1, MaxEventBytes: 1,
		},
	}})
	request := l8D3LifecycleRequest()
	if _, err := adapter.StartProxyListener(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adapter.StopProxyListener(context.Background(), request) })

	httpRequest := httptest.NewRequest(http.MethodPost, "http://runtime-route.invalid/.well-known/hal/credential-http/v1/service/deployments/model/responses?api-version=v1", bytes.NewReader([]byte(`{"model":"model"}`)))
	httpRequest.URL.Scheme = ""
	httpRequest.URL.Host = ""
	httpRequest.RequestURI = "/.well-known/hal/credential-http/v1/service/deployments/model/responses?api-version=v1"
	httpRequest.Host = "runtime-route.invalid"
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("api-key", "opaque-ticket")
	httpResponse := httptest.NewRecorder()

	adapter.ServeHTTP(httpResponse, httpRequest)
	if httpResponse.Code != http.StatusCreated {
		t.Fatalf("response status = %d, want snapshotted route dispatch", httpResponse.Code)
	}
}

func TestL8D3PolicyProxyApplicationRouteCleanupRetriesBeforeStopped(t *testing.T) {
	route := &l8D3PolicyProxyRoute{closeFailures: 1}
	adapter := newL8D3PolicyProxyAdapterUnstarted(t, route, nil)
	request := l8D3LifecycleRequest()
	if _, err := adapter.StartProxyListener(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	metadata, err := adapter.StopProxyListener(context.Background(), request)
	if err == nil || metadata.Status != "failed" {
		t.Fatalf("first StopProxyListener() = (%#v, %v), want cleanup failure", metadata, err)
	}
	metadata, err = adapter.StopProxyListener(context.Background(), request)
	if err != nil || metadata.Status != "stopped" {
		t.Fatalf("retry StopProxyListener() = (%#v, %v), want stopped", metadata, err)
	}
	if route.CloseCount() != 2 {
		t.Fatalf("route close attempts = %d, want 2", route.CloseCount())
	}
}

func newL8D3PolicyProxyAdapter(t *testing.T, route applicationroute.Handler, dial DialFunc) *Adapter {
	t.Helper()
	adapter := newL8D3PolicyProxyAdapterUnstarted(t, route, dial)
	request := l8D3LifecycleRequest()
	if _, err := adapter.StartProxyListener(context.Background(), request); err != nil {
		t.Fatalf("StartProxyListener() error: %v", err)
	}
	t.Cleanup(func() { _, _ = adapter.StopProxyListener(context.Background(), request) })
	return adapter
}

func newL8D3PolicyProxyAdapterUnstarted(t *testing.T, route applicationroute.Handler, dial DialFunc) *Adapter {
	t.Helper()
	config := l8D3PolicyProxyConfig(t)
	config.ApplicationRoutes = route
	if dial != nil {
		config.DialContext = dial
	}
	adapter, err := New(config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return adapter
}

func l8D3PolicyProxyConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Policy:        testPolicy(),
		ListenAddress: "127.0.0.1:0",
		Resolver: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
	}
}

func l8D3LifecycleRequest() networkenforcement.ProxyListenerLifecycleRequest {
	return networkenforcement.ProxyListenerLifecycleRequest{
		Plan: networkenforcement.NewSanitizedPlan(testPolicy().PlanMetadata()),
	}
}

type l8D3PolicyProxyRoute struct {
	mu            sync.Mutex
	started       bool
	definitions   []applicationroute.Definition
	request       applicationroute.Request
	startCount    int
	closeCount    int
	startErr      error
	closeFailures int
}

func (route *l8D3PolicyProxyRoute) Definitions() []applicationroute.Definition {
	route.mu.Lock()
	defer route.mu.Unlock()
	if route.definitions != nil {
		return append([]applicationroute.Definition(nil), route.definitions...)
	}
	return []applicationroute.Definition{{
		ID: applicationroute.RouteCredentialHTTPV1, Prefix: applicationroute.CredentialHTTPV1Prefix,
		Limits: applicationroute.StreamLimits{
			MaxRequestHeaderBytes: 32 << 10, MaxRequestBodyBytes: 16 << 20,
			MaxResponseHeaderBytes: 32 << 10, MaxResponseBodyBytes: 64 << 20, MaxEventBytes: 2 << 20,
		},
	}}
}

func (route *l8D3PolicyProxyRoute) SetDefinitions(definitions []applicationroute.Definition) {
	route.mu.Lock()
	defer route.mu.Unlock()
	route.definitions = append([]applicationroute.Definition(nil), definitions...)
}

func (route *l8D3PolicyProxyRoute) Start(context.Context) error {
	route.mu.Lock()
	defer route.mu.Unlock()
	route.startCount++
	route.started = route.startErr == nil
	return route.startErr
}

func (route *l8D3PolicyProxyRoute) Handle(_ context.Context, _ applicationroute.RouteID, request applicationroute.Request) (applicationroute.Response, error) {
	route.mu.Lock()
	defer route.mu.Unlock()
	if !route.started {
		return applicationroute.Response{}, errors.New("not started")
	}
	route.request = request
	return applicationroute.Response{
		Metadata: applicationroute.ResponseMetadata{StatusCode: http.StatusCreated, ContentType: "application/json", HeaderBytes: 32, ContentLength: int64(len(`{"ok":true}`))},
		Body:     io.NopCloser(stringsNewReader(`{"ok":true}`)),
	}, nil
}

func (route *l8D3PolicyProxyRoute) Close(context.Context) error {
	route.mu.Lock()
	defer route.mu.Unlock()
	route.closeCount++
	if route.closeFailures > 0 {
		route.closeFailures--
		return errors.New("raw close api-key=canary")
	}
	route.started = false
	return nil
}

func (route *l8D3PolicyProxyRoute) LastRequest() applicationroute.Request {
	route.mu.Lock()
	defer route.mu.Unlock()
	return route.request
}

func (route *l8D3PolicyProxyRoute) StartCount() int {
	route.mu.Lock()
	defer route.mu.Unlock()
	return route.startCount
}

func (route *l8D3PolicyProxyRoute) CloseCount() int {
	route.mu.Lock()
	defer route.mu.Unlock()
	return route.closeCount
}

func stringsContains(value, part string) bool { return bytes.Contains([]byte(value), []byte(part)) }
func stringsNewReader(value string) io.Reader { return bytes.NewReader([]byte(value)) }
