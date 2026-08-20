package credentialproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute"
)

func TestL8D3AzureResponsesRouteUsesExactLocalFramingAndVerifiedTLS(t *testing.T) {
	const (
		deployment = "deployment-one"
		version    = "2026-06-01"
		secret     = "sk-live-upstream-canary"
	)
	observed := make(chan l8D3ObservedUpstream, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observed <- l8D3ObservedUpstream{
			protocol: request.Proto,
			method:   request.Method,
			path:     request.URL.EscapedPath(),
			query:    request.URL.RawQuery,
			host:     request.Host,
			apiKey:   request.Header.Get("api-key"),
			body:     string(body),
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{"id":"response-one"}`))
	}))
	upstream.EnableHTTP2 = false
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	upstream.TLS.NextProtos = []string{"http/1.1"}

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	definition, err := NewAzureOpenAIResponsesV1Definition("example.com", 443, "example.com", TLSRootPolicySystem, deployment, version)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewStaticServiceCatalog("catalog-generation-01", CatalogOwnerHostAdmin, definition)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time { return now }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x71}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	correlation := l8D3TicketActivation(t, now).Correlation
	network := &l8D3NetworkProof{}
	source := &l8D3CountingSecretSource{value: []byte(secret)}
	handler, ticket, err := newAzureResponsesRoute(AzureResponsesRouteConfig{
		Catalog:        catalog,
		TicketStore:    store,
		Correlation:    correlation,
		LocalAuthority: "runtime-credential.internal:8080",
		IssuedAt:       now,
		Source:         source,
		NetworkProof:   network,
	}, azureResponsesRouteDeps{
		roots: roots,
		resolver: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("newAzureResponsesRoute() error: %v", err)
	}
	if err := handler.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close(context.Background()) })

	ticketValue := make([]byte, JobTicketEncodedBytes)
	if _, err := ticket.CopyTo(ticketValue); err != nil {
		t.Fatal(err)
	}
	requestBody := []byte(`{"model":"deployment-one","input":"hello"}`)
	response, err := handler.Handle(context.Background(), applicationroute.Request{
		Metadata: applicationroute.RequestMetadata{
			Method: "POST", ContentType: "application/json", HeaderBytes: 128, ContentLength: int64(len(requestBody)),
		},
		Target: applicationroute.RequestTarget{
			Authority: "runtime-credential.internal:8080",
			Path:      "/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/deployment-one/responses",
			RawQuery:  "api-version=2026-06-01",
		},
		Headers: newL8D3HeaderValues(map[string][][]byte{
			"accept":       {[]byte("application/json")},
			"api-key":      {ticketValue},
			"content-type": {[]byte("application/json")},
			"user-agent":   {[]byte("pi/0.82.1")},
		}),
		Body: bytes.NewReader(requestBody),
	})
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(responseBody), `{"id":"response-one"}`; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}
	if response.Metadata.StatusCode != 200 || response.Metadata.ContentType != "application/json" || response.Metadata.Streaming {
		t.Fatalf("response metadata = %#v", response.Metadata)
	}
	got := <-observed
	if got.protocol != "HTTP/1.1" || got.method != "POST" || got.path != "/openai/v1/responses" || got.query != "" ||
		got.host != "example.com" || got.apiKey != secret || got.body != string(requestBody) {
		t.Fatalf("upstream observation = %#v", got)
	}
	if bytes.Contains([]byte(got.apiKey), ticketValue) {
		t.Fatal("upstream authentication contains local ticket")
	}
	if source.Count() != 1 {
		t.Fatalf("source reads = %d, want 1", source.Count())
	}
	if network.Count() != 2 {
		t.Fatalf("network proof inspections = %d, want before DNS and immediately before source", network.Count())
	}
}

func TestL8D3AzureResponsesRouteRejectsMalformedRequestsBeforeSourceAccess(t *testing.T) {
	requestBody := []byte(`{"model":"deployment-one","input":"hello"}`)
	tests := []struct {
		name   string
		mutate func(*applicationroute.Request)
	}{
		{name: "method", mutate: func(request *applicationroute.Request) { request.Metadata.Method = "GET" }},
		{name: "content type", mutate: func(request *applicationroute.Request) {
			request.Metadata.ContentType = "application/json; charset=utf-8"
		}},
		{name: "authority", mutate: func(request *applicationroute.Request) { request.Target.Authority = "neighbor.internal:8080" }},
		{name: "path", mutate: func(request *applicationroute.Request) { request.Target.Path += "/extra" }},
		{name: "query", mutate: func(request *applicationroute.Request) { request.Target.RawQuery += "&other=true" }},
		{name: "body length", mutate: func(request *applicationroute.Request) { request.Metadata.ContentLength++ }},
		{name: "wrong model", mutate: func(request *applicationroute.Request) {
			request.Body = strings.NewReader(`{"model":"other"}`)
			request.Metadata.ContentLength = 17
		}},
		{name: "duplicate ticket", mutate: func(request *applicationroute.Request) {
			request.Headers = newL8D3HeaderValues(map[string][][]byte{"api-key": {bytes.Repeat([]byte{'a'}, 43), bytes.Repeat([]byte{'b'}, 43)}, "content-type": {[]byte("application/json")}})
		}},
		{name: "competing auth", mutate: func(request *applicationroute.Request) {
			request.Headers = newL8D3HeaderValues(map[string][][]byte{"api-key": {bytes.Repeat([]byte{'a'}, 43)}, "authorization": {[]byte("Bearer raw")}, "content-type": {[]byte("application/json")}})
		}},
		{name: "transfer coding", mutate: func(request *applicationroute.Request) {
			request.Headers = newL8D3HeaderValues(map[string][][]byte{"api-key": {bytes.Repeat([]byte{'a'}, 43)}, "transfer-encoding": {[]byte("chunked")}, "content-type": {[]byte("application/json")}})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, ticket, source := l8D3RequestValidationRoute(t)
			ticketValue := make([]byte, JobTicketEncodedBytes)
			_, _ = ticket.CopyTo(ticketValue)
			request := applicationroute.Request{
				Metadata: applicationroute.RequestMetadata{Method: "POST", ContentType: "application/json", HeaderBytes: 128, ContentLength: int64(len(requestBody))},
				Target: applicationroute.RequestTarget{
					Authority: "runtime-credential.internal:8080",
					Path:      "/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/deployment-one/responses",
					RawQuery:  "api-version=2026-06-01",
				},
				Headers: newL8D3HeaderValues(map[string][][]byte{"api-key": {ticketValue}, "content-type": {[]byte("application/json")}}),
				Body:    bytes.NewReader(requestBody),
			}
			tt.mutate(&request)
			if _, err := handler.Handle(context.Background(), request); !errors.Is(err, ErrRouteRequestRejected) {
				t.Fatalf("Handle() error = %v, want sanitized rejection", err)
			}
			if source.Count() != 0 {
				t.Fatalf("source reads = %d, want zero", source.Count())
			}
		})
	}
}

func TestL8D3AzureResponsesRouteRejectsUnsafeDNSAndTLSBeforeSourceAccess(t *testing.T) {
	tests := []struct {
		name     string
		resolver AzureResponsesResolver
		dial     AzureResponsesDialer
	}{
		{
			name: "mixed safe and private DNS",
			resolver: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.8")}, nil
			},
			dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("must not dial") },
		},
		{
			name: "unsafe NAT64",
			resolver: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("64:ff9b::a00:8")}, nil
			},
			dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("must not dial") },
		},
		{
			name: "TLS verification failure",
			resolver: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			},
			dial: func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() { defer server.Close(); _, _ = server.Write([]byte("not TLS")) }()
				return client, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, ticket, source := l8D3RouteWithDeps(t, azureResponsesRouteDeps{resolver: tt.resolver, dial: tt.dial})
			request := l8D3ValidRouteRequest(t, ticket)
			if _, err := handler.Handle(context.Background(), request); !errors.Is(err, ErrRouteUpstreamUnavailable) {
				t.Fatalf("Handle() error = %v, want safe upstream failure", err)
			}
			if source.Count() != 0 {
				t.Fatalf("source reads = %d, want zero", source.Count())
			}
		})
	}
}

func l8D3RequestValidationRoute(t *testing.T) (*AzureResponsesRoute, *JobTicket, *l8D3CountingSecretSource) {
	t.Helper()
	return l8D3RouteWithDeps(t, azureResponsesRouteDeps{
		resolver: func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("not reached") },
		dial:     func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not reached") },
	})
}

func l8D3RouteWithDeps(t *testing.T, deps azureResponsesRouteDeps) (*AzureResponsesRoute, *JobTicket, *l8D3CountingSecretSource) {
	t.Helper()
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	definition, err := NewAzureOpenAIResponsesV1Definition("example.com", 443, "example.com", TLSRootPolicySystem, "deployment-one", "2026-06-01")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewStaticServiceCatalog("catalog-generation-01", CatalogOwnerHostAdmin, definition)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{now: func() time.Time { return now }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x72}, 64))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	source := &l8D3CountingSecretSource{value: []byte("secret")}
	handler, ticket, err := newAzureResponsesRoute(AzureResponsesRouteConfig{
		Catalog: catalog, TicketStore: store, Correlation: l8D3TicketActivation(t, now).Correlation,
		LocalAuthority: "runtime-credential.internal:8080", IssuedAt: now, Source: source, NetworkProof: &l8D3NetworkProof{},
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close(context.Background()) })
	return handler, ticket, source
}

func l8D3ValidRouteRequest(t *testing.T, ticket *JobTicket) applicationroute.Request {
	t.Helper()
	ticketValue := make([]byte, JobTicketEncodedBytes)
	_, _ = ticket.CopyTo(ticketValue)
	body := []byte(`{"model":"deployment-one"}`)
	return applicationroute.Request{
		Metadata: applicationroute.RequestMetadata{Method: "POST", ContentType: "application/json", HeaderBytes: 100, ContentLength: int64(len(body))},
		Target: applicationroute.RequestTarget{
			Authority: "runtime-credential.internal:8080",
			Path:      "/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/deployment-one/responses",
			RawQuery:  "api-version=2026-06-01",
		},
		Headers: newL8D3HeaderValues(map[string][][]byte{"api-key": {ticketValue}, "content-type": {[]byte("application/json")}}),
		Body:    bytes.NewReader(body),
	}
}

type l8D3ObservedUpstream struct {
	protocol string
	method   string
	path     string
	query    string
	host     string
	apiKey   string
	body     string
}

type l8D3HeaderValues struct {
	names  []string
	values map[string][][]byte
}

func newL8D3HeaderValues(values map[string][][]byte) *l8D3HeaderValues {
	names := make([]string, 0, len(values))
	cloned := make(map[string][][]byte, len(values))
	for name, entries := range values {
		names = append(names, name)
		for _, entry := range entries {
			cloned[name] = append(cloned[name], append([]byte(nil), entry...))
		}
	}
	slicesSortStrings(names)
	return &l8D3HeaderValues{names: names, values: cloned}
}

func (headers *l8D3HeaderValues) Names() []string            { return append([]string(nil), headers.names...) }
func (headers *l8D3HeaderValues) ValueCount(name string) int { return len(headers.values[name]) }
func (headers *l8D3HeaderValues) CopyValue(name string, index int, destination []byte) (int, error) {
	values := headers.values[name]
	if index < 0 || index >= len(values) || len(destination) < len(values[index]) {
		for index := range destination {
			destination[index] = 0
		}
		return 0, errors.New("copy rejected")
	}
	copy(destination, values[index])
	return len(values[index]), nil
}

func slicesSortStrings(values []string) {
	for left := 0; left < len(values); left++ {
		for right := left + 1; right < len(values); right++ {
			if values[right] < values[left] {
				values[left], values[right] = values[right], values[left]
			}
		}
	}
}

type l8D3CountingSecretSource struct {
	mu    sync.Mutex
	value []byte
	count int
}

func (source *l8D3CountingSecretSource) FillSecret(_ context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	source.mu.Lock()
	source.count++
	value := append([]byte(nil), source.value...)
	source.mu.Unlock()
	defer func() {
		for index := range value {
			value[index] = 0
		}
	}()
	if len(value) > sink.MaxCredentialBytes() {
		return errors.New("too large")
	}
	return sink.WriteCredential(value)
}

func (source *l8D3CountingSecretSource) Count() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.count
}

type l8D3NetworkProof struct {
	mu    sync.Mutex
	count int
	err   error
}

func (proof *l8D3NetworkProof) InspectActiveCredentialRoute(context.Context, TicketCorrelation) error {
	proof.mu.Lock()
	defer proof.mu.Unlock()
	proof.count++
	return proof.err
}

func (proof *l8D3NetworkProof) Count() int {
	proof.mu.Lock()
	defer proof.mu.Unlock()
	return proof.count
}
