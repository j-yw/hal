package credentialproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
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
	network := &l8D3NetworkProof{wantLocalAuthority: "runtime-credential.internal:8080"}
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
	for _, value := range []any{handler, *handler} {
		if rendered := fmt.Sprintf("%#v", value); rendered != "credentialproxy.AzureResponsesRoute{live}" {
			t.Fatalf("route formatting = %q", rendered)
		}
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
	if network.LastLocalAuthority() != "runtime-credential.internal:8080" {
		t.Fatalf("network proof local authority = %q, want exact route binding", network.LastLocalAuthority())
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

func TestL8D3AzureResponsesRouteContainsHeaderAccessorPanicsAndUnstableCounts(t *testing.T) {
	handler, ticket, source := l8D3RequestValidationRoute(t)
	request := l8D3ValidRouteRequest(t, ticket)
	base := request.Headers.(*l8D3HeaderValues)
	request.Headers = &l8D3AdversarialHeaderValues{l8D3HeaderValues: base, panicCopy: "content-type"}
	if _, err := handler.Handle(context.Background(), request); !errors.Is(err, ErrRouteRequestRejected) {
		t.Fatalf("content-type CopyValue panic error = %v, want sanitized rejection", err)
	}
	if source.Count() != 0 {
		t.Fatalf("source reads after accessor panic = %d, want zero", source.Count())
	}

	metadata := &l8D3AdversarialHeaderValues{
		l8D3HeaderValues: newL8D3HeaderValues(map[string][][]byte{"user-agent": {[]byte("pi/0.82.1")}}),
		panicCopy:        "user-agent",
	}
	if value, err := copySafeHeaderValue(metadata, "user-agent", 64); !errors.Is(err, ErrRouteRequestRejected) || value != nil {
		t.Fatalf("metadata CopyValue panic = (%q, %v), want sanitized all-or-error", value, err)
	}

	unstable := &l8D3AdversarialHeaderValues{
		l8D3HeaderValues: newL8D3HeaderValues(map[string][][]byte{"content-type": {[]byte("application/json")}}),
		countName:        "content-type",
		counts:           []int{1, 2},
	}
	if value, err := copySafeHeaderValue(unstable, "content-type", 64); !errors.Is(err, ErrRouteRequestRejected) || value != nil {
		t.Fatalf("unstable ValueCount copy = (%q, %v), want sanitized all-or-error", value, err)
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
				go func() {
					defer server.Close()
					var hello [4096]byte
					_, _ = server.Read(hello[:])
					_, _ = server.Write([]byte("not TLS"))
				}()
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

func TestL8D3AzureResponsesRouteCloseClearsOwnedTicketAndLiveSources(t *testing.T) {
	handler, ticket, _ := l8D3RequestValidationRoute(t)
	store := handler.state.config.TicketStore
	digest, err := store.digestJobTicket(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}

	if err := handler.Close(context.Background()); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if err := handler.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close() error: %v", err)
	}
	handler.state.mu.Lock()
	routeSourceRetained := handler.state.config.Source != nil
	routeTicketRetained := handler.state.ticket != nil
	routeStoreRetained := handler.state.config.TicketStore != nil
	routeProofRetained := handler.state.config.NetworkProof != nil
	handler.state.mu.Unlock()
	store.state.mu.Lock()
	entry := store.state.entries[digest]
	storeSourceRetained := entry != nil && entry.source != nil
	store.state.mu.Unlock()
	if routeSourceRetained || routeTicketRetained || routeStoreRetained || routeProofRetained || storeSourceRetained {
		t.Fatalf("closed route retained live capabilities: routeSource=%t routeTicket=%t routeStore=%t routeProof=%t storeSource=%t",
			routeSourceRetained, routeTicketRetained, routeStoreRetained, routeProofRetained, storeSourceRetained)
	}
}

func TestL8D3AzureResponsesRouteCloseFailureRetainsOnlyRetryTombstone(t *testing.T) {
	handler, ticket, _ := l8D3RequestValidationRoute(t)
	store := handler.state.config.TicketStore
	correlation := handler.state.config.Correlation
	lease := l8D3AcquireTicket(t, store, ticket, correlation)
	closer := &l8D3TicketCloser{failures: 1}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatal(err)
	}

	if err := handler.Close(context.Background()); !errors.Is(err, ErrRouteCleanup) {
		t.Fatalf("first Close() error = %v, want cleanup incomplete", err)
	}
	handler.state.mu.Lock()
	firstSourceRetained := handler.state.config.Source != nil
	firstTicketRetained := handler.state.ticket != nil
	firstStoreRetained := handler.state.config.TicketStore != nil
	firstProofRetained := handler.state.config.NetworkProof != nil
	firstResolverRetained := handler.state.resolver != nil
	firstDialRetained := handler.state.dial != nil
	firstRootsRetained := handler.state.roots != nil
	handler.state.mu.Unlock()
	if firstSourceRetained || !firstTicketRetained || !firstStoreRetained || firstProofRetained || firstResolverRetained || firstDialRetained || firstRootsRetained {
		t.Fatalf("cleanup retry retained more than tombstone: source=%t ticket=%t store=%t proof=%t resolver=%t dial=%t roots=%t",
			firstSourceRetained, firstTicketRetained, firstStoreRetained, firstProofRetained, firstResolverRetained, firstDialRetained, firstRootsRetained)
	}
	if err := handler.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() error: %v", err)
	}
	if closer.Count() != 2 {
		t.Fatalf("route cleanup close attempts = %d, want retained retry", closer.Count())
	}
	handler.state.mu.Lock()
	finalTicketRetained := handler.state.ticket != nil
	finalStoreRetained := handler.state.config.TicketStore != nil
	handler.state.mu.Unlock()
	if finalTicketRetained || finalStoreRetained {
		t.Fatalf("completed route cleanup retained tombstone: ticket=%t store=%t", finalTicketRetained, finalStoreRetained)
	}
}

func TestL8D3AzureResponsesRouteConcurrentCloseConvergesCleanup(t *testing.T) {
	handler, ticket, _ := l8D3RequestValidationRoute(t)
	store := handler.state.config.TicketStore
	correlation := handler.state.config.Correlation
	lease := l8D3AcquireTicket(t, store, ticket, correlation)
	closer := &l8D3TicketCloser{failures: 1}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatal(err)
	}

	const callers = 16
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsSeen <- handler.Close(context.Background())
		}()
	}
	group.Wait()
	close(errorsSeen)
	for closeErr := range errorsSeen {
		if closeErr != nil && !errors.Is(closeErr, ErrRouteCleanup) {
			t.Errorf("concurrent Close() error = %v", closeErr)
		}
	}
	if err := handler.Close(context.Background()); err != nil {
		t.Fatalf("final Close() error: %v", err)
	}
	if closer.Count() != 2 {
		t.Fatalf("concurrent route close attempts = %d, want one failure and one retry", closer.Count())
	}
	handler.state.mu.Lock()
	retained := handler.state.ticket != nil || handler.state.config.Source != nil || handler.state.config.TicketStore != nil
	handler.state.mu.Unlock()
	if retained {
		t.Fatal("concurrent route cleanup retained live capabilities")
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

type l8D3AdversarialHeaderValues struct {
	*l8D3HeaderValues
	panicCopy string
	countName string
	counts    []int
	countCall int
}

func (headers *l8D3AdversarialHeaderValues) ValueCount(name string) int {
	if name == headers.countName && headers.countCall < len(headers.counts) {
		count := headers.counts[headers.countCall]
		headers.countCall++
		return count
	}
	return headers.l8D3HeaderValues.ValueCount(name)
}

func (headers *l8D3AdversarialHeaderValues) CopyValue(name string, index int, destination []byte) (int, error) {
	if name == headers.panicCopy {
		copy(destination, []byte("raw-header-canary"))
		panic("raw header panic api-key=canary")
	}
	return headers.l8D3HeaderValues.CopyValue(name, index, destination)
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
	mu                 sync.Mutex
	count              int
	err                error
	wantLocalAuthority string
	lastLocalAuthority string
}

func (proof *l8D3NetworkProof) InspectActiveCredentialRoute(_ context.Context, correlation TicketCorrelation) error {
	proof.mu.Lock()
	defer proof.mu.Unlock()
	proof.count++
	proof.lastLocalAuthority = correlation.LocalAuthority
	if proof.wantLocalAuthority != "" && correlation.LocalAuthority != proof.wantLocalAuthority {
		return errors.New("local authority binding mismatch")
	}
	return proof.err
}

func (proof *l8D3NetworkProof) Count() int {
	proof.mu.Lock()
	defer proof.mu.Unlock()
	return proof.count
}

func (proof *l8D3NetworkProof) LastLocalAuthority() string {
	proof.mu.Lock()
	defer proof.mu.Unlock()
	return proof.lastLocalAuthority
}
