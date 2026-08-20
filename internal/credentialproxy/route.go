package credentialproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute"
)

const maxUpstreamCredentialBytes = 64 << 10

var (
	ErrRouteConfigInvalid       = errors.New("credential proxy route configuration invalid")
	ErrRouteNotStarted          = errors.New("credential proxy route not started")
	ErrRouteClosed              = errors.New("credential proxy route closed")
	ErrRouteStart               = errors.New("credential proxy route start failed")
	ErrRouteCleanup             = errors.New("credential proxy route cleanup failed")
	ErrRouteRequestRejected     = errors.New("credential proxy route request rejected")
	ErrRouteUpstreamUnavailable = errors.New("credential proxy route upstream unavailable")
	ErrRouteResponseRejected    = errors.New("credential proxy route response rejected")
	ErrLiveRouteNotSerializable = errors.New("credential proxy live route is not serializable")
)

type AzureResponsesResolver func(context.Context, string, string) ([]netip.Addr, error)
type AzureResponsesDialer func(context.Context, string, string) (net.Conn, error)

type CredentialRouteNetworkProof interface {
	InspectActiveCredentialRoute(context.Context, TicketCorrelation) error
}

type AzureResponsesRouteConfig struct {
	Catalog        *StaticServiceCatalog
	TicketStore    *TicketStore
	Correlation    TicketCorrelation
	LocalAuthority string
	IssuedAt       time.Time
	Source         sandboxruntime.LiveSecretSource
	NetworkProof   CredentialRouteNetworkProof
}

func (AzureResponsesRouteConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveRouteNotSerializable
}
func (AzureResponsesRouteConfig) MarshalText() ([]byte, error) {
	return nil, ErrLiveRouteNotSerializable
}
func (AzureResponsesRouteConfig) String() string {
	return "credentialproxy.AzureResponsesRouteConfig{live}"
}
func (AzureResponsesRouteConfig) GoString() string {
	return "credentialproxy.AzureResponsesRouteConfig{live}"
}
func (AzureResponsesRouteConfig) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.AzureResponsesRouteConfig{live}"))
}

type azureResponsesRouteDeps struct {
	resolver AzureResponsesResolver
	dial     AzureResponsesDialer
	roots    *x509.CertPool
}

type AzureResponsesRoute struct {
	state *azureResponsesRouteState
}

type azureResponsesRouteState struct {
	mu             sync.Mutex
	config         AzureResponsesRouteConfig
	definition     ServiceDefinition
	ticket         *JobTicket
	resolver       AzureResponsesResolver
	dial           AzureResponsesDialer
	roots          *x509.CertPool
	started        bool
	closed         bool
	cleanupPending bool
}

var _ applicationroute.RouteHandler = (*AzureResponsesRoute)(nil)

func NewAzureResponsesRoute(config AzureResponsesRouteConfig) (*AzureResponsesRoute, *JobTicket, error) {
	return newAzureResponsesRoute(config, azureResponsesRouteDeps{})
}

func newAzureResponsesRoute(config AzureResponsesRouteConfig, deps azureResponsesRouteDeps) (*AzureResponsesRoute, *JobTicket, error) {
	if !validAzureResponsesRouteConfig(config) {
		return nil, nil, ErrRouteConfigInvalid
	}
	definition, err := config.Catalog.Lookup(ServiceIDAzureOpenAIResponsesV1)
	if err != nil || ValidateServiceDefinition(definition) != nil || config.Catalog.Generation() != config.Correlation.CatalogGeneration {
		return nil, nil, ErrRouteConfigInvalid
	}
	if deps.resolver == nil {
		deps.resolver = net.DefaultResolver.LookupNetIP
	}
	if deps.dial == nil {
		dialer := &net.Dialer{Timeout: definition.Limits().ReadIdleTimeout}
		deps.dial = dialer.DialContext
	}
	ticket, err := config.TicketStore.Issue(context.Background(), TicketActivation{
		Correlation: config.Correlation,
		IssuedAt:    config.IssuedAt,
		Source:      config.Source,
	})
	if err != nil {
		return nil, nil, ErrRouteConfigInvalid
	}
	route := &AzureResponsesRoute{state: &azureResponsesRouteState{
		config:     config,
		definition: definition,
		ticket:     ticket,
		resolver:   deps.resolver,
		dial:       deps.dial,
		roots:      cloneX509Roots(deps.roots),
	}}
	return route, ticket, nil
}

func (route *AzureResponsesRoute) Definition() applicationroute.Definition {
	state := route.sharedState()
	if state == nil {
		return applicationroute.Definition{}
	}
	limits := state.definition.Limits()
	return applicationroute.Definition{
		ID:     applicationroute.RouteCredentialHTTPV1,
		Prefix: applicationroute.CredentialHTTPV1Prefix,
		Limits: applicationroute.StreamLimits{
			MaxRequestHeaderBytes:  limits.MaxRequestHeaderBytes,
			MaxRequestBodyBytes:    limits.MaxRequestBodyBytes,
			MaxResponseHeaderBytes: limits.MaxResponseHeaderBytes,
			MaxResponseBodyBytes:   limits.MaxResponseBodyBytes,
			MaxEventBytes:          limits.MaxSSEEventBytes,
		},
	}
}

func (route *AzureResponsesRoute) Start(ctx context.Context) error {
	state := route.sharedState()
	if state == nil || ctx == nil {
		return ErrRouteStart
	}
	if err := ctx.Err(); err != nil {
		return ErrRouteStart
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.cleanupPending {
		return ErrRouteClosed
	}
	if state.started {
		return ErrRouteStart
	}
	state.started = true
	return nil
}

func (route *AzureResponsesRoute) Handle(ctx context.Context, request applicationroute.Request) (applicationroute.Response, error) {
	state := route.sharedState()
	if state == nil || ctx == nil {
		return applicationroute.Response{}, ErrRouteRequestRejected
	}
	state.mu.Lock()
	if !state.started {
		state.mu.Unlock()
		return applicationroute.Response{}, ErrRouteNotStarted
	}
	if state.closed || state.cleanupPending {
		state.mu.Unlock()
		return applicationroute.Response{}, ErrRouteClosed
	}
	config := state.config
	definition := state.definition
	resolver := state.resolver
	dial := state.dial
	roots := state.roots
	state.mu.Unlock()

	body, err := validateAzureResponsesRequest(request, config.LocalAuthority, definition)
	if err != nil {
		return applicationroute.Response{}, ErrRouteRequestRejected
	}
	defer wipeBytes(body)
	ticketMapping, err := copyPresentedTicket(ctx, request.Headers, definition.TicketHeader())
	if err != nil {
		return applicationroute.Response{}, ErrRouteRequestRejected
	}
	defer ticketMapping.Destroy()

	var lease *TicketRequestLease
	var acquireErr error
	borrowErr := ticketMapping.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		lease, acquireErr = config.TicketStore.acquirePresentedTicket(ctx, view, config.Correlation)
		return nil
	})
	if borrowErr != nil || acquireErr != nil || lease == nil {
		return applicationroute.Response{}, ErrRouteRequestRejected
	}
	defer lease.Release()

	if err := config.NetworkProof.InspectActiveCredentialRoute(ctx, config.Correlation); err != nil {
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	target, err := resolveAzureResponsesTarget(ctx, resolver, definition)
	if err != nil {
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	raw, err := dial(ctx, "tcp", target)
	if err != nil || raw == nil || typedNil(raw) {
		if raw != nil {
			_ = raw.Close()
		}
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	if err := lease.OwnConnection(raw); err != nil {
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	secure, err := startVerifiedAzureResponsesTLS(ctx, raw, definition, roots)
	if err != nil {
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	if err := config.NetworkProof.InspectActiveCredentialRoute(ctx, config.Correlation); err != nil {
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	if err := lease.Revalidate(ctx, config.Correlation); err != nil {
		return applicationroute.Response{}, ErrRouteRequestRejected
	}
	if err := writeAzureResponsesRequest(ctx, secure, lease, config.Correlation, definition, body); err != nil {
		return applicationroute.Response{}, ErrRouteUpstreamUnavailable
	}
	response, err := readAzureResponsesResponse(secure, definition)
	if err != nil {
		return applicationroute.Response{}, err
	}
	return response, nil
}

func (route *AzureResponsesRoute) Close(ctx context.Context) error {
	state := route.sharedState()
	if state == nil || ctx == nil {
		return ErrRouteCleanup
	}
	state.mu.Lock()
	if state.closed && !state.cleanupPending {
		state.mu.Unlock()
		return nil
	}
	state.started = false
	state.cleanupPending = true
	config := state.config
	ticket := state.ticket
	state.mu.Unlock()

	err := config.TicketStore.Revoke(ctx, ticket, config.Correlation)
	state.mu.Lock()
	defer state.mu.Unlock()
	if err != nil {
		return ErrRouteCleanup
	}
	state.cleanupPending = false
	state.closed = true
	return nil
}

func validAzureResponsesRouteConfig(config AzureResponsesRouteConfig) bool {
	return config.Catalog != nil && config.TicketStore != nil && validTicketCorrelation(config.Correlation) &&
		validLocalRuntimeAuthority(config.LocalAuthority) && !config.IssuedAt.IsZero() &&
		config.Source != nil && !typedNil(config.Source) && config.NetworkProof != nil && !typedNil(config.NetworkProof)
}

func validLocalRuntimeAuthority(authority string) bool {
	if authority == "" || len(authority) > 512 || strings.ContainsAny(authority, "@/\\?# \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	portNumber, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && host != "" && portNumber > 0 && portNumber <= 65535
}

func (route *AzureResponsesRoute) sharedState() *azureResponsesRouteState {
	if route == nil {
		return nil
	}
	return route.state
}

func (AzureResponsesRoute) MarshalJSON() ([]byte, error) { return nil, ErrLiveRouteNotSerializable }
func (AzureResponsesRoute) MarshalText() ([]byte, error) { return nil, ErrLiveRouteNotSerializable }
func (AzureResponsesRoute) String() string               { return "credentialproxy.AzureResponsesRoute{live}" }
func (AzureResponsesRoute) GoString() string             { return "credentialproxy.AzureResponsesRoute{live}" }
func (AzureResponsesRoute) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.AzureResponsesRoute{live}"))
}

func copyPresentedTicket(ctx context.Context, headers applicationroute.RequestHeaderValues, name string) (*credentialmemory.LockedMapping, error) {
	if headers == nil || typedNil(headers) || headers.ValueCount(name) != 1 {
		return nil, ErrRouteRequestRejected
	}
	mapping, err := credentialmemory.NewLockedMapping(JobTicketEncodedBytes)
	if err != nil {
		return nil, ErrRouteRequestRejected
	}
	loadErr := mapping.Load(ctx, func(destination []byte) (count int, result error) {
		defer func() {
			if recover() != nil {
				wipeBytes(destination)
				count = 0
				result = ErrRouteRequestRejected
			}
		}()
		count, result = headers.CopyValue(name, 0, destination)
		if result != nil || count != JobTicketEncodedBytes || !validEncodedTicket(destination[:count]) {
			wipeBytes(destination)
			return 0, ErrRouteRequestRejected
		}
		return count, nil
	})
	if loadErr != nil {
		_ = mapping.Destroy()
		return nil, ErrRouteRequestRejected
	}
	return mapping, nil
}

func cloneX509Roots(roots *x509.CertPool) *x509.CertPool {
	if roots == nil {
		return nil
	}
	return roots.Clone()
}

func startVerifiedAzureResponsesTLS(ctx context.Context, raw net.Conn, definition ServiceDefinition, roots *x509.CertPool) (*tls.Conn, error) {
	if raw == nil || ctx == nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	policy := definition.SealedTLS()
	secure := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: policy.ServerName(),
		RootCAs:    cloneX509Roots(roots),
		NextProtos: []string{"http/1.1"},
	})
	deadline := time.Now().Add(definition.Limits().ReadIdleTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = secure.SetDeadline(deadline)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	state := secure.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return nil, ErrRouteUpstreamUnavailable
	}
	return secure, nil
}

func requestHeaderNames(headers applicationroute.RequestHeaderValues) (names []string, ok bool) {
	defer func() {
		if recover() != nil {
			names = nil
			ok = false
		}
	}()
	names = headers.Names()
	return names, true
}

func copySafeHeaderValue(headers applicationroute.RequestHeaderValues, name string, maximum int) ([]byte, error) {
	if maximum <= 0 || headers.ValueCount(name) != 1 {
		return nil, ErrRouteRequestRejected
	}
	value := make([]byte, maximum)
	count, err := headers.CopyValue(name, 0, value)
	if err != nil || count <= 0 || count > maximum {
		wipeBytes(value)
		return nil, ErrRouteRequestRejected
	}
	return value[:count], nil
}
