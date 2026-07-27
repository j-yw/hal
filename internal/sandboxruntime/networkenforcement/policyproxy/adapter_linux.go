//go:build linux

package policyproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

const productionAdapterID = "production-policy-proxy"

var _ networkenforcement.ProxyListenerAdapter = (*Adapter)(nil)

// Adapter owns one explicitly configured Linux loopback policy proxy.
type Adapter struct {
	config Config

	mu         sync.Mutex
	server     *http.Server
	listener   net.Listener
	endpoint   string
	cancel     context.CancelFunc
	done       chan error
	sem        chan struct{}
	tunnels    map[net.Conn]struct{}
	generation uint64
	stopping   bool

	// beforeTunnelTrack is a package-test synchronization seam. Production
	// construction leaves it nil.
	beforeTunnelTrack func()
}

// New validates immutable configuration without binding a listener.
func New(config Config) (*Adapter, error) {
	config.Limits = normalizeLimits(config.Limits)
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:0"
	}
	if !validLimits(config.Limits) || !validLoopbackListenAddress(config.ListenAddress) {
		return nil, ErrInvalidConfig
	}
	plan := config.Policy.PlanMetadata()
	if plan.ID == "" || plan.Proxy == nil || plan.Proxy.Mechanism != networkenforcement.EnforcementMechanismProxy {
		return nil, ErrInvalidConfig
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver.LookupNetIP
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{Timeout: config.Limits.RequestTimeout}
		config.DialContext = dialer.DialContext
	}
	return &Adapter{
		config:  config,
		sem:     make(chan struct{}, config.Limits.MaxConcurrent),
		tunnels: make(map[net.Conn]struct{}),
	}, nil
}

func validLoopbackListenAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535
}

// PrepareProxyListener validates identity and bounds without binding.
func (a *Adapter) PrepareProxyListener(ctx context.Context, request networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if err := ctx.Err(); err != nil {
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonAdapterFailed), safeAdapterError("prepare")
	}
	if !a.matchesPlan(request) || !validLimits(a.config.Limits) {
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonCapabilityMissing), safeAdapterError("prepare")
	}
	return a.metadata(request, networkenforcement.LifecycleStatusPrepared, networkenforcement.LifecycleReasonPrepared), nil
}

// StartProxyListener binds the owned loopback listener and starts serving.
func (a *Adapter) StartProxyListener(ctx context.Context, request networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if err := ctx.Err(); err != nil || !a.matchesPlan(request) {
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonAdapterFailed), safeAdapterError("start")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.listener != nil {
		return a.metadata(request, networkenforcement.LifecycleStatusStarting, networkenforcement.LifecycleReasonStarted), nil
	}

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", a.config.ListenAddress)
	if err != nil {
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonAdapterFailed), safeAdapterError("start")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	server := &http.Server{
		Handler:           a,
		ReadHeaderTimeout: a.config.Limits.ReadHeaderTimeout,
		ReadTimeout:       a.config.Limits.ReadTimeout,
		WriteTimeout:      a.config.Limits.WriteTimeout,
		IdleTimeout:       a.config.Limits.IdleTimeout,
		MaxHeaderBytes:    a.config.Limits.MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return lifetime
		},
	}
	done := make(chan error, 1)
	a.generation++
	generation := a.generation
	a.stopping = false
	a.listener = listener
	a.endpoint = listener.Addr().String()
	a.cancel = cancel
	a.server = server
	a.done = done
	go func() {
		serveErr := server.Serve(listener)
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		a.superviseServeExit(generation, server, listener, cancel, serveErr)
		done <- serveErr
		close(done)
	}()
	return a.metadata(request, networkenforcement.LifecycleStatusStarting, networkenforcement.LifecycleReasonStarted), nil
}

// ActiveProxyListener proves only that this adapter's listener serve loop is
// still owned and live.
func (a *Adapter) ActiveProxyListener(ctx context.Context, request networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if err := ctx.Err(); err != nil || !a.matchesPlan(request) {
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonActiveCheckFailed), safeAdapterError("active")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.listener == nil || a.server == nil || a.done == nil {
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonActiveCheckFailed), safeAdapterError("active")
	}
	select {
	case <-a.done:
		return a.metadata(request, networkenforcement.LifecycleStatusFailed, networkenforcement.LifecycleReasonActiveCheckFailed), safeAdapterError("active")
	default:
	}
	return a.metadata(request, networkenforcement.LifecycleStatusActive, networkenforcement.LifecycleReasonActive), nil
}

// StopProxyListener performs bounded idempotent cleanup even when the caller
// context has already been canceled.
func (a *Adapter) StopProxyListener(_ context.Context, request networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	a.mu.Lock()
	a.stopping = true
	generation := a.generation
	server := a.server
	listener := a.listener
	cancel := a.cancel
	done := a.done
	tunnels := make([]net.Conn, 0, len(a.tunnels))
	for conn := range a.tunnels {
		tunnels = append(tunnels, conn)
	}
	a.server = nil
	a.listener = nil
	a.endpoint = ""
	a.cancel = nil
	a.done = nil
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, conn := range tunnels {
		_ = conn.Close()
	}
	if server != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), a.config.Limits.ShutdownTimeout)
		_ = server.Shutdown(cleanupCtx)
		cleanupCancel()
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if done != nil {
		timer := time.NewTimer(a.config.Limits.ShutdownTimeout)
		select {
		case <-done:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	a.mu.Lock()
	if a.generation == generation && a.server == nil {
		for conn := range a.tunnels {
			delete(a.tunnels, conn)
		}
	}
	a.mu.Unlock()
	return a.metadata(request, networkenforcement.LifecycleStatusStopped, networkenforcement.LifecycleReasonStopped), nil
}

func (a *Adapter) superviseServeExit(generation uint64, server *http.Server, listener net.Listener, cancel context.CancelFunc, serveErr error) {
	if serveErr == nil {
		return
	}
	a.mu.Lock()
	if a.generation != generation || a.server != server || a.listener != listener || a.stopping {
		a.mu.Unlock()
		return
	}
	a.stopping = true
	tunnels := make([]net.Conn, 0, len(a.tunnels))
	for conn := range a.tunnels {
		tunnels = append(tunnels, conn)
		delete(a.tunnels, conn)
	}
	a.server = nil
	a.listener = nil
	a.endpoint = ""
	a.cancel = nil
	a.done = nil
	a.mu.Unlock()

	cancel()
	for _, conn := range tunnels {
		_ = conn.Close()
	}
	_ = listener.Close()
	_ = server.Close()
}

// Endpoint returns the live-only listener endpoint for explicit L7 topology
// wiring. It is never included in lifecycle proof or JSON metadata.
func (a *Adapter) Endpoint() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.endpoint == "" || a.listener == nil {
		return "", false
	}
	select {
	case <-a.done:
		return "", false
	default:
		return a.endpoint, true
	}
}

func (a *Adapter) matchesPlan(request networkenforcement.ProxyListenerLifecycleRequest) bool {
	configured := a.config.Policy.PlanMetadata()
	requested := request.Plan.Plan()
	if configured.ID == "" || configured.ID != requested.ID || configured.Proxy == nil || requested.Proxy == nil {
		return false
	}
	return configured.Proxy.ProxySessionID == requested.Proxy.ProxySessionID
}

func (a *Adapter) metadata(request networkenforcement.ProxyListenerLifecycleRequest, status networkenforcement.LifecycleStatus, reason networkenforcement.LifecycleReasonCode) networkenforcement.ProxyListenerLifecycleMetadata {
	plan := request.Plan.Plan()
	metadata := networkenforcement.ProxyListenerLifecycleMetadata{
		PlanID:           plan.ID,
		AdapterID:        productionAdapterID,
		Status:           status,
		Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismProxy},
		PolicySnapshot:   plan.PolicySnapshot,
		CapabilityLabels: []string{"http_connect", "http_request", "proxy_listener"},
		ReasonCode:       reason,
	}
	if plan.Proxy != nil {
		metadata.ID = plan.Proxy.ProxySessionID
		metadata.Operations = append([]string(nil), plan.Proxy.Operations...)
	}
	return networkenforcement.SanitizeProxyListenerLifecycleMetadata(metadata)
}

type adapterError string

func (e adapterError) Error() string { return string(e) }

func safeAdapterError(operation string) error {
	switch operation {
	case "prepare", "start", "active":
		return adapterError("production policy proxy " + operation + " failed")
	default:
		return adapterError("production policy proxy failed")
	}
}

func (a *Adapter) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	a.mu.Lock()
	generation := a.generation
	stopping := a.stopping
	a.mu.Unlock()
	if stopping {
		a.emitSyntheticDecision(networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		safeHTTPError(w, http.StatusServiceUnavailable)
		return
	}
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		a.emitSyntheticDecision(networkenforcement.PolicyProxyDecisionReasonRequestBoundsExceeded, "")
		safeHTTPError(w, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), a.config.Limits.RequestTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	if request.Method == http.MethodConnect {
		a.serveConnect(w, request, generation)
		return
	}
	a.serveHTTP(w, request)
}

func (a *Adapter) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if !validForwardRequest(request) {
		a.emitSyntheticDecision(networkenforcement.PolicyProxyDecisionReasonProxyUnsupported, "")
		safeHTTPError(w, http.StatusBadRequest)
		return
	}
	result := networkenforcement.EvaluatePolicyProxyServiceDecisionResult(
		a.config.Policy,
		networkenforcement.PolicyProxyDecisionRequest{
			Kind: networkenforcement.PolicyProxyRequestKindHTTPRequestHost,
			Host: request.URL.Host,
		},
	)
	if result.Decision.Action != networkenforcement.PolicyProxyDecisionActionAllow {
		a.emitDecision(result)
		safeHTTPError(w, http.StatusForbidden)
		return
	}

	body, tooLarge, err := readBounded(request.Body, a.config.Limits.MaxRequestBodyBytes)
	if err != nil {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonRequestBoundsExceeded, "")
		safeHTTPError(w, http.StatusBadRequest)
		return
	}
	if tooLarge {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonRequestBoundsExceeded, "")
		safeHTTPError(w, http.StatusRequestEntityTooLarge)
		return
	}

	targets, destinationStatus, category := a.resolveTargets(request.Context(), request.URL.Host, "80")
	if destinationStatus != 0 {
		a.emitResolutionDecision(result, destinationStatus, category)
		safeHTTPError(w, destinationStatus)
		return
	}
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.ContentLength = int64(len(body))
	outbound.Header = request.Header.Clone()
	removeHopHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Authorization")
	outbound.Header.Del("Accept-Encoding")

	upstream, err := a.dialTargets(request.Context(), "tcp", targets)
	if err != nil {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(a.config.Limits.RequestTimeout))
	outbound.URL = cloneURL(outbound.URL)
	outbound.URL.Scheme = ""
	outbound.URL.Host = ""
	if err := outbound.Write(upstream); err != nil {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}
	responseReader, err := boundedResponseReader(upstream, a.config.Limits.MaxResponseHeaderBytes)
	if err != nil {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonResponseBoundsExceeded, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}
	response, err := http.ReadResponse(responseReader, outbound)
	if err != nil {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonProxyUnsupported, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}
	responseBody, tooLarge, err := readBounded(response.Body, a.config.Limits.MaxResponseBodyBytes)
	if err != nil || tooLarge {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonResponseBoundsExceeded, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}
	a.emitDecision(result)
	removeHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody)
}

func validForwardRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || !request.URL.IsAbs() {
		return false
	}
	if request.URL.User != nil || !strings.EqualFold(request.URL.Scheme, "http") || request.URL.Host == "" {
		return false
	}
	if request.Host == "" || !sameAuthority(request.Host, request.URL.Host, "80") {
		return false
	}
	return request.Header.Get("Upgrade") == ""
}

func sameAuthority(left, right, defaultPort string) bool {
	leftHost, leftPort, ok := splitAuthority(left, defaultPort)
	if !ok {
		return false
	}
	rightHost, rightPort, ok := splitAuthority(right, defaultPort)
	return ok && strings.EqualFold(leftHost, rightHost) && leftPort == rightPort
}

func (a *Adapter) serveConnect(w http.ResponseWriter, request *http.Request, generation uint64) {
	authority := request.Host
	if authority == "" {
		authority = request.RequestURI
	}
	host, _, ok := splitAuthority(authority, "")
	if !ok || host == "" {
		a.emitSyntheticDecision(networkenforcement.PolicyProxyDecisionReasonProxyUnsupported, "")
		safeHTTPError(w, http.StatusBadRequest)
		return
	}
	result := networkenforcement.EvaluatePolicyProxyServiceDecisionResult(
		a.config.Policy,
		networkenforcement.PolicyProxyDecisionRequest{
			Kind:      networkenforcement.PolicyProxyRequestKindHTTPConnect,
			Authority: authority,
		},
	)
	if result.Decision.Action != networkenforcement.PolicyProxyDecisionActionAllow {
		a.emitDecision(result)
		safeHTTPError(w, http.StatusForbidden)
		return
	}
	targets, destinationStatus, category := a.resolveTargets(request.Context(), authority, "")
	if destinationStatus != 0 {
		a.emitResolutionDecision(result, destinationStatus, category)
		safeHTTPError(w, destinationStatus)
		return
	}
	upstream, err := a.dialTargets(request.Context(), "tcp", targets)
	if err != nil {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		safeHTTPError(w, http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonProxyUnsupported, "")
		safeHTTPError(w, http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		return
	}
	if a.beforeTunnelTrack != nil {
		a.beforeTunnelTrack()
	}
	if !a.ownTunnelPair(generation, client, upstream) {
		a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, networkenforcement.PolicyProxyDecisionReasonUpstreamUnavailable, "")
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	a.emitDecision(result)
	defer func() {
		a.releaseTunnelPair(client, upstream)
		_ = client.Close()
		_ = upstream.Close()
	}()
	deadline := time.Now().Add(a.config.Limits.ConnectTimeout)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err := io.WriteString(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	copyDone := make(chan tunnelCopyResult, 2)
	clientSource := io.Reader(client)
	if buffered.Reader.Buffered() > 0 {
		clientSource = io.MultiReader(buffered.Reader, client)
	}
	go boundedTunnelCopy(upstream, clientSource, client, a.config.Limits.MaxConnectBytes, copyDone)
	go boundedTunnelCopy(client, upstream, upstream, a.config.Limits.MaxConnectBytes, copyDone)
	select {
	case <-request.Context().Done():
	case first := <-copyDone:
		closeWrite(first.destination)
		select {
		case <-request.Context().Done():
		case second := <-copyDone:
			closeWrite(second.destination)
		}
	}
}

type tunnelCopyResult struct {
	destination net.Conn
}

func boundedTunnelCopy(dst net.Conn, src io.Reader, deadlineSource net.Conn, limit int64, done chan<- tunnelCopyResult) {
	written, _ := io.CopyN(dst, src, limit)
	if written == limit {
		_ = deadlineSource.SetReadDeadline(time.Now())
		var extra [1]byte
		_, _ = src.Read(extra[:])
	}
	done <- tunnelCopyResult{destination: dst}
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if current, ok := conn.(closeWriter); ok {
		_ = current.CloseWrite()
	}
}

func (a *Adapter) ownTunnelPair(generation uint64, left, right net.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopping || generation != a.generation || a.listener == nil || a.server == nil {
		return false
	}
	a.tunnels[left] = struct{}{}
	a.tunnels[right] = struct{}{}
	return true
}

func (a *Adapter) releaseTunnelPair(left, right net.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tunnels, left)
	delete(a.tunnels, right)
}

func (a *Adapter) emitDecision(result networkenforcement.PolicyProxyServiceDecisionResult) {
	if result.DecisionLog == nil {
		return
	}
	a.enqueueDecision(*result.DecisionLog)
}

func (a *Adapter) emitResolutionDecision(result networkenforcement.PolicyProxyServiceDecisionResult, status int, category networkenforcement.AllowlistRuleCategory) {
	a.emitFinalDecision(result, networkenforcement.PolicyProxyDecisionActionDeny, resolutionReason(status), category)
}

func resolutionReason(status int) networkenforcement.PolicyProxyDecisionReasonCode {
	if status == http.StatusForbidden {
		return networkenforcement.PolicyProxyDecisionReasonResolvedDestinationBlocked
	}
	return networkenforcement.PolicyProxyDecisionReasonDestinationResolutionFailed
}

func (a *Adapter) emitFinalDecision(result networkenforcement.PolicyProxyServiceDecisionResult, action networkenforcement.PolicyProxyDecisionAction, reason networkenforcement.PolicyProxyDecisionReasonCode, category networkenforcement.AllowlistRuleCategory) {
	if result.DecisionLog == nil {
		a.emitSyntheticDecision(reason, category)
		return
	}
	record := *result.DecisionLog
	record.Action = action
	record.ReasonCode = reason
	if category != "" {
		record.DestinationCategory = category
	}
	a.enqueueDecision(record)
}

func (a *Adapter) emitSyntheticDecision(reason networkenforcement.PolicyProxyDecisionReasonCode, category networkenforcement.AllowlistRuleCategory) {
	plan := a.config.Policy.PlanMetadata()
	record := networkenforcement.PolicyProxyDecisionLogRecord{
		Action:              networkenforcement.PolicyProxyDecisionActionDeny,
		ReasonCode:          reason,
		DestinationCategory: category,
		Count:               1,
	}
	if plan.PolicySnapshot != nil {
		record.PolicySnapshotID = plan.PolicySnapshot.ID
		record.RuleSetID = plan.PolicySnapshot.RuleSetID
	}
	a.enqueueDecision(record)
}

func (a *Adapter) enqueueDecision(record networkenforcement.PolicyProxyDecisionLogRecord) {
	if a.config.DecisionSink == nil {
		return
	}
	record = networkenforcement.SanitizePolicyProxyDecisionLogRecord(record)
	func() {
		defer func() { _ = recover() }()
		a.config.DecisionSink(record)
	}()
}

func (a *Adapter) resolveTargets(ctx context.Context, authority, defaultPort string) ([]string, int, networkenforcement.AllowlistRuleCategory) {
	host, port, ok := splitAuthority(authority, defaultPort)
	if !ok {
		return nil, http.StatusBadRequest, ""
	}
	var addresses []netip.Addr
	if direct, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{direct}
	} else {
		resolved, err := a.config.Resolver(ctx, "ip", host)
		if err != nil || len(resolved) == 0 || len(resolved) > a.config.Limits.MaxResolvedAddresses {
			return nil, http.StatusBadGateway, ""
		}
		addresses = resolved
	}
	targets := make([]string, 0, len(addresses))
	seen := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if category := unsafeResolvedAddressCategory(address); category != "" {
			return nil, http.StatusForbidden, category
		}
		if seen[address] {
			continue
		}
		seen[address] = true
		targets = append(targets, net.JoinHostPort(address.String(), port))
	}
	if len(targets) == 0 {
		return nil, http.StatusForbidden, ""
	}
	return targets, 0, ""
}

func unsafeResolvedAddressCategory(address netip.Addr) networkenforcement.AllowlistRuleCategory {
	if !address.IsValid() || address.Zone() != "" {
		return networkenforcement.AllowlistRuleCategoryEndpoint
	}
	switch address.String() {
	case "169.254.169.254", "169.254.170.2", "fd00:ec2::254":
		return networkenforcement.AllowlistRuleCategoryMetadataEndpoint
	}
	if address.IsUnspecified() || address.IsLoopback() ||
		address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsMulticast() || specialUseAddress(address) {
		switch {
		case address.IsLoopback():
			return networkenforcement.AllowlistRuleCategoryLoopback
		case address.IsPrivate():
			return networkenforcement.AllowlistRuleCategoryPrivateRange
		case address.IsLinkLocalUnicast():
			return networkenforcement.AllowlistRuleCategoryLinkLocal
		default:
			return networkenforcement.AllowlistRuleCategoryEndpoint
		}
	}
	if !address.IsGlobalUnicast() {
		return networkenforcement.AllowlistRuleCategoryEndpoint
	}
	return ""
}

func specialUseAddress(address netip.Addr) bool {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func splitAuthority(authority, defaultPort string) (string, string, bool) {
	authority = strings.TrimSpace(authority)
	if authority == "" || strings.ContainsAny(authority, "/?#@ \t\r\n") {
		return "", "", false
	}
	host, port, err := net.SplitHostPort(authority)
	if err == nil {
		if host == "" || !validPort(port) {
			return "", "", false
		}
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), port, true
	}
	if strings.Contains(authority, ":") {
		return "", "", false
	}
	if defaultPort == "" {
		return "", "", false
	}
	return authority, defaultPort, true
}

func validPort(port string) bool {
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}

func (a *Adapter) dialTargets(ctx context.Context, network string, targets []string) (net.Conn, error) {
	for _, target := range targets {
		conn, err := a.config.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
	}
	return nil, safeAdapterError("dial")
}

func readBounded(reader io.Reader, limit int64) ([]byte, bool, error) {
	if reader == nil {
		return nil, false, nil
	}
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(payload)) > limit {
		return nil, true, nil
	}
	return payload, false, nil
}

func removeHopHeaders(header http.Header) {
	var connectionTokens []string
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				connectionTokens = append(connectionTokens, token)
			}
		}
	}
	for _, token := range connectionTokens {
		header.Del(token)
	}
	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func cloneURL(input *url.URL) *url.URL {
	if input == nil {
		return &url.URL{}
	}
	out := *input
	return &out
}

func boundedResponseReader(conn net.Conn, limit int64) (*bufio.Reader, error) {
	header := make([]byte, 0, minInt64(limit, 4096))
	var tail [4]byte
	for int64(len(header)) <= limit {
		var current [1]byte
		if _, err := io.ReadFull(conn, current[:]); err != nil {
			return nil, safeAdapterError("response")
		}
		header = append(header, current[0])
		copy(tail[:3], tail[1:])
		tail[3] = current[0]
		if tail == [4]byte{'\r', '\n', '\r', '\n'} {
			return bufio.NewReader(io.MultiReader(bytes.NewReader(header), conn)), nil
		}
	}
	return nil, safeAdapterError("response")
}

func minInt64(left, right int64) int {
	if left < right {
		return int(left)
	}
	return int(right)
}

func safeHTTPError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
