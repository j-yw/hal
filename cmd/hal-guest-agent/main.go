package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "hal guest agent failed")
		os.Exit(1)
	}
}

func run() error {
	listener, err := vsock.ListenLinux()
	if err != nil {
		return err
	}
	transport, err := vsock.NewTransport(vsock.Options{Listener: listener})
	if err != nil {
		_ = listener.Close()
		return err
	}
	configuration, err := linuxGuestAgentConfigurationFromLookup(os.LookupEnv)
	if err != nil {
		_ = listener.Close()
		return err
	}
	backend, err := server.NewLinuxBackend(configuration.backend)
	if err != nil {
		_ = listener.Close()
		return err
	}
	isolationVerifier, err := linuxIsolationVerifierForConfiguration(
		context.Background(), configuration, guestnetwork.LoadLinuxBootConfig, guestnetwork.NewLinuxNetworkIsolationVerifier,
	)
	if err != nil {
		_ = listener.Close()
		_ = backend.Close(context.Background())
		return err
	}
	agent, err := server.New(server.Options{
		Transport:                     transport,
		Backend:                       backend,
		IsolationVerifier:             isolationVerifier,
		RequireNetworkProofBeforeWork: configuration.requireNetworkProofBeforeWork,
	})
	if err != nil {
		_ = listener.Close()
		_ = backend.Close(context.Background())
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return agent.Serve(ctx)
}

func linuxBackendOptions() server.LinuxBackendOptions {
	options, _ := linuxBackendOptionsFromLookup(func(string) (string, bool) { return "", false })
	return options
}

func linuxBackendOptionsFromLookup(lookup func(string) (string, bool)) (server.LinuxBackendOptions, error) {
	configuration, err := linuxGuestAgentConfigurationFromLookup(lookup)
	return configuration.backend, err
}

type linuxGuestAgentConfiguration struct {
	backend                       server.LinuxBackendOptions
	requireNetworkProofBeforeWork bool
	proxyURL                      string
}

func linuxGuestAgentConfigurationFromLookup(lookup func(string) (string, bool)) (linuxGuestAgentConfiguration, error) {
	proxyEnvironment, err := validatedL7ProxyEnvironment(lookup)
	if err != nil {
		return linuxGuestAgentConfiguration{}, err
	}
	return linuxGuestAgentConfiguration{
		backend: server.LinuxBackendOptions{
			WorkspaceRoot: "/workspace",
			GuestRoot:     "/workspace",
			BaseEnvironment: append([]string{
				"HOME=/workspace",
				"PATH=/usr/bin:/bin",
				"TMPDIR=/tmp",
			}, proxyEnvironment...),
			ExecutablePaths: []string{"/usr/bin", "/bin"},
		},
		requireNetworkProofBeforeWork: len(proxyEnvironment) != 0,
		proxyURL:                      proxyURLFromEnvironment(proxyEnvironment),
	}, nil
}

func linuxIsolationVerifierForConfiguration(
	ctx context.Context,
	configuration linuxGuestAgentConfiguration,
	loadBoot func(context.Context) (guestnetwork.BootConfig, bool, error),
	newNetworkVerifier func(guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error),
) (server.IsolationVerifier, error) {
	if !configuration.requireNetworkProofBeforeWork {
		return server.NewLinuxIsolationVerifier(server.LinuxIsolationVerifierOptions{})
	}
	if loadBoot == nil || newNetworkVerifier == nil || configuration.proxyURL == "" {
		return nil, errors.New("guest network proof bootstrap is invalid")
	}
	boot, present, err := loadBoot(ctx)
	if err != nil || !present || !boot.Valid() || boot.ProxyURL() != configuration.proxyURL {
		return nil, errors.New("guest network proof bootstrap is invalid")
	}
	networkVerifier, err := newNetworkVerifier(guestnetwork.LinuxNetworkIsolationVerifierOptions{BootConfig: boot})
	if err != nil {
		return nil, errors.New("guest network proof bootstrap is invalid")
	}
	return server.NewLinuxIsolationVerifier(server.LinuxIsolationVerifierOptions{NetworkVerifier: networkVerifier})
}

func proxyURLFromEnvironment(environment []string) string {
	for _, value := range environment {
		if strings.HasPrefix(value, "HTTP_PROXY=") {
			return strings.TrimPrefix(value, "HTTP_PROXY=")
		}
	}
	return ""
}

func validatedL7ProxyEnvironment(lookup func(string) (string, bool)) ([]string, error) {
	if lookup == nil {
		return nil, errors.New("guest proxy bootstrap is invalid")
	}
	httpProxy, hasHTTP := lookup("HTTP_PROXY")
	httpsProxy, hasHTTPS := lookup("HTTPS_PROXY")
	httpProxyLower, hasHTTPLower := lookup("http_proxy")
	httpsProxyLower, hasHTTPSLower := lookup("https_proxy")
	if !hasHTTP && !hasHTTPS && !hasHTTPLower && !hasHTTPSLower {
		return nil, nil
	}
	if !hasHTTP || !hasHTTPS || !hasHTTPLower || !hasHTTPSLower ||
		httpProxy != httpsProxy || httpProxy != httpProxyLower || httpProxy != httpsProxyLower ||
		!validGeneratedProxyURL(httpProxy) {
		return nil, errors.New("guest proxy bootstrap is invalid")
	}
	return []string{
		"HTTP_PROXY=" + httpProxy,
		"HTTPS_PROXY=" + httpsProxy,
		"http_proxy=" + httpProxyLower,
		"https_proxy=" + httpsProxyLower,
	}, nil
}

func validGeneratedProxyURL(value string) bool {
	if value == "" || len(value) > 256 || strings.IndexFunc(value, func(char rune) bool { return char <= ' ' || char == 0x7f }) >= 0 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !host.IsGlobalUnicast() || host.IsPrivate() || host.IsLoopback() || host.IsLinkLocalUnicast() || host.IsMulticast() || host.IsUnspecified() {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	hostText := host.String()
	if host.Is6() {
		hostText = "[" + hostText + "]"
	}
	return value == "http://"+hostText+":"+strconv.Itoa(port)
}
