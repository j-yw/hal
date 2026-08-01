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
	backendOptions, err := linuxBackendOptionsFromLookup(os.LookupEnv)
	if err != nil {
		_ = listener.Close()
		return err
	}
	backend, err := server.NewLinuxBackend(backendOptions)
	if err != nil {
		_ = listener.Close()
		return err
	}
	isolationVerifier, err := server.NewLinuxIsolationVerifier(server.LinuxIsolationVerifierOptions{})
	if err != nil {
		_ = listener.Close()
		_ = backend.Close(context.Background())
		return err
	}
	agent, err := server.New(server.Options{
		Transport:                       transport,
		Backend:                         backend,
		IsolationVerifier:               isolationVerifier,
		RequireIsolationProofBeforeWork: len(backendOptions.BaseEnvironment) > 3,
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
	proxyEnvironment, err := validatedL7ProxyEnvironment(lookup)
	if err != nil {
		return server.LinuxBackendOptions{}, err
	}
	return server.LinuxBackendOptions{
		WorkspaceRoot: "/workspace",
		GuestRoot:     "/workspace",
		BaseEnvironment: append([]string{
			"HOME=/workspace",
			"PATH=/usr/bin:/bin",
			"TMPDIR=/tmp",
		}, proxyEnvironment...),
		ExecutablePaths: []string{"/usr/bin", "/bin"},
	}, nil
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
