package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

type fakeCommandNetworkVerifier struct{}

func (fakeCommandNetworkVerifier) VerifyNetworkIsolation(context.Context) (server.NetworkIsolationProofResult, error) {
	return server.NetworkIsolationProofResult{}, nil
}

func TestL7GuestAgentInjectsNetworkVerifierOnlyForMatchingSealedBootState(t *testing.T) {
	configuration := l7GuestAgentConfiguration(t)
	boot := l7GuestBootConfig(t)
	constructed := 0
	verifier, err := linuxIsolationVerifierForConfiguration(
		context.Background(),
		configuration,
		func(context.Context) (guestnetwork.BootConfig, bool, error) { return boot, true, nil },
		func(options server.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error) {
			constructed++
			if options.BootConfig.ProxyURL() != boot.ProxyURL() {
				t.Fatal("network verifier received mismatched boot state")
			}
			return fakeCommandNetworkVerifier{}, nil
		},
	)
	if err != nil || verifier == nil || constructed != 1 {
		t.Fatalf("linuxIsolationVerifierForConfiguration() = %#v, %v; constructed %d", verifier, err, constructed)
	}

	legacy, err := linuxIsolationVerifierForConfiguration(
		context.Background(),
		linuxGuestAgentConfiguration{},
		func(context.Context) (guestnetwork.BootConfig, bool, error) {
			t.Fatal("legacy path read L7 boot state")
			return guestnetwork.BootConfig{}, false, nil
		},
		func(server.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error) {
			t.Fatal("legacy path constructed network verifier")
			return nil, nil
		},
	)
	if err != nil || legacy == nil {
		t.Fatalf("legacy verifier = %#v, %v", legacy, err)
	}
}

func TestL7GuestAgentRejectsMissingMismatchedOrFailedBootStateWithoutEcho(t *testing.T) {
	configuration := l7GuestAgentConfiguration(t)
	mismatched, present, err := guestnetwork.ParseBootCommandLine("hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
		"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.2:18080")
	if err != nil || !present {
		t.Fatal("test boot state is invalid")
	}
	secret := errors.New("/proc/cmdline token=ghp_secret endpoint=10.0.0.8:8080")
	for _, loader := range []func(context.Context) (guestnetwork.BootConfig, bool, error){
		func(context.Context) (guestnetwork.BootConfig, bool, error) {
			return guestnetwork.BootConfig{}, false, nil
		},
		func(context.Context) (guestnetwork.BootConfig, bool, error) { return mismatched, true, nil },
		func(context.Context) (guestnetwork.BootConfig, bool, error) {
			return guestnetwork.BootConfig{}, false, secret
		},
	} {
		_, err := linuxIsolationVerifierForConfiguration(context.Background(), configuration, loader, server.NewLinuxNetworkIsolationVerifier)
		if err == nil {
			t.Fatal("linuxIsolationVerifierForConfiguration() error = nil, want fail closed")
		}
		for _, forbidden := range []string{"/proc/", "ghp_secret", "10.0.0.8", "8080", "198.18.0.2"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("error leaked %q: %v", forbidden, err)
			}
		}
	}
}

func l7GuestAgentConfiguration(t *testing.T) linuxGuestAgentConfiguration {
	t.Helper()
	values := map[string]string{
		"HTTP_PROXY": "http://198.18.0.1:18080", "HTTPS_PROXY": "http://198.18.0.1:18080",
		"http_proxy": "http://198.18.0.1:18080", "https_proxy": "http://198.18.0.1:18080",
	}
	configuration, err := linuxGuestAgentConfigurationFromLookup(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

func l7GuestBootConfig(t *testing.T) guestnetwork.BootConfig {
	t.Helper()
	config, present, err := guestnetwork.ParseBootCommandLine("hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
		"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080")
	if err != nil || !present {
		t.Fatalf("boot config = %#v, %t, %v", config, present, err)
	}
	return config
}
