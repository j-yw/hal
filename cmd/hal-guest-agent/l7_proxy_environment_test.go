package main

import (
	"strings"
	"testing"
)

func TestL7GuestAgentAddsOnlyValidatedGeneratedProxyEnvironment(t *testing.T) {
	values := map[string]string{
		"HTTP_PROXY":  "http://192.0.2.1:18080",
		"HTTPS_PROXY": "http://192.0.2.1:18080",
		"http_proxy":  "http://192.0.2.1:18080",
		"https_proxy": "http://192.0.2.1:18080",
	}
	options, err := linuxBackendOptionsFromLookup(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatalf("linuxBackendOptionsFromLookup() error = %v", err)
	}
	for _, want := range []string{
		"HTTP_PROXY=http://192.0.2.1:18080",
		"HTTPS_PROXY=http://192.0.2.1:18080",
		"http_proxy=http://192.0.2.1:18080",
		"https_proxy=http://192.0.2.1:18080",
	} {
		found := false
		for _, value := range options.BaseEnvironment {
			found = found || value == want
		}
		if !found {
			t.Fatalf("BaseEnvironment missing %q: %#v", want, options.BaseEnvironment)
		}
	}
}

func TestL7GuestAgentRejectsPartialOrUnsafeProxyEnvironmentWithoutEcho(t *testing.T) {
	for _, values := range []map[string]string{
		{"HTTP_PROXY": "http://192.0.2.1:18080"},
		{
			"HTTP_PROXY": "http://192.0.2.1:18080", "HTTPS_PROXY": "http://203.0.113.8:19443",
			"http_proxy": "http://192.0.2.1:18080", "https_proxy": "http://203.0.113.8:19443",
		},
		{
			"HTTP_PROXY": "http://user:secret@192.0.2.1:18080", "HTTPS_PROXY": "http://user:secret@192.0.2.1:18080",
			"http_proxy": "http://user:secret@192.0.2.1:18080", "https_proxy": "http://user:secret@192.0.2.1:18080",
		},
		{
			"HTTP_PROXY": "http://10.0.0.8:18080", "HTTPS_PROXY": "http://10.0.0.8:18080",
			"http_proxy": "http://10.0.0.8:18080", "https_proxy": "http://10.0.0.8:18080",
		},
	} {
		_, err := linuxBackendOptionsFromLookup(func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		})
		if err == nil {
			t.Fatalf("linuxBackendOptionsFromLookup(%#v) error = nil, want fail closed", values)
		}
		for _, forbidden := range []string{"192.0.2", "203.0.113", "10.0.0.8", "18080", "19443", "secret"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("error leaked %q in %q", forbidden, err)
			}
		}
	}
}

func TestL7GuestAgentUsesExplicitValidatedNetworkProofIntent(t *testing.T) {
	valid := map[string]string{
		"HTTP_PROXY":  "http://192.0.2.1:18080",
		"HTTPS_PROXY": "http://192.0.2.1:18080",
		"http_proxy":  "http://192.0.2.1:18080",
		"https_proxy": "http://192.0.2.1:18080",
	}
	configuration, err := linuxGuestAgentConfigurationFromLookup(func(name string) (string, bool) {
		value, ok := valid[name]
		return value, ok
	})
	if err != nil {
		t.Fatalf("linuxGuestAgentConfigurationFromLookup() error = %v", err)
	}
	if !configuration.requireNetworkProofBeforeWork {
		t.Fatal("validated L7 proxy bootstrap did not require network proof")
	}

	legacy, err := linuxGuestAgentConfigurationFromLookup(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("legacy linuxGuestAgentConfigurationFromLookup() error = %v", err)
	}
	if legacy.requireNetworkProofBeforeWork {
		t.Fatal("legacy guest configuration unexpectedly required network proof")
	}
}
