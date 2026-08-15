package main

import "testing"

func TestL7GuestAgentProjectsUpperAndLowercaseProxyEnvironmentOnly(t *testing.T) {
	values := map[string]string{
		"HTTP_PROXY":  "http://198.18.0.1:18080",
		"HTTPS_PROXY": "http://198.18.0.1:18080",
		"http_proxy":  "http://198.18.0.1:18080",
		"https_proxy": "http://198.18.0.1:18080",
		"NO_PROXY":    "sensitive-bypass.example",
		"no_proxy":    "sensitive-bypass.example",
	}
	options, err := linuxBackendOptionsFromLookup(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatalf("linuxBackendOptionsFromLookup() error = %v", err)
	}
	want := map[string]bool{
		"HTTP_PROXY=http://198.18.0.1:18080":  false,
		"HTTPS_PROXY=http://198.18.0.1:18080": false,
		"http_proxy=http://198.18.0.1:18080":  false,
		"https_proxy=http://198.18.0.1:18080": false,
	}
	for _, entry := range options.BaseEnvironment {
		if _, ok := want[entry]; ok {
			want[entry] = true
		}
		if entry == "NO_PROXY=sensitive-bypass.example" || entry == "no_proxy=sensitive-bypass.example" {
			t.Fatalf("BaseEnvironment forwarded bypass variable %q", entry)
		}
	}
	for entry, found := range want {
		if !found {
			t.Errorf("BaseEnvironment missing %q: %#v", entry, options.BaseEnvironment)
		}
	}
}
