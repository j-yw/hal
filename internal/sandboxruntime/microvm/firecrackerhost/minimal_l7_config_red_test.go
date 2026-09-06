//go:build linux

package firecrackerhost

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

func TestMinimalL7ConfigAcceptsExactSelectedDescriptor(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:43123", "[::1]:43123"} {
		t.Run(endpoint, func(t *testing.T) {
			expectation := minimalL7ConfigTestExpectation(t, endpoint)
			request := validStrictJailerCoordinatorRequest(t)
			request.minimalL7 = expectation
			replaceCoordinatorConfig(t, &request, minimalL7ConfigTestJSON(t, expectation, true))
			if err := validateStrictJailerCoordinatorConfig(request); err != nil {
				t.Fatalf("exact selected L7 descriptor config rejected: %v", err)
			}
		})
	}
}

func TestMinimalL7ConfigRequiresSelectedNetworkInterface(t *testing.T) {
	expectation := minimalL7ConfigTestExpectation(t, "127.0.0.1:43123")
	request := validStrictJailerCoordinatorRequest(t)
	request.minimalL7 = expectation
	replaceCoordinatorConfig(t, &request, minimalL7ConfigTestJSON(t, expectation, false))
	if err := validateStrictJailerCoordinatorConfig(request); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
		t.Fatalf("selected L7 config without network interface = %v, want invalid config", err)
	}
}

func TestMinimalL7ConfigUnselectedBehaviorRemainsClosed(t *testing.T) {
	expectation := minimalL7ConfigTestExpectation(t, "127.0.0.1:43123")
	for name, config := range map[string]string{
		"descriptor interface": minimalL7ConfigTestJSON(t, expectation, true),
		"null interface":       coordinatorConfigWith(`"network-interfaces":null`),
		"empty interface":      coordinatorConfigWith(`"network-interfaces":[]`),
	} {
		t.Run(name, func(t *testing.T) {
			request := validStrictJailerCoordinatorRequest(t)
			replaceCoordinatorConfig(t, &request, config)
			if err := validateStrictJailerCoordinatorConfig(request); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
				t.Fatalf("unselected config = %v, want unchanged rejection", err)
			}
		})
	}
	if err := validateStrictJailerCoordinatorConfig(validStrictJailerCoordinatorRequest(t)); err != nil {
		t.Fatalf("legacy config without selected expectation changed: %v", err)
	}
}

// This constructs candidate JSON from an actually issued descriptor, not from
// an arbitrary TAP label. It is deliberately separate from the future mapper.
// It tests only the existing config validator, not minimal bootstrap rendering.
func minimalL7ConfigTestJSON(t *testing.T, expected *minimalL7ConfigExpectation, includeNIC bool) string {
	t.Helper()
	iface, tap, mac, ok := expected.descriptor.NetworkInterface()
	if !ok || iface != "net1" {
		t.Fatal("prepared descriptor did not supply the fixed interface")
	}
	guest, ipv4, gateway4, ipv6, gateway6, proxy, ok := expected.descriptor.StaticNetwork()
	if !ok || guest != "eth0" {
		t.Fatal("prepared descriptor did not supply the fixed guest interface")
	}
	boot := "console=ttyS0 hal_l7_net_if=" + guest + " hal_l7_ipv4=" + ipv4 +
		" hal_l7_ipv4_gateway=" + gateway4 + " hal_l7_ipv6=" + ipv6 +
		" hal_l7_ipv6_gateway=" + gateway6 + " hal_l7_proxy=" + proxy
	parsed, present, err := guestnetwork.ParseBootCommandLine(boot)
	if err != nil || !present || parsed.ProxyURL() != proxy {
		t.Fatalf("descriptor-generated L7 boot fields rejected: present=%t err=%v", present, err)
	}
	bootJSON, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	config := strings.Replace(validCoordinatorConfig(), `"kernel_image_path":"/boot/vmlinux"`,
		`"kernel_image_path":"/boot/vmlinux","boot_args":`+string(bootJSON), 1)
	if includeNIC {
		nic, err := json.Marshal([]map[string]string{{"iface_id": iface, "host_dev_name": tap, "guest_mac": mac}})
		if err != nil {
			t.Fatal(err)
		}
		config = strings.TrimSuffix(config, "}") + `,"network-interfaces":` + string(nic) + "}"
	}
	return config
}
