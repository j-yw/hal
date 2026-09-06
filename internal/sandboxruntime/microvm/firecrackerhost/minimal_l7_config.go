package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

// minimalL7ConfigExpectation is a private schema/mapping input, not live
// enforcement authority. The descriptor must come from the retained session
// selected using its full expected identity; its two expected generations must
// come independently from that selection, never from candidate config JSON.
type minimalL7ConfigExpectation struct {
	descriptor         l7network.LaunchDescriptor
	runtimeGeneration  string
	topologyGeneration string
}

type minimalL7NetworkInterface struct {
	InterfaceID    string `json:"iface_id"`
	HostDeviceName string `json:"host_dev_name"`
	GuestMAC       string `json:"guest_mac"`
}

var minimalL7BootKeys = [...]string{
	"hal_l7_net_if", "hal_l7_ipv4", "hal_l7_ipv4_gateway",
	"hal_l7_ipv6", "hal_l7_ipv6_gateway", "hal_l7_proxy",
}

// renderMinimalL7Config returns one exact interface and a boot base to pass to
// minimalcontrol.RenderBootCommandLine before config sealing. Neither output
// establishes current session ownership, guest readiness or enforcement.
func renderMinimalL7Config(base string, expected *minimalL7ConfigExpectation) (minimalL7NetworkInterface, string, error) {
	nic, values, err := minimalL7Mapping(expected)
	if err != nil {
		return minimalL7NetworkInterface{}, "", err
	}
	existing, err := minimalL7BootFields(base)
	if err != nil || existing != ([6]string{}) {
		return minimalL7NetworkInterface{}, "", invalidMinimalL7Config()
	}
	if base != "" {
		base += " "
	}
	base += minimalL7BootFragment(values)
	if len(base)+1 > minimalcontrol.MaximumBootCommandLineBytes {
		return minimalL7NetworkInterface{}, "", invalidMinimalL7Config()
	}
	return nic, base, nil
}

func validateMinimalL7Config(config strictJailerConfigFile, expected *minimalL7ConfigExpectation) error {
	if expected == nil {
		if len(config.NetworkInterfaces) != 0 {
			return invalidMinimalL7Config()
		}
		return nil
	}
	nic, values, err := minimalL7Mapping(expected)
	if err != nil || len(config.NetworkInterfaces) == 0 {
		return invalidMinimalL7Config()
	}
	decoder := json.NewDecoder(bytes.NewReader(config.NetworkInterfaces))
	decoder.DisallowUnknownFields()
	var interfaces []minimalL7NetworkInterface
	if decoder.Decode(&interfaces) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF ||
		len(interfaces) != 1 || interfaces[0] != nic {
		return invalidMinimalL7Config()
	}
	actual, err := minimalL7BootFields(config.BootSource.BootArgs)
	if err != nil || actual != values {
		return invalidMinimalL7Config()
	}
	return nil
}

func minimalL7Mapping(expected *minimalL7ConfigExpectation) (minimalL7NetworkInterface, [6]string, error) {
	invalid := func() (minimalL7NetworkInterface, [6]string, error) {
		return minimalL7NetworkInterface{}, [6]string{}, invalidMinimalL7Config()
	}
	if expected == nil {
		return invalid()
	}
	topology, runtime, ok := expected.descriptor.ProofGenerations()
	if !ok || topology != expected.topologyGeneration || runtime != expected.runtimeGeneration {
		return invalid()
	}
	iface, tap, mac, ok := expected.descriptor.NetworkInterface()
	if !ok || iface != "net1" {
		return invalid()
	}
	guest, ipv4, gateway4, ipv6, gateway6, proxy, ok := expected.descriptor.StaticNetwork()
	if !ok || guest != "eth0" {
		return invalid()
	}
	values := [6]string{guest, ipv4, gateway4, ipv6, gateway6, proxy}
	boot, present, err := guestnetwork.ParseBootCommandLine(minimalL7BootFragment(values))
	if err != nil || !present || ([6]string{boot.InterfaceName(), boot.IPv4Address(), boot.IPv4Gateway(),
		boot.IPv6Address(), boot.IPv6Gateway(), boot.ProxyURL()}) != values {
		return invalid()
	}
	return minimalL7NetworkInterface{InterfaceID: iface, HostDeviceName: tap, GuestMAC: mac}, values, nil
}

func minimalL7BootFragment(values [6]string) string {
	fields := make([]string, len(minimalL7BootKeys))
	for index, key := range minimalL7BootKeys {
		fields[index] = key + "=" + values[index]
	}
	return strings.Join(fields, " ")
}

// This scan supplements the guest value parser: aliases that it treats as
// unrelated tokens must not turn malformed selected settings into absence.
// Keep raw values for exact comparison before any parser normalization.
func minimalL7BootFields(line string) ([6]string, error) {
	var values [6]string
	if len(line)+1 > minimalcontrol.MaximumBootCommandLineBytes {
		return values, invalidMinimalL7Config()
	}
	for _, ch := range line {
		if ch < ' ' && ch != '\t' || ch == 0x7f {
			return values, invalidMinimalL7Config()
		}
	}
	for _, field := range strings.Fields(line) {
		key, value, assigned := strings.Cut(field, "=")
		probe := strings.ToLower(strings.Trim(key, "\"'"))
		if probe != "hal_l7" && !strings.HasPrefix(probe, "hal_l7_") {
			continue
		}
		if key != probe || !assigned || value == "" {
			return values, invalidMinimalL7Config()
		}
		found := false
		for index, allowed := range minimalL7BootKeys {
			if key == allowed {
				if values[index] != "" {
					return values, invalidMinimalL7Config()
				}
				values[index], found = value, true
				break
			}
		}
		if !found {
			return values, invalidMinimalL7Config()
		}
	}
	return values, nil
}

func invalidMinimalL7Config() error {
	return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
}
