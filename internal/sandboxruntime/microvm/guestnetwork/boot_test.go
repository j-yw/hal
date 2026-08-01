package guestnetwork

import (
	"strings"
	"testing"
)

const validBootCommandLine = "console=ttyS0 hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
	"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080"

func TestParseBootCommandLineReturnsCanonicalSealedExpectation(t *testing.T) {
	config, present, err := ParseBootCommandLine(validBootCommandLine)
	if err != nil || !present {
		t.Fatalf("ParseBootCommandLine() = %#v, %t, %v", config, present, err)
	}
	if config.InterfaceName() != "eth0" || config.IPv4Address() != "192.0.2.2/30" ||
		config.IPv4Gateway() != "192.0.2.1" || config.IPv6Address() != "fd00:7::2/126" ||
		config.IPv6Gateway() != "fd00:7::1" || config.ProxyURL() != "http://198.18.0.1:18080" {
		t.Fatalf("unexpected canonical boot expectation: %#v", config)
	}
}

func TestParseBootCommandLineFailsClosedOnPartialDuplicateOrNonPointToPointInput(t *testing.T) {
	for _, commandLine := range []string{
		"hal_l7_net_if=eth0",
		validBootCommandLine + " hal_l7_net_if=eth0",
		strings.Replace(validBootCommandLine, "192.0.2.2/30", "192.0.2.2/24", 1),
		strings.Replace(validBootCommandLine, "fd00:7::2/126", "fd00:7::2/64", 1),
		strings.Replace(validBootCommandLine, "hal_l7_ipv4=192.0.2.2/30", "hal_l7_ipv4=192.0.2.0/30", 1),
		strings.Replace(validBootCommandLine, "hal_l7_ipv6=fd00:7::2/126", "hal_l7_ipv6=fd00:7::/126", 1),
	} {
		_, present, err := ParseBootCommandLine(commandLine)
		if err == nil || !present {
			t.Fatalf("ParseBootCommandLine(%q) = present %t, error %v, want fail closed", commandLine, present, err)
		}
		for _, forbidden := range []string{"192.0.2", "fd00:7", "18080"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("error leaked %q: %v", forbidden, err)
			}
		}
	}
}
