package l7profile

import "testing"

func TestL7ImageProfileLocksNetworkDenialProbeApplets(t *testing.T) {
	fragment := readProfileFile(t, "busybox.fragment")
	for _, required := range []string{
		"CONFIG_FEATURE_IPV6=y",
		"CONFIG_PING=y",
		"CONFIG_PING6=y",
		"CONFIG_NSLOOKUP=y",
		"CONFIG_NC=y",
		"CONFIG_NC_EXTRA=y",
	} {
		if !linePresent(fragment, required) {
			t.Errorf("busybox.fragment missing %q", required)
		}
	}
}
