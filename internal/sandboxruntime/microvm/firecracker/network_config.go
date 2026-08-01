package firecracker

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

const (
	maxL7InterfaceIDBytes = 64
	maxLinuxInterfaceName = 15
	maxL7ProxyURLBytes    = 256
	maxL7BootArgsBytes    = 1024
)

type networkInterfacePayload struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
	GuestMAC    string `json:"guest_mac"`
}

func renderNetworkInterfaces(config BackendConfig) ([]networkInterfacePayload, *StaticNetworkBootConfig, error) {
	mode := config.NetworkMode
	if strings.TrimSpace(string(mode)) == "" {
		mode = microvm.NetworkModeNoLiveNetworking
	}
	switch mode {
	case microvm.NetworkModeNoLiveNetworking:
		if len(config.NetworkInterfaces) != 0 || config.StaticNetwork != nil {
			return nil, nil, newLiveBootRenderConfigError("networkMode", "network configuration requires explicit L7 network mode")
		}
		return nil, nil, nil
	case microvm.NetworkModeL7PolicyProxy:
		if !config.ProductionVsock {
			return nil, nil, newLiveBootRenderConfigError("networkMode", "L7 network mode requires production guest readiness")
		}
		if err := validateL7LaunchDescriptor(config.LaunchDescriptor, config.VerifiedL7Profile, config.VerifiedL7Assets); err != nil {
			return nil, nil, err
		}
		if len(config.NetworkInterfaces) != 1 {
			return nil, nil, newLiveBootRenderConfigError("networkInterfaces", "exactly one network interface is required")
		}
		if config.StaticNetwork == nil {
			return nil, nil, newLiveBootRenderConfigError("staticNetwork", "static guest network configuration is required")
		}
		device, err := normalizeNetworkInterface(config.NetworkInterfaces[0])
		if err != nil {
			return nil, nil, err
		}
		static, err := normalizeStaticNetwork(*config.StaticNetwork)
		if err != nil {
			return nil, nil, err
		}
		return []networkInterfacePayload{device}, &static, nil
	default:
		return nil, nil, newLiveBootRenderConfigError("networkMode", "network mode is unsupported")
	}
}

func normalizeNetworkInterface(input NetworkInterfaceConfig) (networkInterfacePayload, error) {
	interfaceID := strings.TrimSpace(input.InterfaceID)
	if !safeNetworkToken(interfaceID, maxL7InterfaceIDBytes) {
		return networkInterfacePayload{}, newLiveBootRenderConfigError("networkInterfaces.interfaceId", "network interface id is invalid")
	}
	hostDeviceName := strings.TrimSpace(input.HostDeviceName)
	if !safeNetworkToken(hostDeviceName, maxLinuxInterfaceName) {
		return networkInterfacePayload{}, newLiveBootRenderConfigError("networkInterfaces.hostDeviceName", "host network device name is invalid")
	}
	guestMAC, ok := normalizeLocalUnicastMAC(input.GuestMAC)
	if !ok {
		return networkInterfacePayload{}, newLiveBootRenderConfigError("networkInterfaces.guestMac", "guest MAC is invalid")
	}
	return networkInterfacePayload{
		IfaceID:     interfaceID,
		HostDevName: hostDeviceName,
		GuestMAC:    guestMAC,
	}, nil
}

func normalizeStaticNetwork(input StaticNetworkBootConfig) (StaticNetworkBootConfig, error) {
	guestInterface := strings.TrimSpace(input.GuestInterfaceName)
	if !safeNetworkToken(guestInterface, maxLinuxInterfaceName) {
		return StaticNetworkBootConfig{}, newLiveBootRenderConfigError("staticNetwork.guestInterfaceName", "guest network interface name is invalid")
	}
	ipv4Prefix, ipv4Gateway, err := normalizeAddressPair(input.IPv4Address, input.IPv4Gateway, false)
	if err != nil {
		return StaticNetworkBootConfig{}, newLiveBootRenderConfigError("staticNetwork.ipv4", "static IPv4 configuration is invalid")
	}
	ipv6Prefix, ipv6Gateway, err := normalizeAddressPair(input.IPv6Address, input.IPv6Gateway, true)
	if err != nil {
		return StaticNetworkBootConfig{}, newLiveBootRenderConfigError("staticNetwork.ipv6", "static IPv6 configuration is invalid")
	}
	proxyURL, err := normalizeProxyURL(input.ProxyURL)
	if err != nil {
		return StaticNetworkBootConfig{}, newLiveBootRenderConfigError("staticNetwork.proxy", "proxy bootstrap is invalid")
	}
	return StaticNetworkBootConfig{
		GuestInterfaceName: guestInterface,
		IPv4Address:        ipv4Prefix.String(),
		IPv4Gateway:        ipv4Gateway.String(),
		IPv6Address:        ipv6Prefix.String(),
		IPv6Gateway:        ipv6Gateway.String(),
		ProxyURL:           proxyURL,
	}, nil
}

func normalizeAddressPair(address, gateway string, ipv6 bool) (netip.Prefix, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(address))
	wantBits := 30
	if ipv6 {
		wantBits = 126
	}
	if err != nil || prefix.Bits() != wantBits || prefix.Addr().Is6() != ipv6 || !usableStaticAddress(prefix.Addr()) {
		return netip.Prefix{}, netip.Addr{}, errInvalidStaticNetwork
	}
	prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits())
	parsedGateway, err := netip.ParseAddr(strings.TrimSpace(gateway))
	if err != nil || parsedGateway.Is6() != ipv6 || !usableStaticAddress(parsedGateway) || !prefix.Contains(parsedGateway) || parsedGateway == prefix.Addr() {
		return netip.Prefix{}, netip.Addr{}, errInvalidStaticNetwork
	}
	network := prefix.Masked().Addr()
	if prefix.Addr() == network || parsedGateway == network {
		return netip.Prefix{}, netip.Addr{}, errInvalidStaticNetwork
	}
	if !ipv6 && (unusableIPv4PointToPointAddress(prefix, prefix.Addr()) || unusableIPv4PointToPointAddress(prefix, parsedGateway)) {
		return netip.Prefix{}, netip.Addr{}, errInvalidStaticNetwork
	}
	return prefix, parsedGateway, nil
}

func unusableIPv4PointToPointAddress(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() {
		return true
	}
	network := prefix.Masked().Addr()
	bytes := network.As4()
	bytes[3] |= byte((1 << uint(32-prefix.Bits())) - 1)
	broadcast := netip.AddrFrom4(bytes)
	return address == network || address == broadcast
}

func validateL7LaunchDescriptor(
	descriptor *assets.LaunchDescriptor,
	profile *localresolver.VerifiedL7Profile,
	lease *localresolver.VerifiedL7AssetLease,
) error {
	launchAssets, err := firecrackerLaunchDescriptorAssets(descriptor, liveBootRenderOperation)
	if err != nil {
		return err
	}
	if descriptor == nil ||
		launchAssets.Descriptor.ID != assets.SafeID("l7-network-image") ||
		!equalSafeLabels(launchAssets.Descriptor.Labels, []assets.SafeLabel{"firecracker", "reproducible", "network-profile"}) ||
		launchAssets.HasInitrd ||
		launchAssets.Kernel.ID != assets.SafeID("kernel") ||
		launchAssets.Rootfs.ID != assets.SafeID("rootfs") ||
		!localresolver.VerifiedL7ProfileMatches(profile, &launchAssets.Descriptor) {
		return newLiveBootRenderConfigError("launchDescriptor", "verified L7 network image profile is required")
	}
	if lease == nil || lease.ConfirmCurrent(&launchAssets.Descriptor) != nil {
		return newLiveBootRenderConfigError("launchDescriptor", "current verified L7 network image assets are required")
	}
	return nil
}

func equalSafeLabels(left, right []assets.SafeLabel) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func usableStaticAddress(address netip.Addr) bool {
	return address.IsValid() &&
		address.IsGlobalUnicast() &&
		!address.IsLoopback() &&
		!address.IsLinkLocalUnicast() &&
		!address.IsMulticast() &&
		!address.IsUnspecified()
}

func normalizeProxyURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxL7ProxyURLBytes || strings.IndexFunc(value, invalidBootValueRune) >= 0 {
		return "", errInvalidStaticNetwork
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errInvalidStaticNetwork
	}
	host, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !usableProxyAddress(host) {
		return "", errInvalidStaticNetwork
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errInvalidStaticNetwork
	}
	hostText := host.String()
	if host.Is6() {
		hostText = "[" + hostText + "]"
	}
	canonical := "http://" + hostText + ":" + strconv.Itoa(port)
	if value != canonical {
		return "", errInvalidStaticNetwork
	}
	return canonical, nil
}

func usableProxyAddress(address netip.Addr) bool {
	return usableStaticAddress(address) && !address.IsPrivate()
}

func l7ProductionBootArgs(static StaticNetworkBootConfig) (string, error) {
	args := fmt.Sprintf(
		"%s hal_l7_net_if=%s hal_l7_ipv4=%s hal_l7_ipv4_gateway=%s hal_l7_ipv6=%s hal_l7_ipv6_gateway=%s hal_l7_proxy=%s",
		l5ProductionBootArgs,
		static.GuestInterfaceName,
		static.IPv4Address,
		static.IPv4Gateway,
		static.IPv6Address,
		static.IPv6Gateway,
		static.ProxyURL,
	)
	if len(args) > maxL7BootArgsBytes {
		return "", newLiveBootRenderConfigError("staticNetwork", "static guest network boot parameters exceed the limit")
	}
	return args, nil
}

func safeNetworkToken(value string, limit int) bool {
	if value == "" || value == "." || value == ".." || len(value) > limit {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '_', char == '-', char == '.':
		default:
			return false
		}
	}
	return true
}

func normalizeLocalUnicastMAC(value string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 6 {
		return "", false
	}
	bytes := make([]byte, len(parts))
	for index, part := range parts {
		if len(part) != 2 {
			return "", false
		}
		parsed, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return "", false
		}
		bytes[index] = byte(parsed)
	}
	if bytes[0]&1 != 0 || bytes[0]&2 == 0 {
		return "", false
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]), true
}

func invalidBootValueRune(char rune) bool {
	return char <= ' ' || char == 0x7f
}

type staticNetworkError struct{}

func (staticNetworkError) Error() string { return "static network configuration is invalid" }

var errInvalidStaticNetwork error = staticNetworkError{}
