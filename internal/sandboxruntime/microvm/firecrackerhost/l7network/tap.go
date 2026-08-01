package l7network

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultTAPOutputLimit int64 = 64 << 10
	maxTAPOutputLimit     int64 = 1 << 20
	maxTAPIfIndex               = 1<<31 - 1
)

type NamespaceCommandRequest struct {
	Path string   `json:"-"`
	Args []string `json:"-"`
}

// NamespaceCommandBoundary is the only injected command boundary used by the
// TAP implementation. Namespace entry is descriptor-bound; request values are
// private and never included in returned errors.
type NamespaceCommandBoundary interface {
	Run(context.Context, NamespaceLease, NamespaceCommandRequest, int64) ([]byte, error)
}

type TAPOptions struct {
	IPPath         string
	SysctlPath     string
	NsenterPath    string
	Command        NamespaceCommandBoundary
	OutputLimit    int64
	CleanupTimeout time.Duration
}

type LinuxTAP struct {
	options     TAPOptions
	unsupported bool
}

func NewLinuxTAP(input TAPOptions) (*LinuxTAP, error) {
	options := input
	if options.OutputLimit == 0 {
		options.OutputLimit = defaultTAPOutputLimit
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = defaultCleanupTimeout
	}
	if !validToolPath(options.IPPath) || !validToolPath(options.SysctlPath) || !validToolPath(options.NsenterPath) ||
		options.OutputLimit <= 0 || options.OutputLimit > maxTAPOutputLimit || options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	tap := &LinuxTAP{options: options, unsupported: !tapPlatformSupported()}
	if options.Command == nil {
		command, supported := newPlatformNamespaceCommand(options.NsenterPath)
		tap.options.Command = command
		tap.unsupported = tap.unsupported || !supported
	}
	return tap, nil
}

func (t *LinuxTAP) CreateConfigure(ctx context.Context, namespace NamespaceLease, spec tapSpec) (tapState, error) {
	if !t.valid(namespace, spec) {
		return tapState{}, ErrTopologyPrepareFailed
	}
	state := tapState{name: spec.name, generation: spec.generation, fingerprint: spec.fingerprint()}
	created := false
	fail := func() (tapState, error) {
		if created {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), t.options.CleanupTimeout)
			_, _ = t.run(cleanupCtx, namespace, t.options.IPPath, "link", "delete", "dev", spec.name)
			cancel()
		}
		return tapState{}, ErrTopologyPrepareFailed
	}
	commands := [][]string{
		{"tuntap", "add", "dev", spec.name, "mode", "tap"},
		{"link", "set", "dev", spec.name, "address", spec.mac},
		{"link", "set", "dev", spec.name, "addrgenmode", "none"},
		{"link", "set", "dev", spec.name, "up"},
		{"address", "add", spec.gatewayIPv4.String() + "/" + bits(spec.guestIPv4Prefix), "dev", spec.name, "noprefixroute"},
		{"-6", "address", "add", spec.gatewayIPv6.String() + "/" + bits(spec.guestIPv6Prefix), "dev", spec.name, "nodad", "noprefixroute"},
		{"route", "add", spec.guestIPv4Prefix.Addr().String() + "/32", "dev", spec.name, "src", spec.gatewayIPv4.String()},
		{"-6", "route", "add", spec.guestIPv6Prefix.Addr().String() + "/128", "dev", spec.name, "src", spec.gatewayIPv6.String()},
	}
	for index, args := range commands {
		if _, err := t.run(ctx, namespace, t.options.IPPath, args...); err != nil {
			return fail()
		}
		if index == 0 {
			created = true
			payload, inspectErr := t.run(ctx, namespace, t.options.IPPath, "-d", "-j", "link", "show", "dev", spec.name)
			ifIndex, inspected := inspectTAPKernelIdentity(payload, spec.name)
			if inspectErr != nil || !inspected {
				return fail()
			}
			state.ifIndex = ifIndex
		}
	}
	for _, setting := range []string{"net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"} {
		if _, err := t.run(ctx, namespace, t.options.SysctlPath, "-w", setting); err != nil {
			return fail()
		}
	}
	if err := t.Inspect(ctx, namespace, state, spec); err != nil {
		return fail()
	}
	return state, nil
}

func (t *LinuxTAP) Inspect(ctx context.Context, namespace NamespaceLease, state tapState, spec tapSpec) error {
	if !t.valid(namespace, spec) || !state.valid(spec) {
		return ErrProofMismatch
	}
	link, err := t.run(ctx, namespace, t.options.IPPath, "-d", "-j", "link", "show", "dev", spec.name)
	if err != nil || !inspectTAPLink(link, state, spec) {
		return ErrProofMismatch
	}
	addresses, err := t.run(ctx, namespace, t.options.IPPath, "-j", "address", "show", "dev", spec.name)
	if err != nil || !inspectTAPAddresses(addresses, spec) {
		return ErrProofMismatch
	}
	for _, family := range []struct {
		flag, destination, preferredSource string
	}{{"-4", spec.guestIPv4Prefix.Addr().String() + "/32", spec.gatewayIPv4.String()},
		{"-6", spec.guestIPv6Prefix.Addr().String() + "/128", spec.gatewayIPv6.String()}} {
		routes, routeErr := t.run(ctx, namespace, t.options.IPPath, "-j", family.flag, "route", "show", "dev", spec.name)
		if routeErr != nil || !inspectTAPRoutes(routes, spec.name, family.destination, family.preferredSource) {
			return ErrProofMismatch
		}
	}
	for _, setting := range []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"} {
		output, settingErr := t.run(ctx, namespace, t.options.SysctlPath, "-n", setting)
		if settingErr != nil || strings.TrimSpace(string(output)) != "1" {
			return ErrProofMismatch
		}
	}
	return nil
}

func (t *LinuxTAP) Delete(ctx context.Context, namespace NamespaceLease, state tapState, spec tapSpec) error {
	if !t.valid(namespace, spec) || !state.valid(spec) {
		return ErrProofMismatch
	}
	if err := t.Inspect(ctx, namespace, state, spec); err != nil {
		return ErrProofMismatch
	}
	if _, err := t.run(ctx, namespace, t.options.IPPath, "link", "delete", "dev", spec.name); err != nil {
		return ErrCleanupIncomplete
	}
	output, err := t.run(ctx, namespace, t.options.IPPath, "-j", "link", "show")
	if err != nil || !inspectTAPAbsent(output, spec.name) {
		return ErrCleanupIncomplete
	}
	return nil
}

func (t *LinuxTAP) valid(namespace NamespaceLease, spec tapSpec) bool {
	return t != nil && !t.unsupported && t.options.Command != nil && namespace != nil && validInterfaceName(spec.name) &&
		spec.generation != "" && spec.mappingInterface == mappingInterfaceName && spec.proxyAddress.IsValid() && spec.proxyPort != 0 &&
		spec.guestIPv4Prefix.IsValid() && spec.guestIPv4Prefix.Bits() == 30 && spec.guestIPv4Prefix.Addr().Is4() &&
		spec.guestIPv6Prefix.IsValid() && spec.guestIPv6Prefix.Bits() == 126 && spec.guestIPv6Prefix.Addr().Is6() &&
		spec.gatewayIPv4.Is4() && spec.gatewayIPv6.Is6() && spec.gatewayIPv4 != spec.guestIPv4Prefix.Masked().Addr() &&
		spec.gatewayIPv6 != spec.guestIPv6Prefix.Masked().Addr() && spec.gatewayIPv4 != spec.guestIPv4Prefix.Addr() &&
		spec.gatewayIPv6 != spec.guestIPv6Prefix.Addr() && spec.guestIPv4Prefix.Contains(spec.gatewayIPv4) &&
		spec.guestIPv6Prefix.Contains(spec.gatewayIPv6)
}

func (t *LinuxTAP) run(ctx context.Context, namespace NamespaceLease, path string, args ...string) ([]byte, error) {
	output, err := t.options.Command.Run(ctx, namespace, NamespaceCommandRequest{Path: path, Args: append([]string(nil), args...)}, t.options.OutputLimit)
	if err != nil || int64(len(output)) > t.options.OutputLimit {
		return nil, ErrTopologyPrepareFailed
	}
	return output, nil
}

type tapLinkInspection struct {
	Index    int      `json:"ifindex"`
	Name     string   `json:"ifname"`
	Address  string   `json:"address"`
	Flags    []string `json:"flags"`
	LinkType string   `json:"link_type"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
		Data struct {
			Type string `json:"type"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func inspectTAPKernelIdentity(payload []byte, name string) (int, bool) {
	var links []tapLinkInspection
	if json.Unmarshal(payload, &links) != nil || len(links) != 1 {
		return 0, false
	}
	link := links[0]
	return link.Index, link.Index > 0 && link.Index <= maxTAPIfIndex && link.Name == name &&
		link.LinkType == "ether" && link.LinkInfo.Kind == "tun" && link.LinkInfo.Data.Type == "tap"
}

func inspectTAPLink(payload []byte, state tapState, spec tapSpec) bool {
	var links []tapLinkInspection
	if json.Unmarshal(payload, &links) != nil || len(links) != 1 {
		return false
	}
	link := links[0]
	if index, ok := inspectTAPKernelIdentity(payload, spec.name); !ok || index != state.ifIndex ||
		!strings.EqualFold(link.Address, spec.mac) {
		return false
	}
	for _, flag := range link.Flags {
		if flag == "UP" {
			return true
		}
	}
	return false
}

func inspectTAPAddresses(payload []byte, spec tapSpec) bool {
	var links []struct {
		Name string `json:"ifname"`
		Info []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(payload, &links) != nil || len(links) != 1 || links[0].Name != spec.name {
		return false
	}
	if len(links[0].Info) != 2 {
		return false
	}
	want4, want6 := false, false
	for _, info := range links[0].Info {
		address, err := netip.ParseAddr(info.Local)
		if err != nil {
			return false
		}
		switch {
		case info.Family == "inet" && address == spec.gatewayIPv4 && info.PrefixLen == 30:
			want4 = true
		case info.Family == "inet6" && address == spec.gatewayIPv6 && info.PrefixLen == 126:
			want6 = true
		default:
			return false
		}
	}
	return want4 && want6
}

func inspectTAPRoutes(payload []byte, name, destination, preferredSource string) bool {
	var routes []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
		Gateway     string `json:"gateway"`
		Preferred   string `json:"prefsrc"`
		Type        string `json:"type"`
	}
	if json.Unmarshal(payload, &routes) != nil || len(routes) != 1 {
		return false
	}
	route := routes[0]
	if route.Device != name || route.Gateway != "" || route.Destination != destination || route.Preferred != preferredSource ||
		(route.Type != "" && route.Type != "unicast") {
		return false
	}
	return true
}

func inspectTAPAbsent(payload []byte, name string) bool {
	var links []struct {
		Name string `json:"ifname"`
	}
	if json.Unmarshal(payload, &links) != nil {
		return false
	}
	for _, link := range links {
		if link.Name == "" || link.Name == name {
			return false
		}
	}
	return true
}

func validToolPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func validInterfaceName(name string) bool {
	if name == "" || len(name) > 15 || name == "lo" {
		return false
	}
	for _, value := range name {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_' || value == '-' {
			continue
		}
		return false
	}
	return true
}

func bits(prefix netip.Prefix) string {
	return strings.TrimPrefix(prefix.String(), prefix.Addr().String()+"/")
}
