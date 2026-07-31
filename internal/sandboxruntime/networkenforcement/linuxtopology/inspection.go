package linuxtopology

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
)

type inspectionKind uint8

const (
	inspectionLinks inspectionKind = iota + 1
	inspectionAddresses
	inspectionIPv4Routes
	inspectionIPv6Routes
)

func (l *Lifecycle) inspectionSpec(kind inspectionKind, files []*os.File) ProcessSpec {
	ipArgs := []string{"-json"}
	switch kind {
	case inspectionLinks:
		ipArgs = append(ipArgs, "link", "show")
	case inspectionAddresses:
		ipArgs = append(ipArgs, "address", "show")
	case inspectionIPv4Routes:
		ipArgs = append(ipArgs, "-4", "route", "show", "table", "main")
	case inspectionIPv6Routes:
		ipArgs = append(ipArgs, "-6", "route", "show", "table", "main")
	}
	return ProcessSpec{
		Role: ProcessRoleInspection,
		Path: l.config.Tools.Nsenter,
		Args: append([]string{
			"--preserve-credentials",
			"--user=/proc/self/fd/3",
			"--net=/proc/self/fd/4",
			"--", l.config.Tools.IP,
		}, ipArgs...),
		Env:         nil,
		ExtraFiles:  append([]*os.File(nil), files...),
		OutputLimit: l.config.OutputLimit,
	}
}

func validLinkInspection(output []byte, mappingInterface string) bool {
	var links []struct {
		Index int      `json:"ifindex"`
		Name  string   `json:"ifname"`
		Flags []string `json:"flags"`
	}
	if len(output) == 0 || json.Unmarshal(output, &links) != nil || len(links) != 2 {
		return false
	}
	indices := make(map[int]struct{}, len(links))
	loopbackOK := false
	mappingOK := false
	for _, link := range links {
		if link.Index <= 0 {
			return false
		}
		if _, duplicate := indices[link.Index]; duplicate {
			return false
		}
		indices[link.Index] = struct{}{}
		up := slices.Contains(link.Flags, "UP")
		switch link.Name {
		case "lo":
			if loopbackOK || !up || !slices.Contains(link.Flags, "LOOPBACK") {
				return false
			}
			loopbackOK = true
		case mappingInterface:
			if mappingOK || !up || slices.Contains(link.Flags, "LOOPBACK") {
				return false
			}
			mappingOK = true
		default:
			return false
		}
	}
	return loopbackOK && mappingOK
}

type interfaceAddressEvidence struct {
	IPv4Address       netip.Addr
	IPv4Prefix        netip.Prefix
	IPv6GlobalAddress netip.Addr
	IPv6GlobalPrefix  netip.Prefix
	IPv6GlobalRoute   bool
	IPv6LinkAddress   netip.Addr
	IPv6LinkPrefix    netip.Prefix
}

func validAddressInspection(output []byte, mappingInterface string) bool {
	_, valid := inspectAddressEvidence(output, mappingInterface)
	return valid
}

func inspectAddressEvidence(output []byte, mappingInterface string) (interfaceAddressEvidence, bool) {
	var links []struct {
		Index     int    `json:"ifindex"`
		Name      string `json:"ifname"`
		Addresses []struct {
			Family        string `json:"family"`
			Local         string `json:"local"`
			PrefixLen     int    `json:"prefixlen"`
			Scope         string `json:"scope"`
			NoPrefixRoute bool   `json:"noprefixroute"`
		} `json:"addr_info"`
	}
	if len(output) == 0 || json.Unmarshal(output, &links) != nil || len(links) != 2 {
		return interfaceAddressEvidence{}, false
	}
	var evidence interfaceAddressEvidence
	foundLoopback := false
	foundMapping := false
	for _, link := range links {
		if link.Index <= 0 {
			return interfaceAddressEvidence{}, false
		}
		seen := make(map[string]struct{}, len(link.Addresses))
		loopbackV4 := 0
		loopbackV6 := 0
		mappingV4 := 0
		mappingV6Global := 0
		mappingV6Link := 0
		for _, address := range link.Addresses {
			parsed, err := netip.ParseAddr(address.Local)
			if err != nil || (parsed.Is4() && address.Family != "inet") ||
				(parsed.Is6() && address.Family != "inet6") ||
				address.PrefixLen < 0 || (parsed.Is4() && address.PrefixLen > 32) ||
				(parsed.Is6() && address.PrefixLen > 128) {
				return interfaceAddressEvidence{}, false
			}
			key := address.Family + "|" + parsed.String() + "|" + strconv.Itoa(address.PrefixLen) + "|" + address.Scope
			if _, duplicate := seen[key]; duplicate {
				return interfaceAddressEvidence{}, false
			}
			seen[key] = struct{}{}
			switch link.Name {
			case "lo":
				if address.Scope != "host" {
					return interfaceAddressEvidence{}, false
				}
				if parsed == netip.MustParseAddr("127.0.0.1") && address.PrefixLen == 8 {
					loopbackV4++
				} else if parsed == netip.IPv6Loopback() && address.PrefixLen == 128 {
					loopbackV6++
				} else {
					return interfaceAddressEvidence{}, false
				}
			case mappingInterface:
				if parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() {
					return interfaceAddressEvidence{}, false
				}
				prefix := netip.PrefixFrom(parsed, address.PrefixLen).Masked()
				switch {
				case parsed.Is4() && address.Scope == "global" && address.PrefixLen > 0:
					mappingV4++
					evidence.IPv4Address, evidence.IPv4Prefix = parsed, prefix
				case parsed.Is6() && address.Scope == "global" && address.PrefixLen > 0 && !parsed.IsLinkLocalUnicast():
					mappingV6Global++
					evidence.IPv6GlobalAddress, evidence.IPv6GlobalPrefix = parsed, prefix
					evidence.IPv6GlobalRoute = !address.NoPrefixRoute
				case parsed.Is6() && address.Scope == "link" && address.PrefixLen > 0 && parsed.IsLinkLocalUnicast():
					mappingV6Link++
					evidence.IPv6LinkAddress, evidence.IPv6LinkPrefix = parsed, prefix
				default:
					return interfaceAddressEvidence{}, false
				}
			default:
				return interfaceAddressEvidence{}, false
			}
		}
		if link.Name == "lo" {
			if len(link.Addresses) != 2 || loopbackV4 != 1 || loopbackV6 != 1 {
				return interfaceAddressEvidence{}, false
			}
			foundLoopback = true
		} else {
			if len(link.Addresses) != 3 || mappingV4 != 1 || mappingV6Global != 1 || mappingV6Link != 1 {
				return interfaceAddressEvidence{}, false
			}
			foundMapping = true
		}
	}
	return evidence, foundLoopback && foundMapping
}

func validRouteInspection(ipv4, ipv6 []byte, mappingInterface string, addresses interfaceAddressEvidence) bool {
	return validFamilyRoutes(
		ipv4, mappingInterface, true,
		[]netip.Prefix{addresses.IPv4Prefix}, []netip.Addr{addresses.IPv4Address}, []bool{true},
	) && validFamilyRoutes(
		ipv6, mappingInterface, false,
		[]netip.Prefix{addresses.IPv6GlobalPrefix, addresses.IPv6LinkPrefix},
		[]netip.Addr{addresses.IPv6GlobalAddress, addresses.IPv6LinkAddress},
		[]bool{addresses.IPv6GlobalRoute, true},
	)
}

func validFamilyRoutes(
	output []byte,
	mappingInterface string,
	ipv4 bool,
	requiredPrefixes []netip.Prefix,
	interfaceAddresses []netip.Addr,
	requiredRoutes []bool,
) bool {
	var routes []struct {
		Destination string `json:"dst"`
		Gateway     string `json:"gateway"`
		Device      string `json:"dev"`
		Scope       string `json:"scope"`
		Type        string `json:"type"`
		Protocol    string `json:"protocol"`
		Preferred   string `json:"prefsrc"`
		Metric      int    `json:"metric"`
	}
	if len(output) == 0 || json.Unmarshal(output, &routes) != nil || len(requiredPrefixes) == 0 ||
		len(requiredPrefixes) != len(interfaceAddresses) || len(requiredPrefixes) != len(requiredRoutes) {
		return false
	}
	for index := range requiredPrefixes {
		if !requiredPrefixes[index].IsValid() || !interfaceAddresses[index].IsValid() ||
			requiredPrefixes[index].Addr().Is4() != ipv4 || interfaceAddresses[index].Is4() != ipv4 ||
			!requiredPrefixes[index].Contains(interfaceAddresses[index]) {
			return false
		}
	}
	var defaultGateway netip.Addr
	defaults := 0
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.Device != mappingInterface || (route.Type != "" && route.Type != "unicast") {
			return false
		}
		if route.Metric < 0 {
			return false
		}
		if route.Preferred != "" {
			preferred, err := netip.ParseAddr(route.Preferred)
			if err != nil || preferred.Is4() != ipv4 || preferred.IsUnspecified() || preferred.IsMulticast() {
				return false
			}
		}
		key := route.Destination + "|" + route.Gateway + "|" + route.Device + "|" + route.Scope + "|" + route.Type + "|" + route.Protocol + "|" + route.Preferred + "|" + strconv.Itoa(route.Metric)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if route.Destination == "default" {
			if route.Protocol != "" {
				return false
			}
			gateway, err := netip.ParseAddr(route.Gateway)
			if err != nil || gateway.Is4() != ipv4 || gateway.IsUnspecified() || gateway.IsMulticast() ||
				route.Scope != "" || route.Preferred != "" || !addressInPrefixes(gateway, requiredPrefixes) {
				return false
			}
			defaultGateway = gateway
			defaults++
		}
	}
	if defaults != 1 || !defaultGateway.IsValid() {
		return false
	}
	prefixCounts := make([]int, len(requiredPrefixes))
	for _, route := range routes {
		if route.Destination == "default" {
			continue
		}
		if route.Gateway != "" || (route.Scope != "" && route.Scope != "link") {
			return false
		}
		destination, valid := parseRouteDestination(route.Destination)
		if !valid || destination.Addr().Is4() != ipv4 || destination.Addr().IsUnspecified() || destination.Bits() == 0 {
			return false
		}
		matchedPrefix := -1
		for index, required := range requiredPrefixes {
			if destination == required {
				matchedPrefix = index
				break
			}
		}
		if matchedPrefix >= 0 {
			if !requiredRoutes[matchedPrefix] || route.Protocol != "kernel" ||
				(ipv4 && route.Scope != "link") || (!ipv4 && route.Scope != "") {
				return false
			}
			if (ipv4 && route.Preferred != interfaceAddresses[matchedPrefix].String()) ||
				(!ipv4 && route.Preferred != "") {
				return false
			}
			prefixCounts[matchedPrefix]++
			if prefixCounts[matchedPrefix] > 1 {
				return false
			}
			continue
		}
		return false
	}
	for index, count := range prefixCounts {
		if (requiredRoutes[index] && count != 1) || (!requiredRoutes[index] && count != 0) {
			return false
		}
	}
	return true
}

func addressInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRouteDestination(value string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), true
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(address, bits), true
}

type commandReachabilityProber struct {
	runner CommandRunner
	tools  ToolPaths
	limit  int64
}

func (p commandReachabilityProber) Probe(ctx context.Context, namespace *NamespaceHandle, identity Identity, mapping Mapping) error {
	if p.runner == nil || namespace == nil || !validIdentity(identity) || !validMapping(mapping) {
		return ErrInspectionFailed
	}
	_, port, err := net.SplitHostPort(mapping.ProxyEndpoint)
	if err != nil {
		return ErrInspectionFailed
	}
	address, err := netip.ParseAddr(mapping.GuestProxyAddress)
	if err != nil {
		return ErrInspectionFailed
	}
	files, err := namespace.extraFiles()
	if err != nil {
		return ErrInspectionFailed
	}
	defer closeFiles(files)
	family := "-6"
	if address.Is4() {
		family = "-4"
	}
	spec := ProcessSpec{
		Role: ProcessRoleProbe,
		Path: p.tools.Nsenter,
		Args: []string{
			"--preserve-credentials",
			"--user=/proc/self/fd/3",
			"--net=/proc/self/fd/4",
			"--", p.tools.NC, family, "-z", "-w", strconv.Itoa(2), mapping.GuestProxyAddress, port,
		},
		Env:         nil,
		ExtraFiles:  files,
		OutputLimit: p.limit,
	}
	if _, err := p.runner.Run(ctx, spec); err != nil {
		return ErrInspectionFailed
	}
	return nil
}
