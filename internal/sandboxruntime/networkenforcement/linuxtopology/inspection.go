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

func validAddressInspection(output []byte, mappingInterface string) bool {
	var links []struct {
		Index     int    `json:"ifindex"`
		Name      string `json:"ifname"`
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if len(output) == 0 || json.Unmarshal(output, &links) != nil || len(links) != 2 {
		return false
	}
	foundLoopback := false
	foundMapping := false
	for _, link := range links {
		if link.Index <= 0 {
			return false
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
				return false
			}
			key := address.Family + "|" + parsed.String() + "|" + strconv.Itoa(address.PrefixLen) + "|" + address.Scope
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			switch link.Name {
			case "lo":
				if address.Scope != "host" {
					return false
				}
				if parsed == netip.MustParseAddr("127.0.0.1") && address.PrefixLen == 8 {
					loopbackV4++
				} else if parsed == netip.IPv6Loopback() && address.PrefixLen == 128 {
					loopbackV6++
				} else {
					return false
				}
			case mappingInterface:
				if parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() {
					return false
				}
				switch {
				case parsed.Is4() && address.Scope == "global" && address.PrefixLen > 0:
					mappingV4++
				case parsed.Is6() && address.Scope == "global" && address.PrefixLen > 0 && !parsed.IsLinkLocalUnicast():
					mappingV6Global++
				case parsed.Is6() && address.Scope == "link" && address.PrefixLen > 0 && parsed.IsLinkLocalUnicast():
					mappingV6Link++
				default:
					return false
				}
			default:
				return false
			}
		}
		if link.Name == "lo" {
			if len(link.Addresses) != 2 || loopbackV4 != 1 || loopbackV6 != 1 {
				return false
			}
			foundLoopback = true
		} else {
			if len(link.Addresses) != 3 || mappingV4 != 1 || mappingV6Global != 1 || mappingV6Link != 1 {
				return false
			}
			foundMapping = true
		}
	}
	return foundLoopback && foundMapping
}

func validRouteInspection(ipv4, ipv6 []byte, mappingInterface string) bool {
	return validFamilyRoutes(ipv4, mappingInterface, true) && validFamilyRoutes(ipv6, mappingInterface, false)
}

func validFamilyRoutes(output []byte, mappingInterface string, ipv4 bool) bool {
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
	if len(output) == 0 || json.Unmarshal(output, &routes) != nil || len(routes) < 2 || len(routes) > 8 {
		return false
	}
	defaults := 0
	connected := 0
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.Device != mappingInterface || (route.Type != "" && route.Type != "unicast") {
			return false
		}
		if ipv4 && route.Protocol != "dhcp" && route.Protocol != "kernel" && route.Protocol != "" {
			return false
		}
		if !ipv4 && route.Protocol != "ra" && route.Protocol != "kernel" && route.Protocol != "" {
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
			gateway, err := netip.ParseAddr(route.Gateway)
			if err != nil || gateway.Is4() != ipv4 || gateway.IsUnspecified() || gateway.IsMulticast() {
				return false
			}
			defaults++
			continue
		}
		destination, prefixBits, valid := parseRouteDestination(route.Destination)
		if !valid || destination.Is4() != ipv4 || destination.IsUnspecified() || prefixBits == 0 {
			return false
		}
		if route.Gateway != "" {
			gateway, err := netip.ParseAddr(route.Gateway)
			if err != nil || gateway.Is4() != ipv4 || gateway.IsUnspecified() || gateway.IsMulticast() || route.Scope != "" {
				return false
			}
		} else {
			if route.Scope != "" && route.Scope != "link" {
				return false
			}
			connected++
		}
	}
	return defaults == 1 && connected >= 1
}

func parseRouteDestination(value string) (netip.Addr, int, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), prefix.Bits(), true
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}
	return address, bits, true
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
