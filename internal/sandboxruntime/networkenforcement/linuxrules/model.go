package linuxrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

const (
	hardMaxBatchBytes         = 64 << 10
	hardMaxInspectionBytes    = 256 << 10
	defaultMaxBatchBytes      = hardMaxBatchBytes
	defaultMaxInspectionBytes = hardMaxInspectionBytes
	tableFamily               = "inet"
	outputChain               = "hal_output"
	inputChain                = "hal_input"
	forwardChain              = "hal_forward"
	adapterID                 = "linux-nft-inspected-rules"
)

type RuleProfile string

const (
	RuleProfileWorkloadOutput RuleProfile = "workload_output"
	RuleProfileForwardedTAP   RuleProfile = "forwarded_tap"
)

// NamespaceHandle is live-only namespace state. Its descriptor is never
// serialized or included in errors.
type NamespaceHandle struct {
	userFD    int
	networkFD int
}

func NewNamespaceHandle(userFD, networkFD int) NamespaceHandle {
	return NamespaceHandle{userFD: userFD, networkFD: networkFD}
}

func (h NamespaceHandle) valid() bool {
	return h.userFD > 2 && h.networkFD > 2 && h.userFD != h.networkFD
}

type TableQuery struct {
	family string
	name   string
}

// RawPacketIsolationVerifier is a live-only fail-closed boundary for the
// workload-output profile. Implementations must mechanically verify that the
// exact correlated runtime generation cannot create raw packet sockets (for
// example, CAP_NET_RAW is absent from its effective, permitted, inheritable,
// bounding, and ambient capability sets).
// A successful call returns a distinct correlated proof. It must never be
// folded into firewall rule inspection labels because inet rules cannot prove
// link-layer mediation.
type RawPacketIsolationVerifier interface {
	VerifyRawPacketIsolation(context.Context, networkenforcement.EnforcementCorrelation) (networkenforcement.RawPacketIsolationProof, error)
}

// RuleSetConfig contains safe correlation plus private live rule inputs. Raw
// topology and proxy values are deliberately excluded from JSON.
type RuleSetConfig struct {
	Correlation          networkenforcement.EnforcementCorrelation `json:"correlation"`
	Profile              RuleProfile                               `json:"profile"`
	Namespace            NamespaceHandle                           `json:"-"`
	TableName            string                                    `json:"-"`
	InterfaceName        string                                    `json:"-"`
	MappingInterfaceName string                                    `json:"-"`
	ProxyAddress         string                                    `json:"-"`
	ProxyPort            uint16                                    `json:"-"`
	RawPacketIsolation   RawPacketIsolationVerifier                `json:"-"`
	WorkloadIPv6Address  string                                    `json:"-"`
	GatewayIPv6Address   string                                    `json:"-"`
	IPv6PrefixBits       uint8                                     `json:"-"`
	AllowIPv6DAD         bool                                      `json:"-"`
}

// ExpectedRuleSet is a validated, immutable expected-rule model.
type ExpectedRuleSet struct {
	correlation          networkenforcement.EnforcementCorrelation
	profile              RuleProfile
	namespace            NamespaceHandle
	tableName            string
	interfaceName        string
	mappingInterfaceName string
	proxyAddress         netip.Addr
	proxyPort            uint16
	ownerToken           string
	ruleDigest           string
	rawPacketIsolation   RawPacketIsolationVerifier
	workloadIPv6Address  netip.Addr
	gatewayIPv6Address   netip.Addr
	ipv6PrefixBits       uint8
	allowIPv6DAD         bool
}

func NewExpectedRuleSet(config RuleSetConfig) (ExpectedRuleSet, error) {
	correlation := networkenforcement.SanitizeEnforcementCorrelation(config.Correlation)
	address, addressErr := netip.ParseAddr(strings.TrimSpace(config.ProxyAddress))
	workloadIPv6Address, workloadIPv6Err := netip.ParseAddr(strings.TrimSpace(config.WorkloadIPv6Address))
	gatewayIPv6Address, gatewayIPv6Err := netip.ParseAddr(strings.TrimSpace(config.GatewayIPv6Address))
	mappingValid := config.Profile == RuleProfileWorkloadOutput && config.MappingInterfaceName == ""
	if config.Profile == RuleProfileForwardedTAP {
		mappingValid = validInterfaceName(config.MappingInterfaceName) && config.MappingInterfaceName != config.InterfaceName
	}
	rawPacketIsolationValid := config.Profile != RuleProfileWorkloadOutput || config.RawPacketIsolation != nil
	configuredIPv6LinkValid := workloadIPv6Err == nil && gatewayIPv6Err == nil &&
		validConfiguredIPv6Link(workloadIPv6Address, gatewayIPv6Address, config.IPv6PrefixBits) &&
		config.AllowIPv6DAD == (config.Profile == RuleProfileForwardedTAP)
	if !networkenforcement.EnforcementCorrelationComplete(correlation) ||
		!validRuleProfile(config.Profile) ||
		!config.Namespace.valid() ||
		!validNFTIdentifier(config.TableName, 32) ||
		!validInterfaceName(config.InterfaceName) ||
		!mappingValid || !rawPacketIsolationValid || !configuredIPv6LinkValid ||
		addressErr != nil || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || isKnownMetadataProxyAddress(address) ||
		config.ProxyPort == 0 {
		return ExpectedRuleSet{}, operationError{err: ErrInvalidConfiguration}
	}

	ownerToken := correlationDigest(correlation)[:24]
	rules := ExpectedRuleSet{
		correlation:          correlation,
		profile:              config.Profile,
		namespace:            config.Namespace,
		tableName:            config.TableName,
		interfaceName:        config.InterfaceName,
		mappingInterfaceName: config.MappingInterfaceName,
		proxyAddress:         address.Unmap(),
		proxyPort:            config.ProxyPort,
		ownerToken:           ownerToken,
		rawPacketIsolation:   config.RawPacketIsolation,
		workloadIPv6Address:  workloadIPv6Address,
		gatewayIPv6Address:   gatewayIPv6Address,
		ipv6PrefixBits:       config.IPv6PrefixBits,
		allowIPv6DAD:         config.AllowIPv6DAD,
	}
	rules.ruleDigest = inspectionDigest(expectedInspectionDocument(rules))
	return rules, nil
}

func (r ExpectedRuleSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Correlation networkenforcement.EnforcementCorrelation `json:"correlation"`
		Profile     RuleProfile                               `json:"profile"`
		RuleDigest  string                                    `json:"ruleDigest"`
	}{Correlation: r.correlation, Profile: r.profile, RuleDigest: r.ruleDigest})
}

func (r ExpectedRuleSet) valid() bool {
	return networkenforcement.EnforcementCorrelationComplete(r.correlation) &&
		validRuleProfile(r.profile) &&
		r.namespace.valid() && validNFTIdentifier(r.tableName, 32) &&
		validInterfaceName(r.interfaceName) && validMappingInterface(r) && validRawPacketIsolation(r) &&
		validConfiguredIPv6Link(r.workloadIPv6Address, r.gatewayIPv6Address, r.ipv6PrefixBits) &&
		r.allowIPv6DAD == (r.profile == RuleProfileForwardedTAP) && r.proxyAddress.IsValid() &&
		r.proxyPort != 0 && r.ownerToken != "" && r.ruleDigest != ""
}

func (r ExpectedRuleSet) query() TableQuery {
	return TableQuery{family: tableFamily, name: r.tableName}
}

func (r ExpectedRuleSet) ownershipComment() string {
	return "hal-owner-" + r.ownerToken + "-" + r.correlation.RuleGenerationID
}

func (r ExpectedRuleSet) ruleComment(role string) string {
	return r.ownershipComment() + "-" + role
}

func (r ExpectedRuleSet) fullBatch(replace bool) []byte {
	var builder strings.Builder
	if replace {
		fmt.Fprintf(&builder, "delete table %s %s\n", tableFamily, r.tableName)
	}
	fmt.Fprintf(&builder, "add table %s %s { comment %s; }\n", tableFamily, r.tableName, quoteNFT(r.ownershipComment()))
	addressFamily := "ip"
	if r.proxyAddress.Is6() {
		addressFamily = "ip6"
	}
	if r.profile == RuleProfileWorkloadOutput {
		fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook output priority -100; policy drop; }\n", tableFamily, r.tableName, outputChain)
		fmt.Fprintf(&builder, "add rule %s %s %s oifname %s %s daddr %s tcp dport %d accept comment %s\n",
			tableFamily, r.tableName, outputChain, quoteNFT(r.interfaceName), addressFamily,
			r.proxyAddress.String(), r.proxyPort, quoteNFT(r.ruleComment("proxy")))
		r.writeNeighborDiscoveryRules(&builder, outputChain, "oifname")
		return []byte(builder.String())
	}

	fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook input priority -100; policy drop; }\n", tableFamily, r.tableName, inputChain)
	fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook forward priority -100; policy drop; }\n", tableFamily, r.tableName, forwardChain)
	r.writeNeighborDiscoveryRules(&builder, inputChain, "iifname")
	fmt.Fprintf(&builder, "add rule %s %s %s iifname %s oifname %s %s daddr %s tcp dport %d accept comment %s\n",
		tableFamily, r.tableName, forwardChain, quoteNFT(r.interfaceName), quoteNFT(r.mappingInterfaceName), addressFamily,
		r.proxyAddress.String(), r.proxyPort, quoteNFT(r.ruleComment("proxy-outbound")))
	fmt.Fprintf(&builder, "add rule %s %s %s iifname %s oifname %s %s saddr %s tcp sport %d ct state established accept comment %s\n",
		tableFamily, r.tableName, forwardChain, quoteNFT(r.mappingInterfaceName), quoteNFT(r.interfaceName), addressFamily,
		r.proxyAddress.String(), r.proxyPort, quoteNFT(r.ruleComment("proxy-return")))
	return []byte(builder.String())
}

func (r ExpectedRuleSet) writeNeighborDiscoveryRules(builder *strings.Builder, chain, interfaceKey string) {
	for _, rule := range minimalNeighborDiscoveryRules(r) {
		fmt.Fprintf(builder, "add rule %s %s %s %s %s ip6 nexthdr icmpv6 ip6 hoplimit 255 icmpv6 type %s ip6 saddr %s ip6 daddr %s icmpv6 taddr %s accept comment %s\n",
			tableFamily, r.tableName, chain, interfaceKey, quoteNFT(r.interfaceName),
			rule.messageType, rule.source, rule.destination, rule.target, quoteNFT(r.ruleComment(rule.role)))
	}
}

func (r ExpectedRuleSet) quarantineBatch() []byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "delete table %s %s\nadd table %s %s { comment %s; }\n",
		tableFamily, r.tableName, tableFamily, r.tableName, quoteNFT(r.ownershipComment()))
	if r.profile == RuleProfileWorkloadOutput {
		fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook output priority -100; policy drop; comment %s; }\n",
			tableFamily, r.tableName, outputChain, quoteNFT("hal-quarantine"))
		return []byte(builder.String())
	}
	fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook input priority -100; policy drop; comment %s; }\n",
		tableFamily, r.tableName, inputChain, quoteNFT("hal-quarantine"))
	fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook forward priority -100; policy drop; comment %s; }\n",
		tableFamily, r.tableName, forwardChain, quoteNFT("hal-quarantine"))
	return []byte(builder.String())
}

func (r ExpectedRuleSet) deleteBatch() []byte {
	return []byte(fmt.Sprintf("delete table %s %s\n", tableFamily, r.tableName))
}

func quoteNFT(value string) string { return strconv.Quote(value) }

func validNFTIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for index, current := range value {
		if (current >= 'a' && current <= 'z') ||
			(current >= 'A' && current <= 'Z') ||
			(current >= '0' && current <= '9' && index > 0) || current == '_' {
			continue
		}
		return false
	}
	return true
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, current := range value {
		if (current >= 'a' && current <= 'z') ||
			(current >= 'A' && current <= 'Z') ||
			(current >= '0' && current <= '9') || current == '_' || current == '-' {
			continue
		}
		return false
	}
	return true
}

func validRuleProfile(value RuleProfile) bool {
	return value == RuleProfileWorkloadOutput || value == RuleProfileForwardedTAP
}

func validMappingInterface(r ExpectedRuleSet) bool {
	if r.profile == RuleProfileWorkloadOutput {
		return r.mappingInterfaceName == ""
	}
	return validInterfaceName(r.mappingInterfaceName) && r.mappingInterfaceName != r.interfaceName
}

func validRawPacketIsolation(r ExpectedRuleSet) bool {
	return r.profile != RuleProfileWorkloadOutput || r.rawPacketIsolation != nil
}

type neighborDiscoveryRule struct {
	role        string
	messageType string
	source      string
	destination string
	target      string
}

func minimalNeighborDiscoveryRules(expected ExpectedRuleSet) []neighborDiscoveryRule {
	local := expected.workloadIPv6Address.String()
	peer := expected.gatewayIPv6Address.String()
	rules := make([]neighborDiscoveryRule, 0, 5)
	if expected.allowIPv6DAD {
		rules = append(rules, neighborDiscoveryRule{
			role: "ipv6-nd-solicit-dad", messageType: "nd-neighbor-solicit",
			source: "::", destination: solicitedNodeMulticast(expected.workloadIPv6Address).String(), target: local,
		})
	}
	return append(rules,
		neighborDiscoveryRule{
			role: "ipv6-nd-solicit-multicast", messageType: "nd-neighbor-solicit",
			source: local, destination: solicitedNodeMulticast(expected.gatewayIPv6Address).String(), target: peer,
		},
		neighborDiscoveryRule{
			role: "ipv6-nd-solicit-unicast", messageType: "nd-neighbor-solicit",
			source: local, destination: peer, target: peer,
		},
		neighborDiscoveryRule{
			role: "ipv6-nd-advert-unicast", messageType: "nd-neighbor-advert",
			source: local, destination: peer, target: local,
		},
		neighborDiscoveryRule{
			role: "ipv6-nd-advert-all-nodes", messageType: "nd-neighbor-advert",
			source: local, destination: "ff02::1", target: local,
		},
	)
}

func validConfiguredIPv6Link(workload, gateway netip.Addr, prefixBits uint8) bool {
	if prefixBits == 0 || prefixBits > 128 || !validConfiguredIPv6Address(workload) || !validConfiguredIPv6Address(gateway) || workload == gateway {
		return false
	}
	// Rootless pasta uses a link-local next hop for a globally addressed
	// workload interface. The exact route/interface inspection belongs to the
	// topology resolver; the rule model admits that canonical IPv6 link shape.
	if gateway.IsLinkLocalUnicast() && !workload.IsLinkLocalUnicast() {
		return true
	}
	prefix := netip.PrefixFrom(workload, int(prefixBits)).Masked()
	return prefix.IsValid() && prefix.Contains(gateway)
}

func validConfiguredIPv6Address(address netip.Addr) bool {
	return address.IsValid() && address.Is6() && !address.Is4In6() && address.Zone() == "" &&
		!address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback()
}

func solicitedNodeMulticast(target netip.Addr) netip.Addr {
	base := netip.MustParseAddr("ff02::1:ff00:0").As16()
	targetBytes := target.As16()
	copy(base[13:], targetBytes[13:])
	return netip.AddrFrom16(base)
}

func isKnownMetadataProxyAddress(address netip.Addr) bool {
	address = address.Unmap()
	for _, raw := range []string{
		"169.254.169.254",
		"168.63.129.16",
		"100.100.100.200",
		"fd00:ec2::254",
		"fd20:ce::254",
	} {
		if address == netip.MustParseAddr(raw) {
			return true
		}
	}
	return false
}

func correlationDigest(correlation networkenforcement.EnforcementCorrelation) string {
	joined := strings.Join([]string{
		correlation.SandboxID,
		correlation.ExecutionID,
		correlation.WorkerID,
		correlation.RuntimeID,
		correlation.PlanID,
		correlation.PolicySnapshotID,
		correlation.ProxySessionID,
		correlation.ProxyGenerationID,
		correlation.TopologyGenerationID,
		correlation.RuleGenerationID,
	}, "\x00")
	digest := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(digest[:])
}

func inspectionDigest(value any) string {
	payload, _ := json.Marshal(value)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
