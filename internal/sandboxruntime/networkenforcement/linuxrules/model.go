package linuxrules

import (
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
	defaultMaxBatchBytes      = 64 << 10
	defaultMaxInspectionBytes = 256 << 10
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

// RuleSetConfig contains safe correlation plus private live rule inputs. Raw
// topology and proxy values are deliberately excluded from JSON.
type RuleSetConfig struct {
	Correlation   networkenforcement.EnforcementCorrelation `json:"correlation"`
	Profile       RuleProfile                               `json:"profile"`
	Namespace     NamespaceHandle                           `json:"-"`
	TableName     string                                    `json:"-"`
	InterfaceName string                                    `json:"-"`
	ProxyAddress  string                                    `json:"-"`
	ProxyPort     uint16                                    `json:"-"`
}

// ExpectedRuleSet is a validated, immutable expected-rule model.
type ExpectedRuleSet struct {
	correlation   networkenforcement.EnforcementCorrelation
	profile       RuleProfile
	namespace     NamespaceHandle
	tableName     string
	interfaceName string
	proxyAddress  netip.Addr
	proxyPort     uint16
	ownerToken    string
	ruleDigest    string
}

func NewExpectedRuleSet(config RuleSetConfig) (ExpectedRuleSet, error) {
	correlation := networkenforcement.SanitizeEnforcementCorrelation(config.Correlation)
	address, addressErr := netip.ParseAddr(strings.TrimSpace(config.ProxyAddress))
	if !networkenforcement.EnforcementCorrelationComplete(correlation) ||
		!validRuleProfile(config.Profile) ||
		!config.Namespace.valid() ||
		!validNFTIdentifier(config.TableName, 32) ||
		!validInterfaceName(config.InterfaceName) ||
		addressErr != nil || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() ||
		config.ProxyPort == 0 {
		return ExpectedRuleSet{}, operationError{err: ErrInvalidConfiguration}
	}

	ownerToken := correlationDigest(correlation)[:24]
	rules := ExpectedRuleSet{
		correlation:   correlation,
		profile:       config.Profile,
		namespace:     config.Namespace,
		tableName:     config.TableName,
		interfaceName: config.InterfaceName,
		proxyAddress:  address.Unmap(),
		proxyPort:     config.ProxyPort,
		ownerToken:    ownerToken,
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
		validInterfaceName(r.interfaceName) && r.proxyAddress.IsValid() &&
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
		fmt.Fprintf(&builder, "add rule %s %s %s oifname %s ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept comment %s\n",
			tableFamily, r.tableName, outputChain, quoteNFT(r.interfaceName), quoteNFT(r.ruleComment("ipv6-nd")))
		return []byte(builder.String())
	}

	fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook input priority -100; policy drop; }\n", tableFamily, r.tableName, inputChain)
	fmt.Fprintf(&builder, "add chain %s %s %s { type filter hook forward priority -100; policy drop; }\n", tableFamily, r.tableName, forwardChain)
	fmt.Fprintf(&builder, "add rule %s %s %s iifname %s ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept comment %s\n",
		tableFamily, r.tableName, inputChain, quoteNFT(r.interfaceName), quoteNFT(r.ruleComment("ipv6-nd")))
	fmt.Fprintf(&builder, "add rule %s %s %s iifname %s %s daddr %s tcp dport %d accept comment %s\n",
		tableFamily, r.tableName, forwardChain, quoteNFT(r.interfaceName), addressFamily,
		r.proxyAddress.String(), r.proxyPort, quoteNFT(r.ruleComment("proxy-outbound")))
	fmt.Fprintf(&builder, "add rule %s %s %s oifname %s %s saddr %s tcp sport %d ct state established accept comment %s\n",
		tableFamily, r.tableName, forwardChain, quoteNFT(r.interfaceName), addressFamily,
		r.proxyAddress.String(), r.proxyPort, quoteNFT(r.ruleComment("proxy-return")))
	return []byte(builder.String())
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

func correlationDigest(correlation networkenforcement.EnforcementCorrelation) string {
	joined := strings.Join([]string{
		correlation.SandboxID,
		correlation.ExecutionID,
		correlation.WorkerID,
		correlation.RuntimeID,
		correlation.PlanID,
		correlation.PolicySnapshotID,
		correlation.ProxySessionID,
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
