package linuxrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

type inspectionDocument struct {
	NFTables []any `json:"nftables"`
}

func expectedInspectionDocument(expected ExpectedRuleSet) inspectionDocument {
	objects := []any{
		map[string]any{"table": map[string]any{
			"family": tableFamily, "name": expected.tableName, "comment": expected.ownershipComment(),
		}},
	}
	if expected.profile == RuleProfileWorkloadOutput {
		objects = append(objects, expectedChainObject(expected, outputChain, "output", false))
		objects = append(objects, map[string]any{"rule": expectedRuleObject(expected, outputChain, "proxy", outputProxyExpressions(expected))})
		objects = append(objects, expectedNeighborDiscoveryObjects(expected, outputChain, "oifname")...)
		return inspectionDocument{NFTables: objects}
	}
	objects = append(objects,
		expectedChainObject(expected, inputChain, "input", false),
		expectedChainObject(expected, forwardChain, "forward", false),
	)
	objects = append(objects, expectedNeighborDiscoveryObjects(expected, inputChain, "iifname")...)
	objects = append(objects,
		map[string]any{"rule": expectedRuleObject(expected, forwardChain, "proxy-outbound", forwardedProxyExpressions(expected))},
		map[string]any{"rule": expectedRuleObject(expected, forwardChain, "proxy-return", proxyReturnExpressions(expected))},
	)
	return inspectionDocument{NFTables: objects}
}

func expectedChainObject(expected ExpectedRuleSet, chain, hook string, quarantine bool) map[string]any {
	value := map[string]any{
		"family": tableFamily, "table": expected.tableName, "name": chain,
		"type": "filter", "hook": hook, "prio": float64(-100), "policy": "drop",
	}
	if quarantine {
		value["comment"] = "hal-quarantine"
	}
	return map[string]any{"chain": value}
}

func expectedRuleObject(expected ExpectedRuleSet, chain, role string, expressions []any) map[string]any {
	return map[string]any{
		"family":  tableFamily,
		"table":   expected.tableName,
		"chain":   chain,
		"expr":    expressions,
		"comment": expected.ruleComment(role),
	}
}

func outputProxyExpressions(expected ExpectedRuleSet) []any {
	expressions := []any{
		matchExpression(map[string]any{"meta": map[string]any{"key": "oifname"}}, expected.interfaceName),
	}
	return append(expressions, proxyDestinationExpressions(expected)...)
}

func forwardedProxyExpressions(expected ExpectedRuleSet) []any {
	expressions := []any{
		matchExpression(map[string]any{"meta": map[string]any{"key": "iifname"}}, expected.interfaceName),
		matchExpression(map[string]any{"meta": map[string]any{"key": "oifname"}}, expected.mappingInterfaceName),
	}
	return append(expressions, proxyDestinationExpressions(expected)...)
}

func proxyDestinationExpressions(expected ExpectedRuleSet) []any {
	protocol := "ip"
	if expected.proxyAddress.Is6() {
		protocol = "ip6"
	}
	return []any{
		matchExpression(map[string]any{"payload": map[string]any{"protocol": protocol, "field": "daddr"}}, expected.proxyAddress.String()),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, float64(expected.proxyPort)),
		map[string]any{"accept": nil},
	}
}

func proxyReturnExpressions(expected ExpectedRuleSet) []any {
	protocol := "ip"
	if expected.proxyAddress.Is6() {
		protocol = "ip6"
	}
	expressions := []any{
		matchExpression(map[string]any{"meta": map[string]any{"key": "iifname"}}, expected.mappingInterfaceName),
		matchExpression(map[string]any{"meta": map[string]any{"key": "oifname"}}, expected.interfaceName),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": protocol, "field": "saddr"}}, expected.proxyAddress.String()),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "sport"}}, float64(expected.proxyPort)),
		membershipExpression(map[string]any{"ct": map[string]any{"key": "state"}}, "established"),
		map[string]any{"accept": nil},
	}
	return expressions
}

func expectedNeighborDiscoveryObjects(expected ExpectedRuleSet, chain, interfaceKey string) []any {
	objects := make([]any, 0, len(minimalNeighborDiscoveryRules(expected)))
	for _, rule := range minimalNeighborDiscoveryRules(expected) {
		objects = append(objects, map[string]any{"rule": expectedRuleObject(expected, chain, rule.role, neighborDiscoveryExpressions(expected, interfaceKey, rule))})
	}
	return objects
}

func neighborDiscoveryExpressions(expected ExpectedRuleSet, interfaceKey string, rule neighborDiscoveryRule) []any {
	return []any{
		matchExpression(map[string]any{"meta": map[string]any{"key": interfaceKey}}, expected.interfaceName),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "ip6", "field": "nexthdr"}}, "ipv6-icmp"),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "ip6", "field": "hoplimit"}}, float64(255)),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "icmpv6", "field": "type"}}, rule.messageType),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "ip6", "field": "saddr"}}, rule.source),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "ip6", "field": "daddr"}}, rule.destination),
		matchExpression(map[string]any{"payload": map[string]any{"protocol": "icmpv6", "field": "taddr"}}, rule.target),
		map[string]any{"accept": nil},
	}
}

func matchExpression(left, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
}

func membershipExpression(left, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": "in", "left": left, "right": right}}
}

func expectedInspectionJSON(expected ExpectedRuleSet) []byte {
	payload, _ := json.Marshal(expectedInspectionDocument(expected))
	return payload
}

func quarantineInspectionJSON(expected ExpectedRuleSet) []byte {
	objects := []any{
		map[string]any{"table": map[string]any{
			"family": tableFamily, "name": expected.tableName, "comment": expected.ownershipComment(),
		}},
	}
	if expected.profile == RuleProfileWorkloadOutput {
		objects = append(objects, expectedChainObject(expected, outputChain, "output", true))
	} else {
		objects = append(objects,
			expectedChainObject(expected, inputChain, "input", true),
			expectedChainObject(expected, forwardChain, "forward", true),
		)
	}
	payload, _ := json.Marshal(inspectionDocument{NFTables: objects})
	return payload
}

func inspectExpected(payload []byte, expected ExpectedRuleSet, maxBytes int64) error {
	actual, err := decodeInspection(payload, maxBytes)
	if err != nil {
		return err
	}
	if containsForbiddenStatement(actual) {
		return ErrInspectionFailed
	}
	expectedDocument := normalizedDocument(expectedInspectionJSON(expected))
	if !reflect.DeepEqual(actual, expectedDocument) {
		return ErrInspectionFailed
	}
	return nil
}

func inspectQuarantine(payload []byte, expected ExpectedRuleSet, maxBytes int64) error {
	actual, err := decodeInspection(payload, maxBytes)
	if err != nil {
		return err
	}
	quarantine := normalizedDocument(quarantineInspectionJSON(expected))
	if !reflect.DeepEqual(actual, quarantine) {
		return ErrInspectionFailed
	}
	return nil
}

func inspectOwnership(payload []byte, expected ExpectedRuleSet, maxBytes int64) (bool, error) {
	document, err := decodeInspection(payload, maxBytes)
	if err != nil {
		return false, err
	}
	objects, ok := document["nftables"].([]any)
	if !ok || len(objects) == 0 {
		return false, ErrInspectionFailed
	}
	first, ok := objects[0].(map[string]any)
	if !ok {
		return false, ErrInspectionFailed
	}
	table, ok := first["table"].(map[string]any)
	if !ok {
		return false, ErrInspectionFailed
	}
	family, familyOK := table["family"].(string)
	name, nameOK := table["name"].(string)
	comment, commentOK := table["comment"].(string)
	if !familyOK || !nameOK || family != tableFamily || name != expected.tableName || !commentOK {
		return false, ErrInspectionFailed
	}
	return comment == expected.ownershipComment(), nil
}

func decodeInspection(payload []byte, maxBytes int64) (map[string]any, error) {
	if maxBytes <= 0 || int64(len(payload)) > maxBytes {
		return nil, ErrInspectionTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, ErrInspectionFailed
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInspectionFailed
	}
	normalized := normalizeNumbers(raw).(map[string]any)
	if err := normalizeVolatileNFTMetadata(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func normalizedDocument(payload []byte) map[string]any {
	var value map[string]any
	_ = json.Unmarshal(payload, &value)
	return value
}

func normalizeNumbers(value any) any {
	switch current := value.(type) {
	case json.Number:
		parsed, _ := current.Float64()
		return parsed
	case []any:
		for index := range current {
			current[index] = normalizeNumbers(current[index])
		}
		return current
	case map[string]any:
		for key := range current {
			current[key] = normalizeNumbers(current[key])
		}
		return current
	default:
		return value
	}
}

func normalizeVolatileNFTMetadata(document map[string]any) error {
	objects, ok := document["nftables"].([]any)
	if !ok {
		return ErrInspectionFailed
	}
	if len(objects) > 0 {
		if first, ok := objects[0].(map[string]any); ok {
			if _, metainfo := first["metainfo"]; metainfo {
				if len(first) != 1 {
					return ErrInspectionFailed
				}
				objects = objects[1:]
			}
		}
	}
	for _, object := range objects {
		outer, ok := object.(map[string]any)
		if !ok || len(outer) != 1 {
			return ErrInspectionFailed
		}
		for _, raw := range outer {
			inner, ok := raw.(map[string]any)
			if !ok {
				return ErrInspectionFailed
			}
			if handle, exists := inner["handle"]; exists {
				value, ok := handle.(float64)
				if !ok || value < 0 || value != float64(uint64(value)) {
					return ErrInspectionFailed
				}
				delete(inner, "handle")
			}
		}
	}
	document["nftables"] = objects
	return nil
}

func containsForbiddenStatement(value any) bool {
	switch current := value.(type) {
	case []any:
		for _, child := range current {
			if containsForbiddenStatement(child) {
				return true
			}
		}
	case map[string]any:
		for key, child := range current {
			switch key {
			case "jump", "goto", "dnat", "snat", "masquerade", "redirect":
				return true
			}
			if containsForbiddenStatement(child) {
				return true
			}
		}
	}
	return false
}
