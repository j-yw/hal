package cmd

import "strings"

type missingSandboxDeleteRule struct {
	operation string
	markers   []string
}

var missingSandboxDeleteRules = map[string]missingSandboxDeleteRule{
	"digitalocean": {
		operation: "doctl compute droplet delete failed",
		markers: []string{
			": 404",
			"droplet not found",
			"resource you were accessing could not be found",
			"resource you requested could not be found",
		},
	},
	"lightsail": {
		operation: "aws lightsail delete-instance failed",
		markers: []string{
			"notfoundexception",
			"instance does not exist",
			"resource not found",
		},
	},
	"daytona": {
		markers: []string{
			"404",
			"api error: not found",
			"sandbox not found",
			"workspace not found",
		},
	},
	"hetzner": {
		markers: []string{
			"404",
			"server not found",
			"resource not found",
		},
	},
}

var nonMissingSandboxDeleteMarkers = []string{
	"no such host",
	"temporary failure in name resolution",
	"dial tcp",
	"connection refused",
	"connection reset",
	"network is unreachable",
	"tls handshake timeout",
	"i/o timeout",
	"context deadline exceeded",
	"timeout awaiting response headers",
	"unauthorized",
	"authentication failed",
	"access denied",
	"forbidden",
	"permission denied",
	"invalid token",
	"expired token",
	"executable file not found",
}

func isMissingSandboxDeleteError(provider string, err error) bool {
	if err == nil {
		return false
	}

	text := strings.ToLower(err.Error())
	if containsAnySandboxDeleteMarker(text, nonMissingSandboxDeleteMarkers) {
		return false
	}

	rule, ok := missingSandboxDeleteRules[strings.ToLower(strings.TrimSpace(provider))]
	if !ok {
		return false
	}

	if rule.operation != "" && !strings.Contains(text, rule.operation) {
		return false
	}

	return containsAnySandboxDeleteMarker(text, rule.markers)
}

func containsAnySandboxDeleteMarker(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
