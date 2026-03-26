package cmd

import "strings"

func isMissingSandboxDeleteError(provider string, err error) bool {
	if err == nil {
		return false
	}

	text := strings.ToLower(err.Error())
	if !containsMissingSandboxDeleteText(text) {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "digitalocean":
		return strings.Contains(text, "doctl compute droplet delete failed")
	case "lightsail":
		return strings.Contains(text, "aws lightsail delete-instance failed")
	case "daytona", "hetzner":
		return !strings.Contains(text, "executable file not found")
	default:
		return false
	}
}

func containsMissingSandboxDeleteText(text string) bool {
	return strings.Contains(text, "not found") ||
		strings.Contains(text, "does not exist") ||
		strings.Contains(text, "doesn't exist") ||
		strings.Contains(text, "no such")
}
