package sandboxruntime

import "strings"

const (
	RuntimeGuestReadinessStateNotConfigured RuntimeGuestReadinessState = "not_configured"
	RuntimeGuestReadinessStateWaiting       RuntimeGuestReadinessState = "waiting"
	RuntimeGuestReadinessStateReady         RuntimeGuestReadinessState = "ready"
)

// RuntimeGuestReadinessState is the redaction-safe public guest readiness
// state. It records only the readiness boundary status and does not imply exec,
// copy, networking, credential, or template support.
type RuntimeGuestReadinessState string

// NewRuntimeGuestReadinessMetadata builds sanitized guest readiness metadata.
func NewRuntimeGuestReadinessMetadata(state RuntimeGuestReadinessState, transport string, labels []string) *RuntimeGuestReadinessMetadata {
	normalizedState := normalizeRuntimeGuestReadinessState(state)
	if normalizedState == "" {
		return nil
	}
	metadata := &RuntimeGuestReadinessMetadata{
		State:  normalizedState,
		Labels: runtimeGuestReadinessLabels(normalizedState, labels),
	}
	if normalizedState != RuntimeGuestReadinessStateNotConfigured {
		metadata.Transport = sanitizeRuntimeGuestReadinessToken(transport)
	}
	return metadata
}

// SanitizeRuntimeGuestReadinessMetadata preserves only canonical readiness
// state and safe transport/label tokens.
func SanitizeRuntimeGuestReadinessMetadata(metadata *RuntimeGuestReadinessMetadata) *RuntimeGuestReadinessMetadata {
	if metadata == nil {
		return nil
	}
	return NewRuntimeGuestReadinessMetadata(metadata.State, metadata.Transport, metadata.Labels)
}

func normalizeRuntimeGuestReadinessState(state RuntimeGuestReadinessState) RuntimeGuestReadinessState {
	switch RuntimeGuestReadinessState(strings.ToLower(strings.TrimSpace(string(state)))) {
	case RuntimeGuestReadinessStateNotConfigured:
		return RuntimeGuestReadinessStateNotConfigured
	case RuntimeGuestReadinessStateWaiting:
		return RuntimeGuestReadinessStateWaiting
	case RuntimeGuestReadinessStateReady:
		return RuntimeGuestReadinessStateReady
	default:
		return ""
	}
}

func runtimeGuestReadinessLabels(state RuntimeGuestReadinessState, labels []string) []string {
	out := []string{string(state)}
	seen := map[string]bool{string(state): true}
	for _, label := range labels {
		token := sanitizeRuntimeGuestReadinessToken(label)
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
	}
	return out
}

func sanitizeRuntimeGuestReadinessToken(value string) string {
	token := strings.ToLower(strings.TrimSpace(value))
	if token == "" || len(token) > 64 {
		return ""
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return ""
		}
	}
	for _, marker := range []string{
		"token",
		"secret",
		"password",
		"credential",
		"authorization",
		"bearer",
		"api_key",
		"apikey",
		"endpoint",
		"address",
		"url",
		"uri",
		"hostname",
		"host",
		"ip",
		"port",
		"path",
		"socket",
		"process",
		"pid",
		"argv",
		"command",
		"payload",
		"exec",
		"copy",
		"network",
		"proxy",
		"template",
		"vendor",
		"secure",
		"kit",
		"image",
		"provision",
		"kernel",
		"rootfs",
		"initrd",
		"snapshot",
		"bundle",
		"oci",
		"agent",
		"ssh",
		"kvm",
		"jailer",
		"root",
		"docker",
		"podman",
	} {
		if strings.Contains(token, marker) {
			return ""
		}
	}
	return token
}
