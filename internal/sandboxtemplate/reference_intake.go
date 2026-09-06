package sandboxtemplate

import (
	"net/url"
	"strings"
)

const (
	TemplateReferenceStatusAccepted    TemplateReferenceStatus = "accepted"
	TemplateReferenceStatusMalformed   TemplateReferenceStatus = "malformed"
	TemplateReferenceStatusUnsupported TemplateReferenceStatus = "unsupported"
)

const (
	TemplateReferenceReasonLocalPath            TemplateReferenceReasonCode = "local_path"
	TemplateReferenceReasonMutableReference     TemplateReferenceReasonCode = "mutable_reference"
	TemplateReferenceReasonDigestPinned         TemplateReferenceReasonCode = "digest_pinned"
	TemplateReferenceReasonMalformedDigest      TemplateReferenceReasonCode = "malformed_digest"
	TemplateReferenceReasonUnsafeReference      TemplateReferenceReasonCode = "unsafe_reference"
	TemplateReferenceReasonUnsupportedReference TemplateReferenceReasonCode = "unsupported_reference"
)

type TemplateReferenceStatus string
type TemplateReferenceReasonCode string

// TemplateReferenceClassification is data-only intake metadata for a caller
// supplied sandbox template reference. It never probes local files, remote Git
// repositories, OCI registries, workers, runtimes, or sandbox daemons.
type TemplateReferenceClassification struct {
	Kind         ReferenceKind               `json:"kind,omitempty"`
	Status       TemplateReferenceStatus     `json:"status"`
	Reference    *ImmutableRef               `json:"reference,omitempty"`
	Mutable      bool                        `json:"mutable,omitempty"`
	DigestPinned bool                        `json:"digestPinned,omitempty"`
	ReasonCode   TemplateReferenceReasonCode `json:"reasonCode,omitempty"`
}

// ClassifyTemplateReference classifies local path, HTTPS Git URL, and
// registry-qualified OCI artifact references into safe internal metadata. Local
// paths are accepted as caller input but are represented without copying the
// raw path into Reference.
func ClassifyTemplateReference(input string) TemplateReferenceClassification {
	value := strings.TrimSpace(input)
	if value == "" {
		return unsupportedTemplateReference("", TemplateReferenceReasonUnsupportedReference)
	}
	if classification, ok := classifyTemplateGitReference(value); ok {
		return classification
	}
	if classification, ok := classifyTemplateOCIArtifactReference(value); ok {
		return classification
	}
	if templateReferenceLooksLocalPath(value) {
		return acceptedTemplateReference(ReferenceKindLocal, "", nil, TemplateReferenceReasonLocalPath)
	}
	return unsupportedTemplateReference("", TemplateReferenceReasonUnsupportedReference)
}

func classifyTemplateGitReference(value string) (TemplateReferenceClassification, bool) {
	if !strings.HasPrefix(strings.ToLower(value), "https://") {
		return TemplateReferenceClassification{}, false
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path == "" || parsed.Path == "/" {
		return unsupportedTemplateReference(ReferenceKindGit, TemplateReferenceReasonUnsupportedReference), true
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || unsafeFreeText(value) {
		return unsupportedTemplateReference(ReferenceKindGit, TemplateReferenceReasonUnsafeReference), true
	}
	if !strings.HasSuffix(strings.ToLower(parsed.Path), ".git") {
		return unsupportedTemplateReference(ReferenceKindGit, TemplateReferenceReasonUnsupportedReference), true
	}

	sanitizedURL := url.URL{
		Scheme: "https",
		Host:   strings.ToLower(parsed.Host),
		Path:   parsed.Path,
	}
	ref := sanitizedURL.String()
	if !safeReferenceValue(ref, ReferenceKindGit) {
		return unsupportedTemplateReference(ReferenceKindGit, TemplateReferenceReasonUnsafeReference), true
	}
	return acceptedTemplateReference(ReferenceKindGit, ref, nil, TemplateReferenceReasonMutableReference), true
}

func classifyTemplateOCIArtifactReference(value string) (TemplateReferenceClassification, bool) {
	raw := value
	explicitOCI := strings.HasPrefix(strings.ToLower(value), "oci://")
	if explicitOCI {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "oci" || parsed.Host == "" || parsed.Path == "" || parsed.Path == "/" {
			return unsupportedTemplateReference(ReferenceKindOCIArtifact, TemplateReferenceReasonUnsupportedReference), true
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || unsafeFreeText(value) {
			return unsupportedTemplateReference(ReferenceKindOCIArtifact, TemplateReferenceReasonUnsafeReference), true
		}
		raw = strings.ToLower(parsed.Host) + parsed.Path
	} else if strings.Contains(value, "://") {
		return TemplateReferenceClassification{}, false
	}

	if strings.ContainsAny(raw, "?#") || strings.Contains(raw, "\\") || unsafeFreeText(raw) {
		if explicitOCI || templateReferenceFirstSegmentLooksRegistry(raw) {
			return unsupportedTemplateReference(ReferenceKindOCIArtifact, TemplateReferenceReasonUnsafeReference), true
		}
		return TemplateReferenceClassification{}, false
	}

	ref := raw
	var digest *DigestMetadata
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		parsedDigest, ok := parseTemplateReferenceDigest(raw[at+1:])
		if !ok {
			if explicitOCI || templateReferenceFirstSegmentLooksRegistry(raw) {
				return unsupportedTemplateReference(ReferenceKindOCIArtifact, TemplateReferenceReasonMalformedDigest), true
			}
			return TemplateReferenceClassification{}, false
		}
		digest = parsedDigest
		ref = raw[:at]
	}

	if !templateReferenceLooksOCIArtifact(ref, digest != nil) {
		if explicitOCI || templateReferenceFirstSegmentLooksRegistry(raw) {
			return unsupportedTemplateReference(ReferenceKindOCIArtifact, TemplateReferenceReasonUnsupportedReference), true
		}
		return TemplateReferenceClassification{}, false
	}
	if !safeReferenceValue(ref, ReferenceKindOCIArtifact) {
		return unsupportedTemplateReference(ReferenceKindOCIArtifact, TemplateReferenceReasonUnsafeReference), true
	}
	reason := TemplateReferenceReasonMutableReference
	if digest != nil {
		reason = TemplateReferenceReasonDigestPinned
	}
	return acceptedTemplateReference(ReferenceKindOCIArtifact, ref, digest, reason), true
}

func acceptedTemplateReference(kind ReferenceKind, ref string, digest *DigestMetadata, reason TemplateReferenceReasonCode) TemplateReferenceClassification {
	reference := &ImmutableRef{
		Kind:   kind,
		Ref:    strings.TrimSpace(ref),
		Digest: cloneTemplateReferenceDigest(digest),
	}
	digestPinned := ReferenceDigestPinned(reference)
	return TemplateReferenceClassification{
		Kind:         kind,
		Status:       TemplateReferenceStatusAccepted,
		Reference:    reference,
		Mutable:      !digestPinned,
		DigestPinned: digestPinned,
		ReasonCode:   reason,
	}
}

func unsupportedTemplateReference(kind ReferenceKind, reason TemplateReferenceReasonCode) TemplateReferenceClassification {
	status := TemplateReferenceStatusUnsupported
	if reason == TemplateReferenceReasonMalformedDigest {
		status = TemplateReferenceStatusMalformed
	}
	return TemplateReferenceClassification{
		Kind:       kind,
		Status:     status,
		ReasonCode: reason,
	}
}

func templateReferenceLooksLocalPath(value string) bool {
	lower := strings.ToLower(value)
	if strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") ||
		strings.HasPrefix(value, "~/") ||
		strings.Contains(value, "\\") {
		return true
	}
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json") {
		return !templateReferenceFirstSegmentLooksRegistry(value)
	}
	return false
}

func templateReferenceFirstSegmentLooksRegistry(value string) bool {
	slash := strings.Index(value, "/")
	if slash <= 0 {
		return false
	}
	first := value
	first = first[:slash]
	first = strings.ToLower(strings.TrimSpace(first))
	return first == "localhost" || strings.Contains(first, ".") || strings.Contains(first, ":")
}

func templateReferenceLooksOCIArtifact(ref string, digestPinned bool) bool {
	if ref == "" || strings.HasPrefix(ref, "/") || strings.Contains(ref, "//") || strings.Contains(ref, "@") {
		return false
	}
	slash := strings.Index(ref, "/")
	if slash <= 0 || slash == len(ref)-1 {
		return false
	}
	host := ref[:slash]
	path := ref[slash+1:]
	if !templateReferenceFirstSegmentLooksRegistry(ref) || !templateReferenceSafeRegistryHost(host) || !templateReferenceSafeOCIPath(path) {
		return false
	}
	if digestPinned {
		return true
	}
	last := path
	if slash := strings.LastIndex(last, "/"); slash >= 0 {
		last = last[slash+1:]
	}
	return strings.Contains(last, ":")
}

func templateReferenceSafeRegistryHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "@/?#\\") {
		return false
	}
	return allRunes(host, func(ch rune) bool {
		return (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '-' || ch == ':'
	})
}

func templateReferenceSafeOCIPath(value string) bool {
	if value == "" || strings.Contains(value, "//") {
		return false
	}
	return allRunes(value, func(ch rune) bool {
		return (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '_' || ch == '-' || ch == '/' || ch == ':'
	})
}

func parseTemplateReferenceDigest(value string) (*DigestMetadata, bool) {
	algorithm, digestValue, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok {
		return nil, false
	}
	digest := &DigestMetadata{
		Algorithm: DigestAlgorithm(strings.ToLower(strings.TrimSpace(algorithm))),
		Value:     strings.ToLower(strings.TrimSpace(digestValue)),
	}
	if !ReferenceDigestPinned(&ImmutableRef{Digest: digest}) {
		return nil, false
	}
	return digest, true
}

func cloneTemplateReferenceDigest(digest *DigestMetadata) *DigestMetadata {
	if digest == nil {
		return nil
	}
	out := *digest
	return &out
}
