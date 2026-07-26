package registry

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

var (
	repositoryComponentPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	tagPattern                 = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	sha256Pattern              = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type parsedReference struct {
	origin     string
	repository string
	selector   string
	tagged     bool
	digest     string
}

func (r *Resolver) parseReference(reference sandboxtemplate.ImmutableRef) (parsedReference, error) {
	if reference.Kind != "" && reference.Kind != sandboxtemplate.ReferenceKindOCIArtifact {
		return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
	}
	raw := reference.Ref
	authorityLength := authorityEnd(raw)
	if raw == "" || strings.TrimSpace(raw) != raw || raw[:authorityLength] != strings.ToLower(raw[:authorityLength]) {
		return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
	}
	if strings.ContainsAny(raw, `\?#@%`) || strings.Contains(raw, "://") {
		return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
	}
	for _, char := range raw {
		if unicode.IsControl(char) || unicode.IsSpace(char) {
			return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
		}
	}
	slash := strings.IndexByte(raw, '/')
	if slash <= 0 || slash == len(raw)-1 {
		return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
	}
	authority := raw[:slash]
	remainder := raw[slash+1:]
	if strings.Contains(remainder, "//") {
		return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
	}
	components := strings.Split(remainder, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
		}
	}

	origin := ""
	for allowed := range r.registryOrigins {
		parsed, _ := url.Parse(allowed)
		if parsed != nil && parsed.Host == authority {
			origin = allowed
			break
		}
	}
	if origin == "" {
		return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
	}

	result := parsedReference{origin: origin}
	if reference.Digest != nil {
		if reference.Digest.Algorithm != sandboxtemplate.DigestAlgorithmSHA256 ||
			!sha256Pattern.MatchString(reference.Digest.Value) {
			return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
		}
		result.repository = remainder
		result.digest = "sha256:" + reference.Digest.Value
		result.selector = result.digest
	} else {
		lastSlash := strings.LastIndexByte(remainder, '/')
		colon := strings.LastIndexByte(remainder, ':')
		if colon <= lastSlash || colon == len(remainder)-1 {
			return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
		}
		result.repository = remainder[:colon]
		result.selector = remainder[colon+1:]
		if !tagPattern.MatchString(result.selector) {
			return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
		}
		result.tagged = true
	}
	for _, component := range strings.Split(result.repository, "/") {
		if !repositoryComponentPattern.MatchString(component) {
			return parsedReference{}, coded(ErrorCodeInvalidReference, nil)
		}
	}
	return result, nil
}

func authorityEnd(raw string) int {
	if slash := strings.IndexByte(raw, '/'); slash >= 0 {
		return slash
	}
	return len(raw)
}

func normalizeOriginSet(origins, plainOrigins []string) (map[string]struct{}, error) {
	plainRaw := stringSet(plainOrigins)
	out := make(map[string]struct{}, len(origins))
	authorities := make(map[string]string, len(origins))
	for _, raw := range origins {
		normalized, err := normalizeOrigin(raw, hasRaw(plainRaw, raw))
		if err != nil {
			return nil, err
		}
		parsed, err := url.Parse(normalized)
		if err != nil {
			return nil, err
		}
		if prior, ok := authorities[parsed.Host]; ok && prior != normalized {
			return nil, errors.New("registry authority has conflicting origins")
		}
		authorities[parsed.Host] = normalized
		out[normalized] = struct{}{}
	}
	return out, nil
}

func normalizeExactOrigins(origins []string, allowPlain bool) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		normalized, err := normalizeOrigin(raw, allowPlain)
		if err != nil {
			return nil, err
		}
		out[normalized] = struct{}{}
	}
	return out, nil
}

func normalizeOrigin(raw string, allowPlain bool) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("origin is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", errors.New("origin is invalid")
	}
	if parsed.Scheme != "https" && !(allowPlain && parsed.Scheme == "http") {
		return "", errors.New("origin scheme is invalid")
	}
	if parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) {
		return "", errors.New("origin host is invalid")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", errors.New("origin host is invalid")
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number <= 0 || number > 65535 {
			return "", errors.New("origin port is invalid")
		}
	}
	if strings.ContainsAny(parsed.Host, `%\`) {
		return "", errors.New("origin host is invalid")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func hasRaw(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}

func manifestURL(reference parsedReference) string {
	return reference.origin + "/v2/" + reference.repository + "/manifests/" + url.PathEscape(reference.selector)
}

func blobURL(reference parsedReference, digest string) string {
	return reference.origin + "/v2/" + reference.repository + "/blobs/" + url.PathEscape(digest)
}

func canonicalScope(reference parsedReference) string {
	return "repository:" + reference.repository + ":pull"
}

func canonicalService(reference parsedReference) string {
	parsed, _ := url.Parse(reference.origin)
	return parsed.Host
}

func splitHostPort(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("split address: %w", err)
	}
	return host, port, nil
}
