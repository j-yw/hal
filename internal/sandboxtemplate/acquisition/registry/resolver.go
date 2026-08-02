package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

type resolvedManifest struct {
	bytes       []byte
	digest      string
	layer       descriptor
	contentType string
}

func (r *Resolver) ResolveOCIArtifact(ctx context.Context, request acquisition.OCIArtifactResolveRequest) (acquisition.OCIArtifactResolveResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return acquisition.OCIArtifactResolveResult{}, requestContextError(err)
	}
	reference, err := r.parseReference(request.Reference)
	if err != nil {
		return acquisition.OCIArtifactResolveResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.requestTimeout)
	defer cancel()

	first, err := r.resolveManifest(ctx, reference)
	if err != nil {
		return acquisition.OCIArtifactResolveResult{}, err
	}
	layerBytes, cacheHit, err := r.resolveLayer(ctx, reference, first)
	if err != nil {
		return acquisition.OCIArtifactResolveResult{}, err
	}
	if !cacheHit {
		defer r.fetches.forget(first.digest)
	}
	if reference.tagged {
		second, resolveErr := r.resolveManifest(ctx, reference)
		if resolveErr != nil {
			return acquisition.OCIArtifactResolveResult{}, resolveErr
		}
		if second.digest != first.digest {
			return acquisition.OCIArtifactResolveResult{}, coded(ErrorCodeTagMutated, nil)
		}
	}
	if r.cache != nil && !cacheHit {
		if err := r.cache.Store(ctx, CacheEntry{
			ManifestDigest: first.digest,
			LayerDigest:    first.layer.Digest,
			MediaType:      first.layer.MediaType,
			LayerBytes:     layerBytes,
		}); err != nil {
			return acquisition.OCIArtifactResolveResult{}, normalizeRegistryError(ctx, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return acquisition.OCIArtifactResolveResult{}, requestContextError(err)
	}
	format := sandboxtemplate.FormatYAML
	if first.layer.MediaType == MediaTypeTemplateJSON {
		format = sandboxtemplate.FormatJSON
	}
	manifestDigest := digestMetadata(first.bytes)
	layerDigest := digestMetadata(layerBytes)
	return acquisition.OCIArtifactResolveResult{
		TemplateBytes:          append([]byte(nil), layerBytes...),
		ArtifactManifestBytes:  append([]byte(nil), first.bytes...),
		Format:                 format,
		DocumentDigest:         layerDigest,
		TemplateArtifactDigest: manifestDigest,
		ReferenceDigests: []acquisition.ReferenceDigestProof{{
			Field:         "metadata.reference",
			Kind:          sandboxtemplate.ReferenceKindOCIArtifact,
			Digest:        cloneDigestMetadata(manifestDigest),
			VerifiedBytes: append([]byte(nil), first.bytes...),
		}},
		SizeBytes: int64(len(layerBytes)),
	}, nil
}

func (r *Resolver) resolveManifest(ctx context.Context, reference parsedReference) (resolvedManifest, error) {
	response, err := r.get(ctx, requestSpec{
		rawURL:         manifestURL(reference),
		accept:         MediaTypeOCIManifest,
		kind:           RequestOriginRegistry,
		registryOrigin: reference.origin,
		reference:      reference,
	})
	if err != nil {
		return resolvedManifest{}, err
	}
	defer response.Body.Close()
	if err := validateResponseHeaders(response.Header, r.maxResponseHeaderBytes); err != nil {
		return resolvedManifest{}, err
	}
	if response.StatusCode != http.StatusOK {
		return resolvedManifest{}, coded(ErrorCodeRegistryUnavailable, nil)
	}
	if !identityEncoding(response.Header.Get("Content-Encoding")) {
		return resolvedManifest{}, coded(ErrorCodeManifestInvalid, nil)
	}
	body, err := readBoundedBody(response, r.maxManifestBytes, ErrorCodeManifestOversize)
	if err != nil {
		return resolvedManifest{}, err
	}
	measured := digestString(body)
	if reference.digest != "" && measured != reference.digest {
		return resolvedManifest{}, coded(ErrorCodeManifestDigestMismatch, nil)
	}
	if header := strings.TrimSpace(response.Header.Get("Docker-Content-Digest")); header != "" {
		if !validDigest(header) || header != measured {
			return resolvedManifest{}, coded(ErrorCodeManifestDigestMismatch, nil)
		}
	}
	layer, err := decodeManifest(body, response.Header.Get("Content-Type"), r.maxLayerBytes)
	if err != nil {
		return resolvedManifest{}, err
	}
	return resolvedManifest{
		bytes:       body,
		digest:      measured,
		layer:       layer,
		contentType: response.Header.Get("Content-Type"),
	}, nil
}

func (r *Resolver) resolveLayer(ctx context.Context, reference parsedReference, manifest resolvedManifest) ([]byte, bool, error) {
	lookup := CacheLookup{
		ManifestDigest: manifest.digest,
		LayerDigest:    manifest.layer.Digest,
		MediaType:      manifest.layer.MediaType,
		SizeBytes:      manifest.layer.Size,
	}
	if r.cache != nil {
		data, hit, err := r.cache.Load(ctx, lookup)
		if err != nil {
			return nil, false, normalizeRegistryError(ctx, err)
		}
		if hit {
			return data, true, nil
		}
	}
	data, err := r.fetches.do(ctx, manifest.digest, func(fetchCtx context.Context) ([]byte, error) {
		if r.cache != nil {
			cached, hit, cacheErr := r.cache.Load(fetchCtx, lookup)
			if cacheErr != nil {
				return nil, normalizeRegistryError(ctx, cacheErr)
			}
			if hit {
				return cached, nil
			}
		}
		return r.fetchLayer(fetchCtx, reference, manifest.layer)
	})
	return data, false, err
}

func (r *Resolver) fetchLayer(ctx context.Context, reference parsedReference, layer descriptor) ([]byte, error) {
	response, err := r.get(ctx, requestSpec{
		rawURL:            blobURL(reference, layer.Digest),
		accept:            layer.MediaType,
		kind:              RequestOriginRegistry,
		registryOrigin:    reference.origin,
		reference:         reference,
		allowBlobRedirect: true,
	})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := validateResponseHeaders(response.Header, r.maxResponseHeaderBytes); err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, coded(ErrorCodeRegistryUnavailable, nil)
	}
	if !identityEncoding(response.Header.Get("Content-Encoding")) {
		return nil, coded(ErrorCodeLayerDigestMismatch, nil)
	}
	contentType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || contentType != layer.MediaType {
		return nil, coded(ErrorCodeLayerMediaTypeUnsupported, nil)
	}
	data, err := readBoundedBody(response, r.maxLayerBytes, ErrorCodeLayerOversize)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != layer.Size {
		return nil, coded(ErrorCodeLayerDigestMismatch, nil)
	}
	if digestString(data) != layer.Digest {
		return nil, coded(ErrorCodeLayerDigestMismatch, nil)
	}
	return data, nil
}

type requestSpec struct {
	rawURL            string
	accept            string
	kind              RequestOriginKind
	registryOrigin    string
	reference         parsedReference
	allowBlobRedirect bool
}

func (r *Resolver) get(ctx context.Context, spec requestSpec) (*http.Response, error) {
	authorization := ""
	if _, ok := r.preemptiveBasicOrigins[spec.registryOrigin]; ok {
		credential, err := r.lookupCredential(ctx, spec.registryOrigin, "")
		if err != nil {
			return nil, err
		}
		authorization = basicAuthorization(credential)
	}
	response, err := r.doRedirecting(ctx, spec, authorization)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusUnauthorized {
		return response, nil
	}
	challenges := response.Header.Values("WWW-Authenticate")
	_ = response.Body.Close()
	if len(challenges) != 1 || len(challenges[0]) > r.maxChallengeBytes {
		return nil, coded(ErrorCodeAuthenticationChallengeInvalid, nil)
	}
	authorization, err = r.authorizationForChallenge(ctx, spec, challenges[0])
	if err != nil {
		return nil, err
	}
	response, err = r.doRedirecting(ctx, spec, authorization)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		_ = response.Body.Close()
		return nil, coded(ErrorCodeAuthenticationFailed, nil)
	}
	return response, nil
}

func (r *Resolver) doRedirecting(ctx context.Context, spec requestSpec, authorization string) (*http.Response, error) {
	current := spec.rawURL
	currentAuthorization := authorization
	for hop := 0; ; hop++ {
		kind := spec.kind
		if hop > 0 && spec.allowBlobRedirect {
			kind = RequestOriginBlobRedirect
		}
		if err := r.validateRequestOrigin(ctx, kind, current); err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, coded(ErrorCodeInvalidReference, nil)
		}
		request.Header.Set("Accept", spec.accept)
		request.Header.Set("Accept-Encoding", "identity")
		if currentAuthorization != "" {
			request.Header.Set("Authorization", currentAuthorization)
		}
		response, err := r.client.Do(request)
		if err != nil {
			return nil, requestOrRegistryError(ctx, err)
		}
		if err := validateResponseHeaders(response.Header, r.maxResponseHeaderBytes); err != nil {
			_ = response.Body.Close()
			return nil, err
		}
		if !isRedirect(response.StatusCode) {
			return response, nil
		}
		_ = response.Body.Close()
		if hop >= r.maxRedirects {
			return nil, coded(ErrorCodeRedirectRejected, nil)
		}
		locations := response.Header.Values("Location")
		if len(locations) != 1 {
			return nil, coded(ErrorCodeRedirectRejected, nil)
		}
		location := locations[0]
		next, crossOrigin, err := r.validateRedirect(spec, current, location)
		if err != nil {
			return nil, err
		}
		if crossOrigin {
			currentAuthorization = ""
		}
		current = next
	}
}

func (r *Resolver) validateRedirect(spec requestSpec, current, location string) (string, bool, error) {
	base, baseErr := url.Parse(current)
	nextURL, nextErr := url.Parse(location)
	if baseErr != nil || nextErr != nil || location == "" ||
		!unambiguousRedirectURL(base, current) ||
		!unambiguousRedirectURL(nextURL, location) {
		return "", false, coded(ErrorCodeRedirectRejected, nil)
	}
	nextURL = base.ResolveReference(nextURL)
	if !unambiguousRedirectURL(nextURL, nextURL.String()) ||
		nextURL.User != nil || nextURL.Fragment != "" || nextURL.RawQuery != "" ||
		(nextURL.Scheme != "https" && !containsOrigin(r.plainOrigins, nextURL.Scheme+"://"+nextURL.Host)) {
		return "", false, coded(ErrorCodeRedirectRejected, nil)
	}
	currentOrigin, _ := originForURL(current)
	nextOrigin, err := originForURL(nextURL.String())
	if err != nil {
		return "", false, err
	}
	crossOrigin := currentOrigin != nextOrigin
	if !crossOrigin {
		return nextURL.String(), false, nil
	}
	if !spec.allowBlobRedirect {
		return "", false, coded(ErrorCodeRedirectRejected, nil)
	}
	allowed := r.blobOrigins[spec.registryOrigin]
	if _, ok := allowed[nextOrigin]; !ok {
		return "", false, coded(ErrorCodeRedirectRejected, nil)
	}
	return nextURL.String(), true, nil
}

func unambiguousRedirectURL(parsed *url.URL, raw string) bool {
	if parsed == nil || parsed.RawPath != "" || parsed.Opaque != "" ||
		strings.ContainsAny(raw, "\\\r\n\t") {
		return false
	}
	for _, char := range parsed.Path {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func (r *Resolver) authorizationForChallenge(ctx context.Context, spec requestSpec, challenge string) (string, error) {
	scheme, parameters, err := parseChallenge(challenge)
	if err != nil {
		return "", coded(ErrorCodeAuthenticationChallengeInvalid, nil)
	}
	switch scheme {
	case "basic":
		credential, err := r.lookupCredential(ctx, spec.registryOrigin, "")
		if err != nil {
			return "", err
		}
		return basicAuthorization(credential), nil
	case "bearer":
		policy, ok := r.tokenOrigins[spec.registryOrigin]
		if !ok {
			return "", coded(ErrorCodeAuthenticationChallengeInvalid, nil)
		}
		realm := parameters["realm"]
		service := parameters["service"]
		scope := parameters["scope"]
		serviceAllowed := service == canonicalService(spec.reference) ||
			(policy.Service != "" && service == policy.Service)
		realmURL, parseErr := url.Parse(realm)
		realmOrigin, originErr := originForURL(realm)
		if parseErr != nil || originErr != nil || realmURL.User != nil || realmURL.Fragment != "" ||
			realmOrigin != policy.Origin || realmURL.Scheme != "https" ||
			!serviceAllowed ||
			scope != canonicalScope(spec.reference) {
			return "", coded(ErrorCodeAuthenticationChallengeInvalid, nil)
		}
		credential, err := r.lookupCredential(ctx, spec.registryOrigin, realmOrigin)
		if err != nil {
			return "", err
		}
		return r.fetchBearerToken(ctx, realmURL, service, scope, credential)
	default:
		return "", coded(ErrorCodeAuthenticationChallengeInvalid, nil)
	}
}

func (r *Resolver) fetchBearerToken(ctx context.Context, realm *url.URL, service, scope string, credential Credential) (string, error) {
	query := realm.Query()
	if len(query) != 0 {
		return "", coded(ErrorCodeAuthenticationChallengeInvalid, nil)
	}
	query.Set("service", service)
	query.Set("scope", scope)
	realm.RawQuery = query.Encode()
	if err := r.validateRequestOrigin(ctx, RequestOriginToken, realm.String()); err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", coded(ErrorCodeAuthenticationChallengeInvalid, nil)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	if credential.Username != "" || credential.Password != "" {
		request.Header.Set("Authorization", basicAuthorization(credential))
	}
	response, err := r.client.Do(request)
	if err != nil {
		return "", requestOrRegistryError(ctx, err)
	}
	defer response.Body.Close()
	if err := validateResponseHeaders(response.Header, r.maxResponseHeaderBytes); err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", coded(ErrorCodeAuthenticationFailed, nil)
	}
	tokenMediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || tokenMediaType != "application/json" {
		return "", coded(ErrorCodeAuthenticationFailed, nil)
	}
	if !identityEncoding(response.Header.Get("Content-Encoding")) {
		return "", coded(ErrorCodeAuthenticationFailed, nil)
	}
	body, err := readBoundedBody(response, r.maxTokenBytes, ErrorCodeAuthenticationResponseOversize)
	if err != nil {
		return "", err
	}
	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tokenResponse); err != nil || ensureJSONEOF(decoder) != nil {
		return "", coded(ErrorCodeAuthenticationFailed, nil)
	}
	token := tokenResponse.Token
	if tokenResponse.Token != "" && tokenResponse.AccessToken != "" && tokenResponse.Token != tokenResponse.AccessToken {
		return "", coded(ErrorCodeAuthenticationFailed, nil)
	}
	if token == "" {
		token = tokenResponse.AccessToken
	}
	if token == "" || len(token) > r.maxTokenBytes || strings.ContainsAny(token, "\r\n") {
		return "", coded(ErrorCodeAuthenticationFailed, nil)
	}
	return "Bearer " + token, nil
}

func (r *Resolver) lookupCredential(ctx context.Context, registryOrigin, tokenOrigin string) (Credential, error) {
	if r.credentialProvider == nil {
		return Credential{}, coded(ErrorCodeAuthenticationFailed, nil)
	}
	credential, err := r.credentialProvider.LookupCredential(ctx, CredentialRequest{
		RegistryOrigin: registryOrigin,
		TokenOrigin:    tokenOrigin,
	})
	if err != nil {
		return Credential{}, coded(ErrorCodeAuthenticationFailed, nil)
	}
	if strings.ContainsAny(credential.Username+credential.Password, "\r\n") {
		return Credential{}, coded(ErrorCodeAuthenticationFailed, nil)
	}
	return credential, nil
}

func (r *Resolver) validateRequestOrigin(ctx context.Context, kind RequestOriginKind, rawURL string) error {
	origin, err := originForURL(rawURL)
	if err != nil {
		return err
	}
	if r.originValidator != nil {
		if err := r.originValidator.ValidateRequestOrigin(ctx, RequestOriginValidationRequest{Kind: kind, Origin: origin}); err != nil {
			return coded(ErrorCodeAddressRejected, err)
		}
	}
	return nil
}

func parseChallenge(value string) (string, map[string]string, error) {
	value = strings.TrimSpace(value)
	space := strings.IndexByte(value, ' ')
	if space <= 0 {
		return "", nil, errors.New("challenge is invalid")
	}
	scheme := strings.ToLower(value[:space])
	if scheme == "basic" {
		parameter := strings.TrimSpace(value[space+1:])
		if !strings.HasPrefix(strings.ToLower(parameter), "realm=") || strings.Contains(parameter, ",") {
			return "", nil, errors.New("basic challenge is invalid")
		}
		rawRealm := strings.TrimSpace(parameter[len("realm="):])
		if len(rawRealm) < 2 || rawRealm[0] != '"' || rawRealm[len(rawRealm)-1] != '"' {
			return "", nil, errors.New("basic challenge is invalid")
		}
		realm, err := strconv.Unquote(rawRealm)
		if err != nil || realm == "" {
			return "", nil, errors.New("basic challenge is invalid")
		}
		return scheme, map[string]string{}, nil
	}
	if scheme != "bearer" {
		return "", nil, errors.New("challenge scheme is invalid")
	}
	parameters := make(map[string]string)
	for _, part := range splitChallengeParameters(value[space+1:]) {
		equal := strings.IndexByte(part, '=')
		if equal <= 0 {
			return "", nil, errors.New("challenge parameter is invalid")
		}
		key := strings.ToLower(strings.TrimSpace(part[:equal]))
		raw := strings.TrimSpace(part[equal+1:])
		if _, exists := parameters[key]; exists || (key != "realm" && key != "service" && key != "scope") ||
			len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
			return "", nil, errors.New("challenge parameter is invalid")
		}
		decoded, err := strconv.Unquote(raw)
		if err != nil {
			return "", nil, err
		}
		parameters[key] = decoded
	}
	if len(parameters) != 3 {
		return "", nil, errors.New("challenge parameters are incomplete")
	}
	return scheme, parameters, nil
}

func splitChallengeParameters(value string) []string {
	var out []string
	start := 0
	quoted := false
	escaped := false
	for index, char := range value {
		switch {
		case escaped:
			escaped = false
		case char == '\\' && quoted:
			escaped = true
		case char == '"':
			quoted = !quoted
		case char == ',' && !quoted:
			out = append(out, strings.TrimSpace(value[start:index]))
			start = index + 1
		}
	}
	out = append(out, strings.TrimSpace(value[start:]))
	return out
}

func validateResponseHeaders(header http.Header, max int) error {
	total := 0
	for key, values := range header {
		if !validHTTPHeaderName(key) {
			return coded(ErrorCodeResponseHeadersInvalid, nil)
		}
		total += len(key)
		for _, value := range values {
			if !validHTTPHeaderValue(value) {
				return coded(ErrorCodeResponseHeadersInvalid, nil)
			}
			total += len(value)
		}
		if total > max {
			return coded(ErrorCodeResponseHeadersOversize, nil)
		}
	}
	return nil
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validHTTPHeaderValue(value string) bool {
	for _, char := range value {
		if char == '\t' {
			continue
		}
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func readBoundedBody(response *http.Response, max int, code ErrorCode) ([]byte, error) {
	if response.ContentLength > int64(max) {
		return nil, coded(code, nil)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(max)+1))
	if err != nil {
		return nil, coded(ErrorCodeRegistryUnavailable, err)
	}
	if len(data) > max {
		return nil, coded(code, nil)
	}
	return data, nil
}

func identityEncoding(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "identity"
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func basicAuthorization(credential Credential) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credential.Username+":"+credential.Password))
}

func digestString(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestMetadata(data []byte) *sandboxtemplate.DigestMetadata {
	sum := sha256.Sum256(data)
	return &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     hex.EncodeToString(sum[:]),
	}
}

func cloneDigestMetadata(digest *sandboxtemplate.DigestMetadata) *sandboxtemplate.DigestMetadata {
	if digest == nil {
		return nil
	}
	return &sandboxtemplate.DigestMetadata{Algorithm: digest.Algorithm, Value: digest.Value}
}

func normalizeRegistryError(ctx context.Context, err error) error {
	var registryErr *Error
	if errors.As(err, &registryErr) {
		return registryErr
	}
	return requestOrRegistryError(ctx, err)
}
