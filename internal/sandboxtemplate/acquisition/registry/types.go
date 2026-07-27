// Package registry implements bounded OCI Distribution acquisition for HAL
// sandbox templates.
package registry

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

const (
	MediaTypeOCIManifest      = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeTemplateArtifact = "application/vnd.hal.sandbox-template.v1"
	MediaTypeOCIEmptyConfig   = "application/vnd.oci.empty.v1+json"
	MediaTypeTemplateYAML     = "application/vnd.hal.sandbox-template.v1+yaml"
	MediaTypeTemplateJSON     = "application/vnd.hal.sandbox-template.v1+json"

	DefaultMaxManifestBytes       = 1 << 20
	DefaultMaxLayerBytes          = 4 << 20
	DefaultMaxChallengeBytes      = 8 << 10
	DefaultMaxTokenBytes          = 64 << 10
	DefaultMaxResponseHeaderBytes = 32 << 10
	DefaultMaxRedirects           = 3
	DefaultRequestTimeout         = 30 * time.Second
)

type ErrorCode string

const (
	ErrorCodeInvalidReference               ErrorCode = "invalid_reference"
	ErrorCodeRequestCanceled                ErrorCode = "request_canceled"
	ErrorCodeRequestTimeout                 ErrorCode = "request_timeout"
	ErrorCodeRegistryUnavailable            ErrorCode = "registry_unavailable"
	ErrorCodeAddressRejected                ErrorCode = "address_rejected"
	ErrorCodeAuthenticationFailed           ErrorCode = "authentication_failed"
	ErrorCodeAuthenticationChallengeInvalid ErrorCode = "authentication_challenge_invalid"
	ErrorCodeAuthenticationResponseOversize ErrorCode = "authentication_response_oversize"
	ErrorCodeResponseHeadersOversize        ErrorCode = "response_headers_oversize"
	ErrorCodeResponseHeadersInvalid         ErrorCode = "response_headers_invalid"
	ErrorCodeRedirectRejected               ErrorCode = "redirect_rejected"
	ErrorCodeManifestOversize               ErrorCode = "manifest_oversize"
	ErrorCodeManifestMediaTypeUnsupported   ErrorCode = "manifest_media_type_unsupported"
	ErrorCodeManifestInvalid                ErrorCode = "manifest_invalid"
	ErrorCodeManifestDigestMismatch         ErrorCode = "manifest_digest_mismatch"
	ErrorCodeTagMutated                     ErrorCode = "tag_mutated"
	ErrorCodeArtifactTypeUnsupported        ErrorCode = "artifact_type_unsupported"
	ErrorCodeLayerCountInvalid              ErrorCode = "layer_count_invalid"
	ErrorCodeLayerMediaTypeUnsupported      ErrorCode = "layer_media_type_unsupported"
	ErrorCodeLayerOversize                  ErrorCode = "layer_oversize"
	ErrorCodeLayerDigestMismatch            ErrorCode = "layer_digest_mismatch"
	ErrorCodeCacheInvalid                   ErrorCode = "cache_invalid"
	ErrorCodeCachePublishFailed             ErrorCode = "cache_publish_failed"
)

type Error struct {
	Code ErrorCode
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func coded(code ErrorCode, err error) *Error {
	return &Error{Code: code, Err: err}
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Credential struct {
	Username string
	Password string
}

type CredentialRequest struct {
	RegistryOrigin string
	TokenOrigin    string
}

type CredentialProvider interface {
	LookupCredential(context.Context, CredentialRequest) (Credential, error)
}

type TokenOriginPolicy struct {
	Origin  string
	Service string
}

type RequestOriginKind string

const (
	RequestOriginRegistry     RequestOriginKind = "registry"
	RequestOriginToken        RequestOriginKind = "token"
	RequestOriginBlobRedirect RequestOriginKind = "blob_redirect"
)

type RequestOriginValidationRequest struct {
	Kind   RequestOriginKind
	Origin string
}

type OriginValidator interface {
	ValidateRequestOrigin(context.Context, RequestOriginValidationRequest) error
}

type Options struct {
	Client                     HTTPDoer
	AllowedRegistryOrigins     []string
	PlainHTTPOrigins           []string
	AllowedTokenOrigins        map[string]TokenOriginPolicy
	AllowedBlobOrigins         map[string][]string
	PreemptiveBasicAuthOrigins []string
	CredentialProvider         CredentialProvider
	OriginValidator            OriginValidator
	Cache                      Cache
	RequestTimeout             time.Duration
	MaxManifestBytes           int
	MaxLayerBytes              int
	MaxChallengeBytes          int
	MaxTokenBytes              int
	MaxResponseHeaderBytes     int
	MaxRedirects               int
}

type Resolver struct {
	client                 HTTPDoer
	registryOrigins        map[string]struct{}
	plainOrigins           map[string]struct{}
	tokenOrigins           map[string]TokenOriginPolicy
	blobOrigins            map[string]map[string]struct{}
	preemptiveBasicOrigins map[string]struct{}
	credentialProvider     CredentialProvider
	originValidator        OriginValidator
	cache                  Cache
	requestTimeout         time.Duration
	maxManifestBytes       int
	maxLayerBytes          int
	maxChallengeBytes      int
	maxTokenBytes          int
	maxResponseHeaderBytes int
	maxRedirects           int
	fetches                fetchGroup
}

var _ acquisition.OCIArtifactResolver = (*Resolver)(nil)

func NewResolver(options Options) (*Resolver, error) {
	if options.Client == nil {
		return nil, errors.New("registry HTTP client is required")
	}
	registryOrigins, err := normalizeOriginSet(options.AllowedRegistryOrigins, options.PlainHTTPOrigins)
	if err != nil || len(registryOrigins) == 0 {
		return nil, errors.New("registry origin allowlist is invalid")
	}
	plainOrigins, err := normalizeExactOrigins(options.PlainHTTPOrigins, true)
	if err != nil {
		return nil, errors.New("plain HTTP origin allowlist is invalid")
	}
	tokenOrigins := make(map[string]TokenOriginPolicy, len(options.AllowedTokenOrigins))
	for key, policy := range options.AllowedTokenOrigins {
		registryOrigin, originErr := normalizeOrigin(key, containsOrigin(plainOrigins, key))
		if originErr != nil {
			return nil, errors.New("token registry origin policy is invalid")
		}
		tokenOrigin, originErr := normalizeOrigin(policy.Origin, containsString(options.PlainHTTPOrigins, policy.Origin))
		if originErr != nil {
			return nil, errors.New("token origin policy is invalid")
		}
		tokenOrigins[registryOrigin] = TokenOriginPolicy{Origin: tokenOrigin, Service: policy.Service}
	}
	blobOrigins := make(map[string]map[string]struct{}, len(options.AllowedBlobOrigins))
	for key, values := range options.AllowedBlobOrigins {
		registryOrigin, originErr := normalizeOrigin(key, containsOrigin(plainOrigins, key))
		if originErr != nil {
			return nil, errors.New("blob registry origin policy is invalid")
		}
		set, originErr := normalizeExactOrigins(values, false)
		if originErr != nil {
			return nil, errors.New("blob origin policy is invalid")
		}
		blobOrigins[registryOrigin] = set
	}
	timeout := options.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &Resolver{
		client:                 options.Client,
		registryOrigins:        registryOrigins,
		plainOrigins:           plainOrigins,
		tokenOrigins:           tokenOrigins,
		blobOrigins:            blobOrigins,
		preemptiveBasicOrigins: stringSet(options.PreemptiveBasicAuthOrigins),
		credentialProvider:     options.CredentialProvider,
		originValidator:        options.OriginValidator,
		cache:                  options.Cache,
		requestTimeout:         timeout,
		maxManifestBytes:       defaultInt(options.MaxManifestBytes, DefaultMaxManifestBytes),
		maxLayerBytes:          defaultInt(options.MaxLayerBytes, DefaultMaxLayerBytes),
		maxChallengeBytes:      defaultInt(options.MaxChallengeBytes, DefaultMaxChallengeBytes),
		maxTokenBytes:          defaultInt(options.MaxTokenBytes, DefaultMaxTokenBytes),
		maxResponseHeaderBytes: defaultInt(options.MaxResponseHeaderBytes, DefaultMaxResponseHeaderBytes),
		maxRedirects:           defaultInt(options.MaxRedirects, DefaultMaxRedirects),
	}, nil
}

func defaultInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsOrigin(origins map[string]struct{}, value string) bool {
	_, ok := origins[value]
	return ok
}
