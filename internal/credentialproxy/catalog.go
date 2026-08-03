// Package credentialproxy owns sealed credential-proxy service definitions.
package credentialproxy

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute"
)

type ServiceID string
type TLSRootPolicy string
type AuthenticationTransform string
type RedirectPolicy string
type CatalogOwner string
type EnvironmentPolicy string

const (
	ServiceIDAzureOpenAIResponsesV1 ServiceID = "azure-openai-responses-v1"

	TLSRootPolicySystem TLSRootPolicy = "system"

	AuthenticationTransformReplaceTicket AuthenticationTransform = "replace_ticket"

	RedirectPolicyDisabled RedirectPolicy = "disabled"
	RedirectPolicyFollow   RedirectPolicy = "follow"

	CatalogOwnerHostAdmin CatalogOwner = "host_admin"

	EnvironmentPolicyFixedAllowlist EnvironmentPolicy = "fixed_allowlist"
)

const (
	azureOpenAIResponsesV1LocalPath = applicationroute.CredentialHTTPV1Prefix +
		"azure-openai-responses-v1/deployments/{deployment}/responses"
	azureOpenAIResponsesV1UpstreamPath = "/openai/v1/responses"
	azureOpenAIResponsesV1QueryKey     = "api-version"
	azureOpenAIResponsesV1TicketHeader = "api-key"
	azureOpenAIResponsesV1Provider     = "azure-openai-responses"
)

var (
	ErrCatalogGenerationRequired       = errors.New("credential proxy catalog generation is required")
	ErrCatalogOwnerRequired            = errors.New("credential proxy catalog owner is required")
	ErrCatalogEmpty                    = errors.New("credential proxy catalog is empty")
	ErrServiceCollision                = errors.New("credential proxy service collision")
	ErrServiceUnknown                  = errors.New("credential proxy service unknown")
	ErrInvalidServiceDefinition        = errors.New("credential proxy service definition invalid")
	ErrLiveCatalogStateNotSerializable = errors.New("credential proxy live catalog state is not serializable")
	ErrInvalidCatalogServiceReference  = errors.New("credential proxy catalog service reference invalid")
)

type ServiceLimits struct {
	MaxRequestHeaderBytes    int64
	MaxRequestBodyBytes      int64
	MaxResponseHeaderBytes   int64
	MaxResponseBodyBytes     int64
	MaxSSEEventBytes         int64
	ReadIdleTimeout          time.Duration
	MaxRequestsPerConnection int
	MaxRetries               int
}

type SealedTLSPolicy struct {
	serverName string
	rootPolicy TLSRootPolicy
	alpn       []string
}

type SealedInvocationPolicy struct {
	provider                        string
	model                           string
	arguments                       []string
	inheritHostEnvironment          bool
	environmentPolicy               EnvironmentPolicy
	requireOwnedEmptyCodingAgentDir bool
	allowContextFiles               bool
	allowTextSkills                 bool
	transientEnvironmentKeys        []string
	clearedEnvironmentKeys          []string
}

type ServiceDefinition struct {
	serviceID                    ServiceID
	authority                    string
	port                         int
	tls                          SealedTLSPolicy
	deployment                   string
	apiVersion                   string
	methods                      []string
	localPathTemplate            string
	upstreamPathTemplate         string
	queryKey                     string
	ticketHeader                 string
	upstreamAuthenticationHeader string
	authenticationTransform      AuthenticationTransform
	requestContentTypes          []string
	responseContentTypes         []string
	redirectPolicy               RedirectPolicy
	limits                       ServiceLimits
	consumer                     SealedInvocationPolicy
}

type StaticServiceCatalog struct {
	generation string
	owner      CatalogOwner
	services   map[ServiceID]ServiceDefinition
	serviceIDs []ServiceID
}

type CatalogServiceReference struct {
	ServiceID         ServiceID `json:"serviceId"`
	CatalogGeneration string    `json:"catalogGeneration"`
}

func NewAzureOpenAIResponsesV1Definition(
	authority string,
	port int,
	tlsServerName string,
	rootPolicy TLSRootPolicy,
	deployment string,
	apiVersion string,
) (ServiceDefinition, error) {
	authority = strings.ToLower(strings.TrimSpace(authority))
	tlsServerName = strings.ToLower(strings.TrimSpace(tlsServerName))
	deployment = strings.TrimSpace(deployment)
	apiVersion = strings.TrimSpace(apiVersion)

	definition := ServiceDefinition{
		serviceID:  ServiceIDAzureOpenAIResponsesV1,
		authority:  authority,
		port:       port,
		deployment: deployment,
		apiVersion: apiVersion,
		tls: SealedTLSPolicy{
			serverName: tlsServerName,
			rootPolicy: rootPolicy,
			alpn:       []string{"http/1.1"},
		},
		methods:                      []string{"POST"},
		localPathTemplate:            azureOpenAIResponsesV1LocalPath,
		upstreamPathTemplate:         azureOpenAIResponsesV1UpstreamPath,
		queryKey:                     azureOpenAIResponsesV1QueryKey,
		ticketHeader:                 azureOpenAIResponsesV1TicketHeader,
		upstreamAuthenticationHeader: azureOpenAIResponsesV1TicketHeader,
		authenticationTransform:      AuthenticationTransformReplaceTicket,
		requestContentTypes:          []string{"application/json"},
		responseContentTypes:         []string{"application/json", "text/event-stream"},
		redirectPolicy:               RedirectPolicyDisabled,
		limits: ServiceLimits{
			MaxRequestHeaderBytes:    32 << 10,
			MaxRequestBodyBytes:      16 << 20,
			MaxResponseHeaderBytes:   32 << 10,
			MaxResponseBodyBytes:     64 << 20,
			MaxSSEEventBytes:         2 << 20,
			ReadIdleTimeout:          5 * time.Minute,
			MaxRequestsPerConnection: 1,
			MaxRetries:               0,
		},
		consumer: newAzureOpenAIResponsesInvocationPolicy(deployment),
	}
	if err := ValidateServiceDefinition(definition); err != nil {
		return ServiceDefinition{}, ErrInvalidServiceDefinition
	}
	return definition, nil
}

func NewStaticServiceCatalog(generation string, owner CatalogOwner, definitions ...ServiceDefinition) (*StaticServiceCatalog, error) {
	generation = strings.TrimSpace(generation)
	if !validCatalogIdentifier(generation) {
		return nil, ErrCatalogGenerationRequired
	}
	if owner != CatalogOwnerHostAdmin {
		return nil, ErrCatalogOwnerRequired
	}
	if len(definitions) == 0 {
		return nil, ErrCatalogEmpty
	}

	catalog := &StaticServiceCatalog{
		generation: generation,
		owner:      owner,
		services:   make(map[ServiceID]ServiceDefinition, len(definitions)),
		serviceIDs: make([]ServiceID, 0, len(definitions)),
	}
	for _, definition := range definitions {
		if err := ValidateServiceDefinition(definition); err != nil {
			return nil, ErrInvalidServiceDefinition
		}
		id := definition.ServiceID()
		if _, exists := catalog.services[id]; exists {
			return nil, ErrServiceCollision
		}
		catalog.services[id] = cloneServiceDefinition(definition)
		catalog.serviceIDs = append(catalog.serviceIDs, id)
	}
	sort.Slice(catalog.serviceIDs, func(left, right int) bool {
		return catalog.serviceIDs[left] < catalog.serviceIDs[right]
	})
	return catalog, nil
}

func ValidateServiceDefinition(definition ServiceDefinition) error {
	if definition.serviceID != ServiceIDAzureOpenAIResponsesV1 ||
		!validAuthority(definition.authority) ||
		definition.port != 443 ||
		!validAuthority(definition.tls.serverName) ||
		definition.tls.rootPolicy != TLSRootPolicySystem ||
		!equalStrings(definition.tls.alpn, []string{"http/1.1"}) ||
		!validCatalogIdentifier(definition.deployment) ||
		!validCatalogIdentifier(definition.apiVersion) ||
		!equalStrings(definition.methods, []string{"POST"}) ||
		definition.localPathTemplate != azureOpenAIResponsesV1LocalPath ||
		definition.upstreamPathTemplate != azureOpenAIResponsesV1UpstreamPath ||
		definition.queryKey != azureOpenAIResponsesV1QueryKey ||
		definition.ticketHeader != azureOpenAIResponsesV1TicketHeader ||
		definition.upstreamAuthenticationHeader != azureOpenAIResponsesV1TicketHeader ||
		definition.authenticationTransform != AuthenticationTransformReplaceTicket ||
		!equalStrings(definition.requestContentTypes, []string{"application/json"}) ||
		!equalStrings(definition.responseContentTypes, []string{"application/json", "text/event-stream"}) ||
		definition.redirectPolicy != RedirectPolicyDisabled ||
		definition.limits != azureOpenAIResponsesV1Limits() ||
		!validAzureOpenAIResponsesInvocationPolicy(definition.consumer, definition.deployment) {
		return ErrInvalidServiceDefinition
	}
	return nil
}

func ValidateCatalogServiceReference(reference CatalogServiceReference) error {
	if !validCatalogIdentifier(string(reference.ServiceID)) || !validCatalogIdentifier(reference.CatalogGeneration) {
		return ErrInvalidCatalogServiceReference
	}
	return nil
}

func (catalog *StaticServiceCatalog) Generation() string {
	if catalog == nil {
		return ""
	}
	return catalog.generation
}

func (catalog *StaticServiceCatalog) ServiceIDs() []ServiceID {
	if catalog == nil {
		return nil
	}
	return append([]ServiceID(nil), catalog.serviceIDs...)
}

func (catalog *StaticServiceCatalog) Lookup(id ServiceID) (ServiceDefinition, error) {
	if catalog == nil {
		return ServiceDefinition{}, ErrServiceUnknown
	}
	definition, ok := catalog.services[id]
	if !ok {
		return ServiceDefinition{}, ErrServiceUnknown
	}
	return cloneServiceDefinition(definition), nil
}

func (catalog *StaticServiceCatalog) SafeReference(id ServiceID) (CatalogServiceReference, error) {
	if catalog == nil {
		return CatalogServiceReference{}, ErrServiceUnknown
	}
	if _, ok := catalog.services[id]; !ok {
		return CatalogServiceReference{}, ErrServiceUnknown
	}
	return CatalogServiceReference{ServiceID: id, CatalogGeneration: catalog.generation}, nil
}

func (definition ServiceDefinition) ServiceID() ServiceID    { return definition.serviceID }
func (definition ServiceDefinition) SealedAuthority() string { return definition.authority }
func (definition ServiceDefinition) SealedPort() int         { return definition.port }
func (definition ServiceDefinition) SealedTLS() SealedTLSPolicy {
	return cloneTLSPolicy(definition.tls)
}
func (definition ServiceDefinition) SealedDeployment() string { return definition.deployment }
func (definition ServiceDefinition) SealedAPIVersion() string { return definition.apiVersion }
func (definition ServiceDefinition) AllowedMethods() []string {
	return append([]string(nil), definition.methods...)
}
func (definition ServiceDefinition) LocalPathTemplate() string { return definition.localPathTemplate }
func (definition ServiceDefinition) UpstreamPathTemplate() string {
	return definition.upstreamPathTemplate
}
func (definition ServiceDefinition) QueryKey() string     { return definition.queryKey }
func (definition ServiceDefinition) TicketHeader() string { return definition.ticketHeader }
func (definition ServiceDefinition) UpstreamAuthenticationHeader() string {
	return definition.upstreamAuthenticationHeader
}
func (definition ServiceDefinition) AuthenticationTransform() AuthenticationTransform {
	return definition.authenticationTransform
}
func (definition ServiceDefinition) RequestContentTypes() []string {
	return append([]string(nil), definition.requestContentTypes...)
}
func (definition ServiceDefinition) ResponseContentTypes() []string {
	return append([]string(nil), definition.responseContentTypes...)
}
func (definition ServiceDefinition) RedirectPolicy() RedirectPolicy { return definition.redirectPolicy }
func (definition ServiceDefinition) Limits() ServiceLimits          { return definition.limits }
func (definition ServiceDefinition) SealedInvocationPolicy() SealedInvocationPolicy {
	return cloneInvocationPolicy(definition.consumer)
}

func (policy SealedTLSPolicy) ServerName() string        { return policy.serverName }
func (policy SealedTLSPolicy) RootPolicy() TLSRootPolicy { return policy.rootPolicy }
func (policy SealedTLSPolicy) ALPN() []string            { return append([]string(nil), policy.alpn...) }

func (policy SealedInvocationPolicy) Provider() string { return policy.provider }
func (policy SealedInvocationPolicy) Model() string    { return policy.model }
func (policy SealedInvocationPolicy) Arguments() []string {
	return append([]string(nil), policy.arguments...)
}
func (policy SealedInvocationPolicy) InheritHostEnvironment() bool {
	return policy.inheritHostEnvironment
}
func (policy SealedInvocationPolicy) EnvironmentPolicy() EnvironmentPolicy {
	return policy.environmentPolicy
}
func (policy SealedInvocationPolicy) RequireOwnedEmptyCodingAgentDir() bool {
	return policy.requireOwnedEmptyCodingAgentDir
}
func (policy SealedInvocationPolicy) AllowContextFiles() bool { return policy.allowContextFiles }
func (policy SealedInvocationPolicy) AllowTextSkills() bool   { return policy.allowTextSkills }
func (policy SealedInvocationPolicy) TransientEnvironmentKeys() []string {
	return append([]string(nil), policy.transientEnvironmentKeys...)
}
func (policy SealedInvocationPolicy) ClearedEnvironmentKeys() []string {
	return append([]string(nil), policy.clearedEnvironmentKeys...)
}

func (reference CatalogServiceReference) MarshalJSON() ([]byte, error) {
	if err := ValidateCatalogServiceReference(reference); err != nil {
		return nil, ErrInvalidCatalogServiceReference
	}
	type wireReference CatalogServiceReference
	return json.Marshal(wireReference(reference))
}

func (ServiceDefinition) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (ServiceDefinition) MarshalText() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (definition ServiceDefinition) String() string {
	if definition.serviceID == ServiceIDAzureOpenAIResponsesV1 {
		return "credentialproxy.ServiceDefinition{serviceId:azure-openai-responses-v1,sealed:true}"
	}
	return "credentialproxy.ServiceDefinition{sealed:true}"
}
func (definition ServiceDefinition) GoString() string { return definition.String() }

func (SealedTLSPolicy) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (SealedTLSPolicy) MarshalText() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (SealedTLSPolicy) String() string          { return "credentialproxy.SealedTLSPolicy{sealed:true}" }
func (policy SealedTLSPolicy) GoString() string { return policy.String() }

func (SealedInvocationPolicy) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (SealedInvocationPolicy) MarshalText() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (SealedInvocationPolicy) String() string {
	return "credentialproxy.SealedInvocationPolicy{sealed:true}"
}
func (policy SealedInvocationPolicy) GoString() string { return policy.String() }

func (*StaticServiceCatalog) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (*StaticServiceCatalog) MarshalText() ([]byte, error) {
	return nil, ErrLiveCatalogStateNotSerializable
}
func (*StaticServiceCatalog) String() string {
	return "credentialproxy.StaticServiceCatalog{sealed:true}"
}
func (catalog *StaticServiceCatalog) GoString() string { return catalog.String() }

func newAzureOpenAIResponsesInvocationPolicy(deployment string) SealedInvocationPolicy {
	return SealedInvocationPolicy{
		provider: azureOpenAIResponsesV1Provider,
		model:    deployment,
		arguments: []string{
			"--provider", azureOpenAIResponsesV1Provider,
			"--model", deployment,
			"--offline",
			"--no-extensions",
			"--no-prompt-templates",
			"--no-themes",
			"--no-session",
		},
		inheritHostEnvironment:          false,
		environmentPolicy:               EnvironmentPolicyFixedAllowlist,
		requireOwnedEmptyCodingAgentDir: true,
		allowContextFiles:               true,
		allowTextSkills:                 true,
		transientEnvironmentKeys: []string{
			"AZURE_OPENAI_API_KEY",
			"AZURE_OPENAI_API_VERSION",
			"AZURE_OPENAI_BASE_URL",
			"PI_CODING_AGENT_DIR",
		},
		clearedEnvironmentKeys: []string{
			"ALL_PROXY",
			"AZURE_OPENAI_API_KEY",
			"AZURE_OPENAI_API_VERSION",
			"AZURE_OPENAI_BASE_URL",
			"AZURE_OPENAI_DEPLOYMENT_NAME_MAP",
			"AZURE_OPENAI_RESOURCE_NAME",
			"HTTPS_PROXY",
			"HTTP_PROXY",
			"NO_PROXY",
			"OPENAI_API_KEY",
			"OPENAI_BASE_URL",
		},
	}
}

func validAzureOpenAIResponsesInvocationPolicy(policy SealedInvocationPolicy, deployment string) bool {
	want := newAzureOpenAIResponsesInvocationPolicy(deployment)
	return policy.provider == want.provider &&
		policy.model == want.model &&
		equalStrings(policy.arguments, want.arguments) &&
		policy.inheritHostEnvironment == want.inheritHostEnvironment &&
		policy.environmentPolicy == want.environmentPolicy &&
		policy.requireOwnedEmptyCodingAgentDir == want.requireOwnedEmptyCodingAgentDir &&
		policy.allowContextFiles == want.allowContextFiles &&
		policy.allowTextSkills == want.allowTextSkills &&
		equalStrings(policy.transientEnvironmentKeys, want.transientEnvironmentKeys) &&
		equalStrings(policy.clearedEnvironmentKeys, want.clearedEnvironmentKeys)
}

func azureOpenAIResponsesV1Limits() ServiceLimits {
	return ServiceLimits{
		MaxRequestHeaderBytes:    32 << 10,
		MaxRequestBodyBytes:      16 << 20,
		MaxResponseHeaderBytes:   32 << 10,
		MaxResponseBodyBytes:     64 << 20,
		MaxSSEEventBytes:         2 << 20,
		ReadIdleTimeout:          5 * time.Minute,
		MaxRequestsPerConnection: 1,
		MaxRetries:               0,
	}
}

func cloneServiceDefinition(definition ServiceDefinition) ServiceDefinition {
	clone := definition
	clone.tls = cloneTLSPolicy(definition.tls)
	clone.methods = append([]string(nil), definition.methods...)
	clone.requestContentTypes = append([]string(nil), definition.requestContentTypes...)
	clone.responseContentTypes = append([]string(nil), definition.responseContentTypes...)
	clone.consumer = cloneInvocationPolicy(definition.consumer)
	return clone
}

func cloneTLSPolicy(policy SealedTLSPolicy) SealedTLSPolicy {
	clone := policy
	clone.alpn = append([]string(nil), policy.alpn...)
	return clone
}

func cloneInvocationPolicy(policy SealedInvocationPolicy) SealedInvocationPolicy {
	clone := policy
	clone.arguments = append([]string(nil), policy.arguments...)
	clone.transientEnvironmentKeys = append([]string(nil), policy.transientEnvironmentKeys...)
	clone.clearedEnvironmentKeys = append([]string(nil), policy.clearedEnvironmentKeys...)
	return clone
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validCatalogIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	previousHyphen := false
	for _, character := range value {
		if character == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		previousHyphen = false
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validAuthority(value string) bool {
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	allNumeric := true
	for _, character := range value {
		if character != '.' && (character < '0' || character > '9') {
			allNumeric = false
			break
		}
	}
	if allNumeric {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
