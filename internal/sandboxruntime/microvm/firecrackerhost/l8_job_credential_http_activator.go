package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialproxy"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const l8JobCredentialHTTPActivatorValuePlaceholder = "[firecracker-l8-job-credential-http]"

// ProductionL8JobCredentialHTTPProxyActivatorConfig is explicit constructor
// input for the TicketStore-backed HTTP activator. Zero values are rejected.
type ProductionL8JobCredentialHTTPProxyActivatorConfig struct {
	Store              *credentialproxy.TicketStore
	CatalogGeneration  string
	ListenerGeneration uint64
	LocalAuthority     string
	Now                func() time.Time
}

// ProductionL8JobCredentialHTTPProxyActivator issues one TicketStore ticket per
// HTTP-proxy binding. It is default-off: callers must construct and inject it.
type ProductionL8JobCredentialHTTPProxyActivator struct {
	store              *credentialproxy.TicketStore
	catalogGeneration  string
	listenerGeneration uint64
	localAuthority     string
	now                func() time.Time
}

type productionL8JobCredentialHTTPProxyHandle struct {
	mu          sync.Mutex
	store       *credentialproxy.TicketStore
	ticket      *credentialproxy.JobTicket
	correlation credentialproxy.TicketCorrelation
	serviceID   string
	revoked     bool
}

var (
	_ l8JobCredentialHTTPProxyActivator = (*ProductionL8JobCredentialHTTPProxyActivator)(nil)
	_ l8JobCredentialHTTPProxyHandle    = (*productionL8JobCredentialHTTPProxyHandle)(nil)
)

// NewProductionL8JobCredentialHTTPProxyActivator constructs the TicketStore-backed
// HTTP activator. It is never invoked by sandboxd, hal run, hal auto, factory,
// worker Service, or NewProductionL8JobCredentialRuntime unless injected.
func NewProductionL8JobCredentialHTTPProxyActivator(config ProductionL8JobCredentialHTTPProxyActivatorConfig) (*ProductionL8JobCredentialHTTPProxyActivator, error) {
	if config.Store == nil || !validL8JobCredentialHTTPCatalogID(config.CatalogGeneration) || config.ListenerGeneration == 0 ||
		!validL8JobCredentialHTTPLocalAuthority(config.LocalAuthority) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ProductionL8JobCredentialHTTPProxyActivator{
		store:              config.Store,
		catalogGeneration:  config.CatalogGeneration,
		listenerGeneration: config.ListenerGeneration,
		localAuthority:     config.LocalAuthority,
		now:                now,
	}, nil
}

func (activator *ProductionL8JobCredentialHTTPProxyActivator) Activate(
	ctx context.Context,
	identity sandboxruntime.JobCredentialIdentity,
	binding sandboxruntime.JobCredentialBindingRequest,
	source sandboxruntime.LiveSecretSource,
) (handle l8JobCredentialHTTPProxyHandle, err error) {
	defer func() {
		if recover() != nil {
			handle = nil
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if activator == nil || l8JobCredentialRuntimeValueIsNil(ctx) || l8JobCredentialRuntimeValueIsNil(activator.store) || activator.now == nil {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrL8JobCredentialRuntimeUnavailable
	}
	if binding.Mode != sandboxruntime.JobCredentialDeliveryModeHTTPProxy {
		if binding.Mode == sandboxruntime.JobCredentialDeliveryModeFileTmpfs || binding.Mode == sandboxruntime.JobCredentialDeliveryModeSSHAgent {
			return nil, ErrL8JobCredentialRuntimeUnsupported
		}
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if sandboxruntime.ValidateJobCredentialIdentity(identity) != nil || !l8JobCredentialHTTPBindingMatchesIdentity(identity, binding) {
		return nil, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	if !validL8JobCredentialHTTPCatalogID(binding.ID) || !validL8JobCredentialHTTPCatalogID(binding.ServiceID) ||
		binding.SourceReferenceID == "" || l8JobCredentialRuntimeValueIsNil(source) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if credentialproxy.ServiceID(binding.ServiceID) != credentialproxy.ServiceIDAzureOpenAIResponsesV1 {
		return nil, ErrL8JobCredentialRuntimeUnsupported
	}
	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		return nil, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	if !validL8JobCredentialHTTPCatalogID(identity.ActivationGeneration) {
		return nil, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	issuedAt, err := callL8JobCredentialNow(activator.now)
	if err != nil {
		return nil, err
	}
	correlation := credentialproxy.TicketCorrelation{
		JobIdentityDigest:    digest,
		ServiceID:            credentialproxy.ServiceIDAzureOpenAIResponsesV1,
		BindingID:            binding.ID,
		ActivationGeneration: identity.ActivationGeneration,
		CatalogGeneration:    activator.catalogGeneration,
		ListenerGeneration:   activator.listenerGeneration,
		LocalAuthority:       activator.localAuthority,
	}
	ticket, err := activator.store.Issue(ctx, credentialproxy.TicketActivation{
		Correlation: correlation,
		IssuedAt:    issuedAt,
		Source:      source,
	})
	if err != nil {
		return nil, mapL8JobCredentialHTTPTicketError(err)
	}
	if ticket == nil {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	return &productionL8JobCredentialHTTPProxyHandle{
		store:       activator.store,
		ticket:      ticket,
		correlation: correlation,
		serviceID:   binding.ServiceID,
	}, nil
}

func (handle *productionL8JobCredentialHTTPProxyHandle) ServiceID() string {
	if handle == nil {
		return ""
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.serviceID
}

func (handle *productionL8JobCredentialHTTPProxyHandle) Renew(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if handle == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.revoked || handle.ticket == nil || l8JobCredentialRuntimeValueIsNil(handle.store) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	if err := ctx.Err(); err != nil {
		return ErrL8JobCredentialRuntimeUnavailable
	}
	return mapL8JobCredentialHTTPTicketError(handle.store.Renew(ctx, handle.ticket, handle.correlation))
}

func (handle *productionL8JobCredentialHTTPProxyHandle) Revoke(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if handle == nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	if l8JobCredentialRuntimeValueIsNil(ctx) {
		ctx = context.Background()
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.revoked {
		return nil
	}
	if handle.ticket == nil || l8JobCredentialRuntimeValueIsNil(handle.store) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	if err := handle.store.Revoke(ctx, handle.ticket, handle.correlation); err != nil {
		return mapL8JobCredentialHTTPTicketError(err)
	}
	handle.revoked = true
	handle.ticket = nil
	return nil
}

func l8JobCredentialHTTPBindingMatchesIdentity(identity sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest) bool {
	if binding.ID == "" || len(identity.BindingIDs) != len(identity.DeliveryModes) {
		return false
	}
	for index, bindingID := range identity.BindingIDs {
		if bindingID != binding.ID {
			continue
		}
		return identity.DeliveryModes[index] == sandboxruntime.JobCredentialDeliveryModeHTTPProxy &&
			binding.Mode == sandboxruntime.JobCredentialDeliveryModeHTTPProxy
	}
	return false
}

func mapL8JobCredentialHTTPTicketError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, credentialproxy.ErrTicketCorrelation):
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	case errors.Is(err, credentialproxy.ErrTicketExpired):
		return sandboxruntime.ErrJobCredentialExpired
	case errors.Is(err, credentialproxy.ErrTicketRevoked):
		return sandboxruntime.ErrJobCredentialTransition
	case errors.Is(err, credentialproxy.ErrTicketInvalid), errors.Is(err, credentialproxy.ErrTicketStoreInvalid):
		return ErrL8JobCredentialRuntimeInvalid
	default:
		return sanitizeL8JobCredentialRuntimeError(err)
	}
}

func validL8JobCredentialHTTPCatalogID(value string) bool {
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

func validL8JobCredentialHTTPLocalAuthority(authority string) bool {
	if authority == "" || len(authority) > 512 || strings.ContainsAny(authority, "@/\\?# \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	portNumber, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && host != "" && portNumber > 0 && portNumber <= 65535
}

func (ProductionL8JobCredentialHTTPProxyActivator) String() string {
	return l8JobCredentialHTTPActivatorValuePlaceholder
}
func (ProductionL8JobCredentialHTTPProxyActivator) GoString() string {
	return l8JobCredentialHTTPActivatorValuePlaceholder
}
func (ProductionL8JobCredentialHTTPProxyActivator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialHTTPActivatorValuePlaceholder)
}
func (ProductionL8JobCredentialHTTPProxyActivator) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (ProductionL8JobCredentialHTTPProxyActivator) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (ProductionL8JobCredentialHTTPProxyActivator) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}

func (*productionL8JobCredentialHTTPProxyHandle) String() string {
	return l8JobCredentialHTTPActivatorValuePlaceholder
}
func (*productionL8JobCredentialHTTPProxyHandle) GoString() string {
	return l8JobCredentialHTTPActivatorValuePlaceholder
}
func (*productionL8JobCredentialHTTPProxyHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialHTTPActivatorValuePlaceholder)
}
func (*productionL8JobCredentialHTTPProxyHandle) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*productionL8JobCredentialHTTPProxyHandle) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*productionL8JobCredentialHTTPProxyHandle) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
