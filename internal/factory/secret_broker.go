package factory

import (
	"fmt"
	"strings"
	"sync"
)

// SecretBrokerSessionRequest describes the in-memory secrets available to one
// factory run. ResolvedSecrets carry raw values and must only be passed to the
// live broker; returned session metadata is safe to persist.
type SecretBrokerSessionRequest struct {
	ID              string
	RequestedInputs []RunSecretInput
	ResolvedSecrets []ResolvedRunSecret
}

// SecretBrokerSessionMetadata is the durable, redaction-safe description of an
// in-memory broker session.
type SecretBrokerSessionMetadata struct {
	ID      string                       `json:"id"`
	Secrets []SecretBrokerSecretMetadata `json:"secrets,omitempty"`
}

// SecretBrokerSecretMetadata identifies one secret without carrying its value.
type SecretBrokerSecretMetadata struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Source   string `json:"source"`
	Required bool   `json:"required"`
	Present  bool   `json:"present"`
}

// RunSecretMetadata converts broker metadata to the existing durable run secret
// metadata contract.
func (m SecretBrokerSecretMetadata) RunSecretMetadata() RunSecretMetadata {
	return RunSecretMetadata{
		Name:     m.Name,
		Source:   m.Source,
		Required: m.Required,
		Present:  m.Present,
	}
}

// RunSecretInput converts broker metadata to the existing requested secret
// contract.
func (m SecretBrokerSecretMetadata) RunSecretInput() RunSecretInput {
	return RunSecretInput{
		Name:     m.Name,
		Source:   m.Source,
		Required: m.Required,
	}
}

// InMemorySecretBroker owns raw run secret values for active sessions only.
// Closing a session discards the raw values.
type InMemorySecretBroker struct {
	mu       sync.RWMutex
	sessions map[string]*secretBrokerSession
}

type secretBrokerSession struct {
	metadata SecretBrokerSessionMetadata
	byID     map[string]ResolvedRunSecret
	byName   map[string]ResolvedRunSecret
}

// NewInMemorySecretBroker creates an empty in-memory broker.
func NewInMemorySecretBroker() *InMemorySecretBroker {
	return &InMemorySecretBroker{
		sessions: make(map[string]*secretBrokerSession),
	}
}

// CreateSession creates a broker session and returns only persistable metadata.
func (b *InMemorySecretBroker) CreateSession(request SecretBrokerSessionRequest) (SecretBrokerSessionMetadata, error) {
	if b == nil {
		return SecretBrokerSessionMetadata{}, fmt.Errorf("secret broker is required")
	}

	sessionID := strings.TrimSpace(request.ID)
	if sessionID == "" {
		return SecretBrokerSessionMetadata{}, fmt.Errorf("secret broker session ID is required")
	}

	builder := newSecretBrokerSessionBuilder()
	for _, input := range request.RequestedInputs {
		secret, err := normalizeRunSecretInput(input)
		if err != nil {
			return SecretBrokerSessionMetadata{}, err
		}
		if err := builder.addMetadata(secret.Metadata(false), nil); err != nil {
			return SecretBrokerSessionMetadata{}, err
		}
	}
	for _, secret := range request.ResolvedSecrets {
		normalized, err := normalizeResolvedBrokerSecret(secret)
		if err != nil {
			return SecretBrokerSessionMetadata{}, err
		}
		if err := builder.addMetadata(normalized.Metadata(), &normalized); err != nil {
			return SecretBrokerSessionMetadata{}, err
		}
	}

	session := &secretBrokerSession{
		metadata: SecretBrokerSessionMetadata{
			ID:      sessionID,
			Secrets: cloneSecretBrokerSecretMetadata(builder.secrets),
		},
		byID:   builder.byID,
		byName: builder.byName,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions == nil {
		b.sessions = make(map[string]*secretBrokerSession)
	}
	if _, exists := b.sessions[sessionID]; exists {
		return SecretBrokerSessionMetadata{}, fmt.Errorf("secret broker session %q already exists", sessionID)
	}
	b.sessions[sessionID] = session
	return cloneSecretBrokerSessionMetadata(session.metadata), nil
}

// SessionMetadata returns persistable metadata for an active session.
func (b *InMemorySecretBroker) SessionMetadata(sessionID string) (SecretBrokerSessionMetadata, bool) {
	session, ok := b.session(strings.TrimSpace(sessionID))
	if !ok {
		return SecretBrokerSessionMetadata{}, false
	}
	return cloneSecretBrokerSessionMetadata(session.metadata), true
}

// LookupSecret resolves a secret by safe broker metadata. ID is preferred, and
// Name is used as a fallback for metadata created before IDs are available.
func (b *InMemorySecretBroker) LookupSecret(sessionID string, secret SecretBrokerSecretMetadata) (ResolvedRunSecret, bool) {
	if strings.TrimSpace(secret.ID) != "" {
		if resolved, ok := b.LookupSecretByID(sessionID, secret.ID); ok {
			return resolved, true
		}
	}
	return b.LookupSecretByName(sessionID, secret.Name)
}

// LookupSecretByID resolves a raw secret from the active in-memory session.
func (b *InMemorySecretBroker) LookupSecretByID(sessionID string, secretID string) (ResolvedRunSecret, bool) {
	session, ok := b.session(strings.TrimSpace(sessionID))
	if !ok {
		return ResolvedRunSecret{}, false
	}
	secret, ok := session.byID[strings.TrimSpace(secretID)]
	return secret, ok
}

// LookupSecretByName resolves a raw secret by safe secret name metadata.
func (b *InMemorySecretBroker) LookupSecretByName(sessionID string, name string) (ResolvedRunSecret, bool) {
	session, ok := b.session(strings.TrimSpace(sessionID))
	if !ok {
		return ResolvedRunSecret{}, false
	}
	secret, ok := session.byName[strings.TrimSpace(name)]
	return secret, ok
}

// CloseSession discards the active session and its raw in-memory values.
func (b *InMemorySecretBroker) CloseSession(sessionID string) bool {
	if b == nil {
		return false
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.sessions[sessionID]; !ok {
		return false
	}
	delete(b.sessions, sessionID)
	return true
}

// DiscardSession is an explicit alias for CloseSession.
func (b *InMemorySecretBroker) DiscardSession(sessionID string) bool {
	return b.CloseSession(sessionID)
}

func (b *InMemorySecretBroker) session(sessionID string) (*secretBrokerSession, bool) {
	if b == nil || sessionID == "" {
		return nil, false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	session, ok := b.sessions[sessionID]
	return session, ok
}

type secretBrokerSessionBuilder struct {
	secrets      []SecretBrokerSecretMetadata
	indexByID    map[string]int
	idByName     map[string]string
	resolvedByID map[string]struct{}
	byID         map[string]ResolvedRunSecret
	byName       map[string]ResolvedRunSecret
}

func newSecretBrokerSessionBuilder() *secretBrokerSessionBuilder {
	return &secretBrokerSessionBuilder{
		indexByID:    make(map[string]int),
		idByName:     make(map[string]string),
		resolvedByID: make(map[string]struct{}),
		byID:         make(map[string]ResolvedRunSecret),
		byName:       make(map[string]ResolvedRunSecret),
	}
}

func (b *secretBrokerSessionBuilder) addMetadata(metadata RunSecretMetadata, resolved *ResolvedRunSecret) error {
	secret, err := secretBrokerMetadataFromRunSecret(metadata)
	if err != nil {
		return err
	}

	if existingID, ok := b.idByName[secret.Name]; ok && existingID != secret.ID {
		return fmt.Errorf("secret broker metadata name %q is ambiguous across sources", secret.Name)
	}

	index, exists := b.indexByID[secret.ID]
	if !exists {
		b.indexByID[secret.ID] = len(b.secrets)
		b.idByName[secret.Name] = secret.ID
		b.secrets = append(b.secrets, secret)
	} else {
		if resolved == nil {
			return fmt.Errorf("duplicate secret broker metadata for %s", secret.ID)
		}
		if _, alreadyResolved := b.resolvedByID[secret.ID]; alreadyResolved {
			return fmt.Errorf("duplicate resolved secret broker value for %s", secret.ID)
		}
		b.secrets[index] = secret
	}

	if resolved == nil || !secret.Present {
		return nil
	}

	normalized, err := normalizeResolvedBrokerSecret(*resolved)
	if err != nil {
		return err
	}
	b.resolvedByID[secret.ID] = struct{}{}
	b.byID[secret.ID] = normalized
	b.byName[secret.Name] = normalized
	return nil
}

func secretBrokerMetadataFromRunSecret(metadata RunSecretMetadata) (SecretBrokerSecretMetadata, error) {
	input, err := normalizeRunSecretInput(RunSecretInput{
		Name:     metadata.Name,
		Source:   metadata.Source,
		Required: metadata.Required,
	})
	if err != nil {
		return SecretBrokerSecretMetadata{}, err
	}
	return SecretBrokerSecretMetadata{
		ID:       secretBrokerSecretID(input.Source, input.Name),
		Name:     input.Name,
		Source:   input.Source,
		Required: input.Required,
		Present:  metadata.Present,
	}, nil
}

func normalizeResolvedBrokerSecret(secret ResolvedRunSecret) (ResolvedRunSecret, error) {
	input, err := normalizeRunSecretInput(RunSecretInput{
		Name:     secret.Name,
		Source:   secret.Source,
		Required: secret.Required,
	})
	if err != nil {
		return ResolvedRunSecret{}, err
	}
	return ResolvedRunSecret{
		Name:     input.Name,
		Source:   input.Source,
		Required: input.Required,
		Value:    secret.Value,
	}, nil
}

func secretBrokerSecretID(source string, name string) string {
	return strings.TrimSpace(source) + ":" + strings.TrimSpace(name)
}

func cloneSecretBrokerSessionMetadata(metadata SecretBrokerSessionMetadata) SecretBrokerSessionMetadata {
	return SecretBrokerSessionMetadata{
		ID:      metadata.ID,
		Secrets: cloneSecretBrokerSecretMetadata(metadata.Secrets),
	}
}

func cloneSecretBrokerSecretMetadata(secrets []SecretBrokerSecretMetadata) []SecretBrokerSecretMetadata {
	if len(secrets) == 0 {
		return nil
	}
	return append([]SecretBrokerSecretMetadata(nil), secrets...)
}
