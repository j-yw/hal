package credentialproxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	JobTicketLeaseDuration    = 60 * time.Second
	JobTicketRenewalInterval  = 20 * time.Second
	JobTicketMaximumClockSkew = 5 * time.Second
	JobTicketHardLifetime     = 35 * time.Minute
)

type TicketCorrelation struct {
	JobIdentityDigest    [32]byte
	ServiceID            ServiceID
	BindingID            string
	ActivationGeneration string
	CatalogGeneration    string
	ListenerGeneration   uint64
}

type TicketActivation struct {
	Correlation TicketCorrelation
	IssuedAt    time.Time
	Source      sandboxruntime.LiveSecretSource
}

type TicketStore struct {
	state *ticketStoreState
}

type ticketStoreState struct {
	mu               sync.Mutex
	daemonGeneration string
	key              *credentialmemory.LockedMapping
	entries          map[[32]byte]*ticketStoreEntry
	now              func() time.Time
	entropy          io.Reader
	nextLeaseID      uint64
	closed           bool
}

type ticketStoreEntry struct {
	correlation TicketCorrelation
	issuedAt    time.Time
	leaseExpiry time.Time
	hardExpiry  time.Time
	source      sandboxruntime.LiveSecretSource
	total       int
	concurrent  int
	revoked     bool
	leases      map[uint64]*TicketRequestLease
}

type TicketRequestLease struct {
	store      *TicketStore
	digest     [32]byte
	id         uint64
	connection io.Closer
	released   bool
}

type ticketStoreDeps struct {
	now     func() time.Time
	entropy io.Reader
}

func NewTicketStore(daemonGeneration string) (*TicketStore, error) {
	return newTicketStore(daemonGeneration, ticketStoreDeps{now: time.Now, entropy: rand.Reader})
}

func newTicketStore(daemonGeneration string, deps ticketStoreDeps) (*TicketStore, error) {
	if !validCatalogIdentifier(daemonGeneration) || deps.now == nil || deps.entropy == nil {
		return nil, ErrTicketStoreInvalid
	}
	key, err := credentialmemory.NewLockedMapping(JobTicketRawBytes)
	if err != nil {
		return nil, ErrTicketStoreInvalid
	}
	if err := key.Load(context.Background(), func(destination []byte) (int, error) {
		return io.ReadFull(deps.entropy, destination)
	}); err != nil {
		_ = key.Destroy()
		return nil, ErrTicketStoreInvalid
	}
	return &TicketStore{state: &ticketStoreState{
		daemonGeneration: daemonGeneration,
		key:              key,
		entries:          make(map[[32]byte]*ticketStoreEntry),
		now:              deps.now,
		entropy:          deps.entropy,
	}}, nil
}

func (store *TicketStore) Issue(ctx context.Context, activation TicketActivation) (*JobTicket, error) {
	state := store.sharedState()
	if state == nil || ctx == nil {
		return nil, ErrTicketStoreInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := state.now().UTC()
	if !validTicketActivation(activation, now) {
		return nil, ErrTicketCorrelation
	}
	var raw [JobTicketRawBytes]byte
	if _, err := io.ReadFull(state.entropy, raw[:]); err != nil {
		wipeBytes(raw[:])
		return nil, ErrTicketStoreInvalid
	}
	ticket := newJobTicket(raw)
	wipeBytes(raw[:])
	digest, err := store.digestEncoded(ctx, ticket.encoded[:])
	if err != nil {
		return nil, err
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil, ErrTicketStoreInvalid
	}
	if _, collision := state.entries[digest]; collision {
		return nil, ErrTicketStoreInvalid
	}
	state.entries[digest] = &ticketStoreEntry{
		correlation: activation.Correlation,
		issuedAt:    now,
		leaseExpiry: now.Add(JobTicketLeaseDuration),
		hardExpiry:  now.Add(JobTicketHardLifetime),
		source:      activation.Source,
		leases:      make(map[uint64]*TicketRequestLease),
	}
	return ticket, nil
}

func (store *TicketStore) Renew(ctx context.Context, ticket *JobTicket, correlation TicketCorrelation) error {
	digest, err := store.digestJobTicket(ctx, ticket)
	if err != nil {
		return err
	}
	state := store.sharedState()
	if state == nil {
		return ErrTicketStoreInvalid
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	entry, err := state.validEntryLocked(digest, correlation, state.now().UTC())
	if err != nil {
		return err
	}
	renewed := state.now().UTC().Add(JobTicketLeaseDuration)
	if renewed.After(entry.hardExpiry) {
		renewed = entry.hardExpiry
	}
	entry.leaseExpiry = renewed
	return nil
}

func (store *TicketStore) Revoke(ctx context.Context, ticket *JobTicket, correlation TicketCorrelation) error {
	digest, err := store.digestJobTicket(ctx, ticket)
	if err != nil {
		return err
	}
	state := store.sharedState()
	if state == nil {
		return ErrTicketStoreInvalid
	}
	state.mu.Lock()
	entry, ok := state.entries[digest]
	if !ok {
		state.mu.Unlock()
		return ErrTicketInvalid
	}
	if !sameTicketCorrelation(entry.correlation, correlation) {
		state.mu.Unlock()
		return ErrTicketCorrelation
	}
	entry.revoked = true
	connections := entry.takeConnectionsLocked()
	state.mu.Unlock()
	return closeTicketConnections(connections)
}

func (store *TicketStore) acquirePresentedTicket(ctx context.Context, presentation credentialmemory.BorrowedView, correlation TicketCorrelation) (*TicketRequestLease, error) {
	if ctx == nil || presentation == nil || presentation.Len() != JobTicketEncodedBytes {
		return nil, ErrTicketInvalid
	}
	digestSink := &presentedTicketDigestSink{store: store, ctx: ctx}
	if err := presentation.WriteTo(ctx, digestSink); err != nil {
		return nil, ErrTicketInvalid
	}
	digest := digestSink.digest
	state := store.sharedState()
	if state == nil {
		return nil, ErrTicketStoreInvalid
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	entry, err := state.validEntryLocked(digest, correlation, state.now().UTC())
	if err != nil {
		return nil, err
	}
	if entry.concurrent >= JobTicketMaxConcurrentRequests {
		return nil, ErrTicketConcurrencyLimit
	}
	if entry.total >= JobTicketMaxTotalRequests {
		return nil, ErrTicketRequestLimit
	}
	state.nextLeaseID++
	lease := &TicketRequestLease{store: store, digest: digest, id: state.nextLeaseID}
	entry.concurrent++
	entry.total++
	entry.leases[lease.id] = lease
	return lease, nil
}

func (lease *TicketRequestLease) Revalidate(ctx context.Context, correlation TicketCorrelation) error {
	if lease == nil || lease.store == nil || ctx == nil {
		return ErrTicketInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	state := lease.store.sharedState()
	if state == nil {
		return ErrTicketStoreInvalid
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	entry, err := state.validEntryLocked(lease.digest, correlation, state.now().UTC())
	if err != nil {
		return err
	}
	if current, ok := entry.leases[lease.id]; !ok || current != lease || lease.released {
		return ErrTicketRevoked
	}
	return nil
}

func (lease *TicketRequestLease) FillSecret(ctx context.Context, correlation TicketCorrelation, sink sandboxruntime.JobCredentialSecretSink) error {
	if sink == nil {
		return ErrTicketInvalid
	}
	if err := lease.Revalidate(ctx, correlation); err != nil {
		return err
	}
	state := lease.store.sharedState()
	state.mu.Lock()
	entry := state.entries[lease.digest]
	source := entry.source
	state.mu.Unlock()
	if err := source.FillSecret(ctx, sink); err != nil {
		return ErrTicketInvalid
	}
	return lease.Revalidate(ctx, correlation)
}

func (lease *TicketRequestLease) OwnConnection(connection io.Closer) error {
	if lease == nil || lease.store == nil || connection == nil || typedNil(connection) {
		return ErrTicketConnectionTransition
	}
	state := lease.store.sharedState()
	if state == nil {
		_ = connection.Close()
		return ErrTicketConnectionTransition
	}
	state.mu.Lock()
	entry, ok := state.entries[lease.digest]
	if !ok || entry.revoked || lease.released || entry.leases[lease.id] != lease || lease.connection != nil {
		state.mu.Unlock()
		_ = connection.Close()
		return ErrTicketConnectionTransition
	}
	lease.connection = connection
	state.mu.Unlock()
	return nil
}

func (lease *TicketRequestLease) Release() {
	if lease == nil || lease.store == nil {
		return
	}
	state := lease.store.sharedState()
	if state == nil {
		return
	}
	state.mu.Lock()
	if lease.released {
		state.mu.Unlock()
		return
	}
	lease.released = true
	connection := lease.connection
	lease.connection = nil
	if entry, ok := state.entries[lease.digest]; ok {
		if entry.leases[lease.id] == lease {
			delete(entry.leases, lease.id)
			if entry.concurrent > 0 {
				entry.concurrent--
			}
		}
	}
	state.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
}

func (store *TicketStore) Close(ctx context.Context) error {
	state := store.sharedState()
	if state == nil || ctx == nil {
		return ErrTicketStoreInvalid
	}
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return nil
	}
	state.closed = true
	connections := make([]io.Closer, 0)
	for _, entry := range state.entries {
		entry.revoked = true
		connections = append(connections, entry.takeConnectionsLocked()...)
	}
	state.entries = make(map[[32]byte]*ticketStoreEntry)
	key := state.key
	state.key = nil
	state.mu.Unlock()

	closeErr := closeTicketConnections(connections)
	keyErr := error(nil)
	if key != nil {
		keyErr = key.Destroy()
	}
	if closeErr != nil || keyErr != nil {
		return ErrTicketCleanup
	}
	return nil
}

func (store *TicketStore) digestJobTicket(ctx context.Context, ticket *JobTicket) ([32]byte, error) {
	if ticket == nil || !validEncodedTicket(ticket.encoded[:]) {
		return [32]byte{}, ErrTicketInvalid
	}
	return store.digestEncoded(ctx, ticket.encoded[:])
}

func (store *TicketStore) digestEncoded(ctx context.Context, encoded []byte) ([32]byte, error) {
	state := store.sharedState()
	if state == nil || ctx == nil || !validEncodedTicket(encoded) {
		return [32]byte{}, ErrTicketInvalid
	}
	state.mu.Lock()
	key := state.key
	closed := state.closed
	state.mu.Unlock()
	if closed || key == nil {
		return [32]byte{}, ErrTicketStoreInvalid
	}
	sink := &ticketHMACKeySink{encoded: encoded}
	if err := key.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		return view.WriteTo(ctx, sink)
	}); err != nil {
		return [32]byte{}, ErrTicketStoreInvalid
	}
	return sink.digest, nil
}

func (state *ticketStoreState) validEntryLocked(digest [32]byte, correlation TicketCorrelation, now time.Time) (*ticketStoreEntry, error) {
	if state.closed {
		return nil, ErrTicketStoreInvalid
	}
	entry, ok := state.entries[digest]
	if !ok {
		return nil, ErrTicketInvalid
	}
	if subtle.ConstantTimeCompare(entry.correlation.JobIdentityDigest[:], correlation.JobIdentityDigest[:]) != 1 ||
		!sameTicketCorrelationWithoutDigest(entry.correlation, correlation) {
		return nil, ErrTicketCorrelation
	}
	if entry.revoked {
		return nil, ErrTicketRevoked
	}
	if !now.Before(entry.leaseExpiry) || !now.Before(entry.hardExpiry) {
		entry.revoked = true
		return nil, ErrTicketExpired
	}
	return entry, nil
}

func (entry *ticketStoreEntry) takeConnectionsLocked() []io.Closer {
	connections := make([]io.Closer, 0, len(entry.leases))
	for _, lease := range entry.leases {
		lease.released = true
		if lease.connection != nil {
			connections = append(connections, lease.connection)
			lease.connection = nil
		}
	}
	entry.leases = make(map[uint64]*TicketRequestLease)
	entry.concurrent = 0
	return connections
}

type presentedTicketDigestSink struct {
	store  *TicketStore
	ctx    context.Context
	digest [32]byte
}

func (*presentedTicketDigestSink) MaxCredentialBytes() int { return JobTicketEncodedBytes }
func (sink *presentedTicketDigestSink) WriteCredential(encoded []byte) error {
	digest, err := sink.store.digestEncoded(sink.ctx, encoded)
	if err != nil {
		return ErrTicketInvalid
	}
	sink.digest = digest
	return nil
}

type ticketHMACKeySink struct {
	encoded []byte
	digest  [32]byte
}

func (*ticketHMACKeySink) MaxCredentialBytes() int { return JobTicketRawBytes }
func (sink *ticketHMACKeySink) WriteCredential(key []byte) error {
	if len(key) != JobTicketRawBytes || !validEncodedTicket(sink.encoded) {
		return ErrTicketInvalid
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(sink.encoded)
	sum := mac.Sum(sink.digest[:0])
	copy(sink.digest[:], sum)
	return nil
}

func validTicketActivation(activation TicketActivation, now time.Time) bool {
	return validTicketCorrelation(activation.Correlation) && !activation.IssuedAt.IsZero() &&
		!activation.IssuedAt.Before(now.Add(-JobTicketMaximumClockSkew)) &&
		!activation.IssuedAt.After(now.Add(JobTicketMaximumClockSkew)) &&
		activation.Source != nil && !typedNil(activation.Source)
}

func validTicketCorrelation(correlation TicketCorrelation) bool {
	return correlation.JobIdentityDigest != [32]byte{} && correlation.ServiceID == ServiceIDAzureOpenAIResponsesV1 &&
		validCatalogIdentifier(correlation.BindingID) && validCatalogIdentifier(correlation.ActivationGeneration) &&
		validCatalogIdentifier(correlation.CatalogGeneration) && correlation.ListenerGeneration > 0
}

func sameTicketCorrelation(left, right TicketCorrelation) bool {
	return subtle.ConstantTimeCompare(left.JobIdentityDigest[:], right.JobIdentityDigest[:]) == 1 &&
		sameTicketCorrelationWithoutDigest(left, right)
}

func sameTicketCorrelationWithoutDigest(left, right TicketCorrelation) bool {
	return left.ServiceID == right.ServiceID && left.BindingID == right.BindingID &&
		left.ActivationGeneration == right.ActivationGeneration && left.CatalogGeneration == right.CatalogGeneration &&
		left.ListenerGeneration == right.ListenerGeneration
}

func closeTicketConnections(connections []io.Closer) error {
	failed := false
	for _, connection := range connections {
		if connection != nil && connection.Close() != nil {
			failed = true
		}
	}
	if failed {
		return ErrTicketCleanup
	}
	return nil
}

func typedNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (store *TicketStore) sharedState() *ticketStoreState {
	if store == nil {
		return nil
	}
	return store.state
}

func (*TicketStore) MarshalJSON() ([]byte, error) { return nil, ErrLiveTicketNotSerializable }
func (*TicketStore) MarshalText() ([]byte, error) { return nil, ErrLiveTicketNotSerializable }
func (*TicketStore) String() string               { return "credentialproxy.TicketStore{live}" }
func (*TicketStore) GoString() string             { return "credentialproxy.TicketStore{live}" }
func (*TicketStore) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.TicketStore{live}"))
}

func (*TicketRequestLease) MarshalJSON() ([]byte, error) { return nil, ErrLiveTicketNotSerializable }
func (*TicketRequestLease) MarshalText() ([]byte, error) { return nil, ErrLiveTicketNotSerializable }
func (*TicketRequestLease) String() string               { return "credentialproxy.TicketRequestLease{live}" }
func (*TicketRequestLease) GoString() string             { return "credentialproxy.TicketRequestLease{live}" }
func (*TicketRequestLease) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.TicketRequestLease{live}"))
}
