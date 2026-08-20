package credentialproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8D3TicketFormatHMACRetentionAndOpacity(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	entropy := bytes.NewReader(append(bytes.Repeat([]byte{0x81}, 32), bytes.Repeat([]byte{0x42}, 32)...))
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now:     func() time.Time { return now },
		entropy: entropy,
	})
	if err != nil {
		t.Fatalf("newTicketStore() error: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Errorf("Close() error: %v", err)
		}
	})

	ticket, err := store.Issue(context.Background(), l8D3TicketActivation(t, now))
	if err != nil {
		t.Fatalf("Issue() error: %v", err)
	}
	if got := ticket.Len(); got != JobTicketEncodedBytes {
		t.Fatalf("ticket length = %d, want %d", got, JobTicketEncodedBytes)
	}
	encoded := make([]byte, JobTicketEncodedBytes)
	if n, err := ticket.CopyTo(encoded); err != nil || n != JobTicketEncodedBytes {
		t.Fatalf("CopyTo() = (%d, %v), want (%d, nil)", n, err, JobTicketEncodedBytes)
	}
	if got, want := string(encoded), "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"; got != want {
		t.Fatalf("encoded ticket = %q, want deterministic unpadded base64url %q", got, want)
	}
	for _, rendered := range []string{
		fmt.Sprint(ticket), fmt.Sprintf("%v", ticket), fmt.Sprintf("%+v", ticket), fmt.Sprintf("%#v", ticket),
		fmt.Sprint(*ticket), fmt.Sprintf("%#v", *ticket),
	} {
		if rendered != "credentialproxy.JobTicket{live}" || bytes.Contains([]byte(rendered), encoded) {
			t.Fatalf("ticket formatting = %q, want static live marker", rendered)
		}
	}
	if _, err := json.Marshal(ticket); !errors.Is(err, ErrLiveTicketNotSerializable) {
		t.Fatalf("Marshal(ticket) error = %v, want serialization denial", err)
	}
	if _, err := json.Marshal(*ticket); !errors.Is(err, ErrLiveTicketNotSerializable) {
		t.Fatalf("Marshal(ticket value) error = %v, want serialization denial", err)
	}
	for _, value := range []any{store, *store, l8D3TicketActivation(t, now)} {
		if rendered := fmt.Sprintf("%#v", value); bytes.Contains([]byte(rendered), encoded) || bytes.Contains([]byte(rendered), []byte("sk-live")) {
			t.Fatalf("live ticket value formatting leaked payload: %q", rendered)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrLiveTicketNotSerializable) {
			t.Fatalf("Marshal(%T) error = %v, want denial", value, err)
		}
	}

	state := reflect.ValueOf(store).Elem().FieldByName("state")
	if !state.IsValid() {
		t.Fatal("TicketStore has no private state")
	}
	stateType := state.Type().Elem()
	for _, forbidden := range []string{"ticket", "encoded", "plaintext", "value"} {
		for index := 0; index < stateType.NumField(); index++ {
			if stateType.Field(index).Name == forbidden {
				t.Fatalf("ticket store retains forbidden plaintext field %q", forbidden)
			}
		}
	}
}

func TestL8D3TicketLeaseRenewalHardExpiryAndExactCorrelation(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	clock := now
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now:     func() time.Time { return clock },
		entropy: bytes.NewReader(append(append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...), bytes.Repeat([]byte{0x23}, 32)...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}

	lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
	lease.Release()
	clock = now.Add(JobTicketLeaseDuration)
	if err := store.Renew(context.Background(), ticket, activation.Correlation); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("Renew() at lease expiry = %v, want expired", err)
	}

	clock = now
	second, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	clock = now.Add(JobTicketRenewalInterval)
	if err := store.Renew(context.Background(), second, activation.Correlation); err != nil {
		t.Fatalf("Renew() error: %v", err)
	}
	clock = now.Add(JobTicketRenewalInterval + JobTicketLeaseDuration - time.Nanosecond)
	lease = l8D3AcquireTicket(t, store, second, activation.Correlation)
	lease.Release()

	wrong := activation.Correlation
	wrong.BindingID = "neighbor-binding"
	if _, err := l8D3AcquireTicketError(store, second, wrong); !errors.Is(err, ErrTicketCorrelation) {
		t.Fatalf("neighbor correlation error = %v, want mismatch", err)
	}

	clock = now.Add(JobTicketHardLifetime)
	if err := store.Renew(context.Background(), second, activation.Correlation); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("Renew() at hard expiry = %v, want expired", err)
	}
}

func TestL8D3TicketRenewalUsesOneAtomicClockSample(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	clockCalls := 0
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time {
			clockCalls++
			return now
		},
		entropy: bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}

	clockCalls = 0
	if err := store.Renew(context.Background(), ticket, activation.Correlation); err != nil {
		t.Fatalf("Renew() error: %v", err)
	}
	if clockCalls != 1 {
		t.Fatalf("renewal clock samples = %d, want one atomic sample", clockCalls)
	}
}

func TestL8D3TicketConcurrentAndTotalRequestLimits(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now:     func() time.Time { return now },
		entropy: bytes.NewReader(append(bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x44}, 32)...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}

	leases := make([]*TicketRequestLease, 0, JobTicketMaxConcurrentRequests)
	for index := 0; index < JobTicketMaxConcurrentRequests; index++ {
		leases = append(leases, l8D3AcquireTicket(t, store, ticket, activation.Correlation))
	}
	if _, err := l8D3AcquireTicketError(store, ticket, activation.Correlation); !errors.Is(err, ErrTicketConcurrencyLimit) {
		t.Fatalf("fifth concurrent acquire = %v, want limit", err)
	}
	for _, lease := range leases {
		lease.Release()
	}
	for index := JobTicketMaxConcurrentRequests; index < JobTicketMaxTotalRequests; index++ {
		lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
		lease.Release()
	}
	if _, err := l8D3AcquireTicketError(store, ticket, activation.Correlation); !errors.Is(err, ErrTicketRequestLimit) {
		t.Fatalf("request after total limit = %v, want limit", err)
	}
}

func TestL8D3TicketRevocationClosesInflightAndPreventsRenewal(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now:     func() time.Time { return now },
		entropy: bytes.NewReader(append(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0x66}, 32)...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
	closer := &l8D3TicketCloser{}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatalf("OwnConnection() error: %v", err)
	}

	if err := store.Revoke(context.Background(), ticket, activation.Correlation); err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}
	if closer.Count() != 1 {
		t.Fatalf("in-flight close count = %d, want 1", closer.Count())
	}
	lease.Release()
	lease.Release()
	if closer.Count() != 1 {
		t.Fatalf("release reclosed connection: %d", closer.Count())
	}
	if err := store.Renew(context.Background(), ticket, activation.Correlation); !errors.Is(err, ErrTicketRevoked) {
		t.Fatalf("Renew() after revoke = %v, want revoked", err)
	}
	if _, err := l8D3AcquireTicketError(store, ticket, activation.Correlation); !errors.Is(err, ErrTicketRevoked) {
		t.Fatalf("Acquire() after revoke = %v, want revoked", err)
	}
}

func TestL8D3TicketExpiryClosesEveryInflightConnection(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	clock := now
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time { return clock }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x67}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
	closer := &l8D3TicketCloser{}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(JobTicketLeaseDuration)
	if err := store.Validate(context.Background(), ticket, activation.Correlation); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("Validate() at expiry = %v, want expired", err)
	}
	if closer.Count() != 1 {
		t.Fatalf("expiry close count = %d, want 1", closer.Count())
	}
	if err := lease.Revalidate(context.Background(), activation.Correlation); !errors.Is(err, ErrTicketRevoked) {
		t.Fatalf("Revalidate() after expiry cleanup = %v, want revoked", err)
	}
}

func TestL8D3TicketRevokeClearsLiveSourceAndRetriesFailedReleaseConnection(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time { return now }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x68}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := store.digestJobTicket(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
	closer := &l8D3TicketCloser{failures: 1}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatal(err)
	}

	lease.Release()
	if closer.Count() != 1 {
		t.Fatalf("release close attempts = %d, want 1", closer.Count())
	}
	if err := store.Revoke(context.Background(), ticket, activation.Correlation); err != nil {
		t.Fatalf("Revoke() retry error: %v", err)
	}
	if closer.Count() != 2 {
		t.Fatalf("close attempts after revoke = %d, want retained retry", closer.Count())
	}
	store.state.mu.Lock()
	entry := store.state.entries[digest]
	sourceRetained := entry != nil && entry.source != nil
	store.state.mu.Unlock()
	if sourceRetained {
		t.Fatal("revoked ticket entry retained live secret source")
	}
}

func TestL8D3TicketConcurrentRevokeConvergesFailedConnectionCleanup(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time { return now }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x69}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
	closer := &l8D3TicketCloser{failures: 1}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatal(err)
	}

	const callers = 16
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsSeen <- store.Revoke(context.Background(), ticket, activation.Correlation)
		}()
	}
	group.Wait()
	close(errorsSeen)
	succeeded := 0
	for revokeErr := range errorsSeen {
		if revokeErr == nil {
			succeeded++
		} else if !errors.Is(revokeErr, ErrTicketCleanup) {
			t.Errorf("concurrent Revoke() error = %v", revokeErr)
		}
	}
	if succeeded == 0 {
		t.Fatal("concurrent revoke never completed cleanup")
	}
	if closer.Count() != 2 {
		t.Fatalf("concurrent close attempts = %d, want one failure and one retry", closer.Count())
	}
}

func TestL8D3TicketStoreCloseRetriesFailedOwnedConnection(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time { return now }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x6a}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
	closer := &l8D3TicketCloser{failures: 1}
	if err := lease.OwnConnection(closer); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(context.Background()); !errors.Is(err, ErrTicketCleanup) {
		t.Fatalf("first Close() error = %v, want cleanup incomplete", err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() error: %v", err)
	}
	if closer.Count() != 2 {
		t.Fatalf("store close attempts = %d, want retained retry", closer.Count())
	}
	store.state.mu.Lock()
	entries := len(store.state.entries)
	key := store.state.key
	store.state.mu.Unlock()
	if entries != 0 || key != nil {
		t.Fatalf("completed store cleanup retained entries/key: entries=%d key=%t", entries, key != nil)
	}
}

func TestL8D3TicketCleanupJoinsInflightSourceCalls(t *testing.T) {
	for _, operation := range []string{"revoke", "close", "expiry", "release"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
			clock := now
			var clockMu sync.Mutex
			source := &l8D3BlockingSecretSource{entered: make(chan struct{}), release: make(chan struct{})}
			store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
				now: func() time.Time {
					clockMu.Lock()
					defer clockMu.Unlock()
					return clock
				},
				entropy: bytes.NewReader(bytes.Repeat([]byte{0x6b}, 64)),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close(context.Background()) }()
			activation := l8D3TicketActivation(t, now)
			activation.Source = source
			ticket, err := store.Issue(context.Background(), activation)
			if err != nil {
				t.Fatal(err)
			}
			lease := l8D3AcquireTicket(t, store, ticket, activation.Correlation)
			fillDone := make(chan error, 1)
			go func() {
				fillDone <- lease.FillSecret(context.Background(), activation.Correlation, l8D3TestCredentialSink{})
			}()
			select {
			case <-source.entered:
			case <-time.After(time.Second):
				t.Fatal("source call did not enter")
			}
			if operation == "expiry" {
				clockMu.Lock()
				clock = now.Add(JobTicketLeaseDuration)
				clockMu.Unlock()
			}

			cleanupDone := make(chan error, 1)
			go func() {
				switch operation {
				case "revoke":
					cleanupDone <- store.Revoke(context.Background(), ticket, activation.Correlation)
				case "close":
					cleanupDone <- store.Close(context.Background())
				case "expiry":
					cleanupDone <- store.Validate(context.Background(), ticket, activation.Correlation)
				case "release":
					lease.Release()
					cleanupDone <- nil
				}
			}()
			select {
			case cleanupErr := <-cleanupDone:
				close(source.release)
				t.Fatalf("%s returned before source call joined: %v", operation, cleanupErr)
			case <-time.After(50 * time.Millisecond):
			}
			close(source.release)
			cleanupErr := <-cleanupDone
			switch operation {
			case "revoke", "close", "release":
				if cleanupErr != nil {
					t.Fatalf("%s error: %v", operation, cleanupErr)
				}
			case "expiry":
				if !errors.Is(cleanupErr, ErrTicketExpired) {
					t.Fatalf("expiry error = %v, want expired", cleanupErr)
				}
			}
			if fillErr := <-fillDone; fillErr == nil {
				t.Fatal("source call succeeded after cleanup began")
			}
		})
	}
}

func TestL8D3TicketConcurrentIssueSerializesEntropyAndProducesUniqueCapabilities(t *testing.T) {
	const count = 64
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	entropy := make([]byte, (count+1)*JobTicketRawBytes)
	for block := 0; block <= count; block++ {
		for index := 0; index < JobTicketRawBytes; index++ {
			entropy[block*JobTicketRawBytes+index] = byte(block + index)
		}
	}
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now: func() time.Time { return now }, entropy: bytes.NewReader(entropy),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)

	values := make(chan string, count)
	errorsSeen := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			ticket, issueErr := store.Issue(context.Background(), activation)
			if issueErr != nil {
				errorsSeen <- issueErr
				return
			}
			encoded := make([]byte, JobTicketEncodedBytes)
			if _, copyErr := ticket.CopyTo(encoded); copyErr != nil {
				errorsSeen <- copyErr
				return
			}
			values <- string(encoded)
		}()
	}
	group.Wait()
	close(values)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent Issue() error: %v", err)
	}
	unique := make(map[string]bool, count)
	for value := range values {
		unique[value] = true
	}
	if len(unique) != count {
		t.Fatalf("unique concurrent tickets = %d, want %d", len(unique), count)
	}
}

func l8D3TicketActivation(t *testing.T, now time.Time) TicketActivation {
	t.Helper()
	return TicketActivation{
		Correlation: TicketCorrelation{
			JobIdentityDigest:    [32]byte{1, 2, 3, 4},
			ServiceID:            ServiceIDAzureOpenAIResponsesV1,
			BindingID:            "binding-http-01",
			ActivationGeneration: "activation-generation-01",
			CatalogGeneration:    "catalog-generation-01",
			ListenerGeneration:   7,
		},
		IssuedAt: now,
		Source:   l8D3LiveSecretSource{},
	}
}

func l8D3AcquireTicket(t *testing.T, store *TicketStore, ticket *JobTicket, correlation TicketCorrelation) *TicketRequestLease {
	t.Helper()
	lease, err := l8D3AcquireTicketError(store, ticket, correlation)
	if err != nil {
		t.Fatalf("acquirePresentedTicket() error: %v", err)
	}
	return lease
}

func l8D3AcquireTicketError(store *TicketStore, ticket *JobTicket, correlation TicketCorrelation) (*TicketRequestLease, error) {
	mapping, err := credentialmemory.NewLockedMapping(JobTicketEncodedBytes)
	if err != nil {
		return nil, err
	}
	defer mapping.Destroy()
	if err := mapping.Load(context.Background(), func(destination []byte) (int, error) {
		return ticket.CopyTo(destination)
	}); err != nil {
		return nil, err
	}
	var lease *TicketRequestLease
	var acquireErr error
	err = mapping.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
		lease, acquireErr = store.acquirePresentedTicket(context.Background(), view, correlation)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lease, acquireErr
}

type l8D3LiveSecretSource struct{}

func (l8D3LiveSecretSource) FillSecret(context.Context, sandboxruntime.JobCredentialSecretSink) error {
	return nil
}

type l8D3BlockingSecretSource struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (source *l8D3BlockingSecretSource) FillSecret(_ context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	source.once.Do(func() { close(source.entered) })
	<-source.release
	return sink.WriteCredential([]byte("secret"))
}

type l8D3TestCredentialSink struct{}

func (l8D3TestCredentialSink) MaxCredentialBytes() int { return 32 }
func (l8D3TestCredentialSink) WriteCredential([]byte) error {
	return nil
}

type l8D3TicketCloser struct {
	mu       sync.Mutex
	count    int
	failures int
}

func (closer *l8D3TicketCloser) Close() error {
	closer.mu.Lock()
	defer closer.mu.Unlock()
	closer.count++
	if closer.failures > 0 {
		closer.failures--
		return errors.New("raw close failure api-key=canary")
	}
	return nil
}

func (closer *l8D3TicketCloser) Count() int {
	closer.mu.Lock()
	defer closer.mu.Unlock()
	return closer.count
}
