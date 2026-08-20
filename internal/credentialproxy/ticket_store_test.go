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
	} {
		if rendered != "credentialproxy.JobTicket{live}" || bytes.Contains([]byte(rendered), encoded) {
			t.Fatalf("ticket formatting = %q, want static live marker", rendered)
		}
	}
	if _, err := json.Marshal(ticket); !errors.Is(err, ErrLiveTicketNotSerializable) {
		t.Fatalf("Marshal(ticket) error = %v, want serialization denial", err)
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

type l8D3TicketCloser struct {
	mu    sync.Mutex
	count int
}

func (closer *l8D3TicketCloser) Close() error {
	closer.mu.Lock()
	closer.count++
	closer.mu.Unlock()
	return nil
}

func (closer *l8D3TicketCloser) Count() int {
	closer.mu.Lock()
	defer closer.mu.Unlock()
	return closer.count
}
