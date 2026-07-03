package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestAdapterPollsGuestReadinessUntilReady(t *testing.T) {
	clock := &guestReadinessFakeClock{now: time.Unix(500, 0)}
	sleeper := &guestReadinessAdvancingSleeper{clock: clock}
	probe := &sequenceGuestReadinessProbe{
		results: []firecracker.GuestReadinessResult{
			{
				State:     sandboxruntime.RuntimeGuestReadinessStateWaiting,
				Transport: "VSock",
				Labels:    []string{"probe_pending", "https://ready.example.test/status"},
			},
			{
				State:     sandboxruntime.RuntimeGuestReadinessStateReady,
				Transport: "VSock",
				Labels: []string{
					"probe_ok",
					"ready",
					"status_ok",
					"exec_support",
					"/Users/alice/private/readiness.sock",
				},
			},
		},
	}
	adapter := NewAdapter(
		WithGuestReadinessProbe(probe),
		WithClock(clock),
		WithSleeper(sleeper),
		WithGuestReadinessTimeout(10*time.Second),
		WithGuestReadinessPollInterval(time.Second),
	)

	got, err := adapter.WaitForGuestReadiness(context.Background(), firecracker.GuestReadinessRequest{
		Handle: firecracker.ProcessHandleMetadata{
			ID:     "/Users/alice/private/pid-4242-token",
			Source: "firecrackerhost token=ghp_secret",
		},
		RuntimeID: "fc-runtime-1234",
	})
	if err != nil {
		t.Fatalf("WaitForGuestReadiness() error = %v, want nil", err)
	}

	want := firecracker.GuestReadinessResult{
		State:     sandboxruntime.RuntimeGuestReadinessStateReady,
		Transport: "vsock",
		Labels:    []string{"ready", "probe_ok", "status_ok"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WaitForGuestReadiness() = %#v, want sanitized result %#v", got, want)
	}
	if probe.calls != 2 {
		t.Fatalf("probe calls = %d, want 2", probe.calls)
	}
	if sleeper.calls != 1 {
		t.Fatalf("sleeper calls = %d, want 1", sleeper.calls)
	}
	if got := clock.now; !got.Equal(time.Unix(501, 0)) {
		t.Fatalf("fake clock = %s, want one deterministic interval", got)
	}
	if len(probe.requests) != 2 {
		t.Fatalf("probe requests = %d, want 2", len(probe.requests))
	}
	for _, req := range probe.requests {
		if req.Handle.ID != "" || req.Handle.Source != "" {
			t.Fatalf("probe request handle = %#v, want unsafe handle metadata cleared", req.Handle)
		}
		if req.RuntimeID != "fc-runtime-1234" {
			t.Fatalf("probe request runtime ID = %q, want sanitized runtime ID", req.RuntimeID)
		}
	}
}

func TestAdapterGuestReadinessPollingTimesOutDeterministically(t *testing.T) {
	clock := &guestReadinessFakeClock{now: time.Unix(600, 0)}
	sleeper := &guestReadinessAdvancingSleeper{clock: clock}
	probe := &sequenceGuestReadinessProbe{
		results: []firecracker.GuestReadinessResult{
			{
				State:     sandboxruntime.RuntimeGuestReadinessStateWaiting,
				Transport: "vsock",
				Labels:    []string{"probe_pending"},
			},
		},
	}
	adapter := NewAdapter(
		WithGuestReadinessProbe(probe),
		WithClock(clock),
		WithSleeper(sleeper),
		WithGuestReadinessTimeout(3*time.Second),
		WithGuestReadinessPollInterval(time.Second),
	)

	got, err := adapter.WaitForGuestReadiness(context.Background(), firecracker.NewGuestReadinessRequest(
		firecracker.ProcessHandleMetadata{ID: "fc-handle-ready", Source: "firecrackerhost"},
		"fc-runtime-timeout",
	))

	if err == nil {
		t.Fatal("WaitForGuestReadiness() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(timeout, DeadlineExceeded) = false for %v", err)
	}
	var pollingErr *GuestReadinessPollingError
	if !errors.As(err, &pollingErr) {
		t.Fatalf("error type = %T, want *GuestReadinessPollingError", err)
	}
	if pollingErr.Operation != guestReadinessOperationTimeout {
		t.Fatalf("polling operation = %q, want %q", pollingErr.Operation, guestReadinessOperationTimeout)
	}
	if !reflect.DeepEqual(got, firecracker.GuestReadinessResult{}) {
		t.Fatalf("guest readiness result = %#v, want zero result on timeout", got)
	}
	if probe.calls != 3 {
		t.Fatalf("probe calls = %d, want one deterministic call per second before timeout", probe.calls)
	}
	if sleeper.calls != 3 {
		t.Fatalf("sleeper calls = %d, want 3", sleeper.calls)
	}
	if got := clock.now; !got.Equal(time.Unix(603, 0)) {
		t.Fatalf("fake clock = %s, want timeout deadline", got)
	}
}

func TestAdapterGuestReadinessProbeErrorsAreSanitized(t *testing.T) {
	clock := &guestReadinessFakeClock{now: time.Unix(700, 0)}
	unsafeErr := fmt.Errorf("probe failed on unix:///Users/alice/private/readiness.sock endpoint=https://ready.example.test/status ip=10.0.2.15 host=guest.internal port=2049 transport=vsock://3:1024 OPENAI_API_KEY=sk-live-secret token=ghp_secret")
	probe := &sequenceGuestReadinessProbe{err: unsafeErr}
	adapter := NewAdapter(
		WithGuestReadinessProbe(probe),
		WithClock(clock),
		WithSleeper(&guestReadinessAdvancingSleeper{clock: clock}),
		WithGuestReadinessTimeout(time.Second),
		WithGuestReadinessPollInterval(time.Second),
	)

	_, err := adapter.WaitForGuestReadiness(context.Background(), firecracker.NewGuestReadinessRequest(
		firecracker.ProcessHandleMetadata{ID: "fc-handle-ready", Source: "firecrackerhost"},
		"fc-runtime-error",
	))

	if err == nil {
		t.Fatal("WaitForGuestReadiness() error = nil, want probe error")
	}
	if !errors.Is(err, unsafeErr) {
		t.Fatalf("errors.Is(probe error, unsafeErr) = false for %v", err)
	}
	assertGuestReadinessPublicTextRedacted(t, err.Error(),
		"unix://",
		"/Users/alice",
		"private",
		"readiness.sock",
		"ready.example.test",
		"10.0.2.15",
		"guest.internal",
		"2049",
		"vsock://",
		"OPENAI_API_KEY",
		"sk-live-secret",
		"ghp_secret",
	)
}

func TestGuestAgentReadinessProbeDelegatesProtocolReadinessAndSanitizesMetadata(t *testing.T) {
	client := &recordingGuestAgentReadinessClient{
		response: &guestagent.ReadinessResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
			Ready:           true,
			Status:          guestagent.ReadinessStatusReady,
		},
	}
	probe := NewGuestAgentReadinessProbe(GuestAgentReadinessProbeOptions{
		Client:    client,
		Transport: "UNIX",
		Labels: []string{
			"protocol_ok",
			"exec_support",
			"copy_support",
			"network_proxy",
			"credential_proxy",
			"template",
			"hosted_vendor",
			"docker_in_guest",
			"secure_runtime",
			"agent_ready",
		},
		Timing: &guestagent.TimingMetadata{TimeoutMillis: 2500},
	})

	got, err := probe.ProbeGuestReadiness(context.Background(), firecracker.GuestReadinessRequest{
		Handle: firecracker.ProcessHandleMetadata{
			ID:     "/Users/alice/private/firecracker.pid",
			Source: "token=ghp_secret",
		},
		RuntimeID: "fc-runtime",
	})
	if err != nil {
		t.Fatalf("ProbeGuestReadiness() error = %v, want nil", err)
	}

	want := firecracker.GuestReadinessResult{
		State:     sandboxruntime.RuntimeGuestReadinessStateReady,
		Transport: "unix",
		Labels:    []string{"ready", "protocol", "protocol_ok"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProbeGuestReadiness() = %#v, want sanitized guest-agent readiness %#v", got, want)
	}
	if client.calls != 1 {
		t.Fatalf("guest-agent readiness calls = %d, want 1", client.calls)
	}
	if client.request.ProtocolVersion != guestagent.ProtocolVersionV1 || client.request.Operation != guestagent.OperationReadiness {
		t.Fatalf("readiness request header = %#v, want guest-agent v1 readiness", client.request)
	}
	if client.request.Timing == nil || client.request.Timing.TimeoutMillis != 2500 {
		t.Fatalf("readiness timing = %#v, want cloned timeout", client.request.Timing)
	}
	encoded := fmt.Sprintf("%#v", got)
	assertGuestReadinessPublicTextRedacted(t, encoded,
		"/Users/alice",
		"ghp_secret",
		"exec_support",
		"copy_support",
		"network_proxy",
		"credential_proxy",
		"template",
		"hosted_vendor",
		"docker_in_guest",
		"secure_runtime",
		"agent_ready",
	)
}

func TestAdapterGuestAgentReadinessTimeoutReturnsStructuredError(t *testing.T) {
	clock := &guestReadinessFakeClock{now: time.Unix(800, 0)}
	sleeper := &guestReadinessAdvancingSleeper{clock: clock}
	client := &recordingGuestAgentReadinessClient{
		response: &guestagent.ReadinessResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
			Ready:           false,
			Status:          guestagent.ReadinessStatusNotReady,
		},
	}
	adapter := NewAdapter(
		WithGuestReadinessProbe(NewGuestAgentReadinessProbe(GuestAgentReadinessProbeOptions{Client: client})),
		WithClock(clock),
		WithSleeper(sleeper),
		WithGuestReadinessTimeout(2*time.Second),
		WithGuestReadinessPollInterval(time.Second),
	)

	got, err := adapter.WaitForGuestReadiness(context.Background(), firecracker.NewGuestReadinessRequest(
		firecracker.ProcessHandleMetadata{ID: "fc-handle-ready", Source: "firecrackerhost"},
		"fc-runtime-agent-timeout",
	))

	if err == nil {
		t.Fatal("WaitForGuestReadiness() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(timeout, DeadlineExceeded) = false for %v", err)
	}
	var pollingErr *GuestReadinessPollingError
	if !errors.As(err, &pollingErr) {
		t.Fatalf("error type = %T, want *GuestReadinessPollingError", err)
	}
	if pollingErr.Operation != guestReadinessOperationTimeout {
		t.Fatalf("polling operation = %q, want %q", pollingErr.Operation, guestReadinessOperationTimeout)
	}
	if !reflect.DeepEqual(got, firecracker.GuestReadinessResult{}) {
		t.Fatalf("guest readiness result = %#v, want zero result on timeout", got)
	}
	if client.calls != 2 {
		t.Fatalf("guest-agent readiness calls = %d, want deterministic probes until timeout", client.calls)
	}
	if sleeper.calls != 2 {
		t.Fatalf("sleeper calls = %d, want 2", sleeper.calls)
	}
}

func TestAdapterGuestAgentReadinessCancellationReturnsStructuredError(t *testing.T) {
	client := &recordingGuestAgentReadinessClient{
		readiness: func(context.Context, guestagent.ReadinessRequest) (*guestagent.ReadinessResponse, error) {
			return nil, context.Canceled
		},
	}
	adapter := NewAdapter(WithGuestReadinessProbe(NewGuestAgentReadinessProbe(GuestAgentReadinessProbeOptions{Client: client})))

	_, err := adapter.WaitForGuestReadiness(context.Background(), firecracker.NewGuestReadinessRequest(
		firecracker.ProcessHandleMetadata{ID: "fc-handle-ready", Source: "firecrackerhost"},
		"fc-runtime-agent-canceled",
	))

	if err == nil {
		t.Fatal("WaitForGuestReadiness() error = nil, want cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(cancellation, context.Canceled) = false for %v", err)
	}
	var pollingErr *GuestReadinessPollingError
	if !errors.As(err, &pollingErr) {
		t.Fatalf("error type = %T, want *GuestReadinessPollingError", err)
	}
	if pollingErr.Operation != guestReadinessOperationProbe {
		t.Fatalf("polling operation = %q, want %q", pollingErr.Operation, guestReadinessOperationProbe)
	}
	var protocolErr *guestagent.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("error chain = %T %v, want guest-agent protocol error", err, err)
	}
	if protocolErr.Code != guestagent.ErrorCodeRequestCanceled || protocolErr.Operation != guestagent.OperationReadiness {
		t.Fatalf("protocol error = %#v, want readiness request_canceled", protocolErr)
	}
	if client.calls != 1 {
		t.Fatalf("guest-agent readiness calls = %d, want 1", client.calls)
	}
}

type sequenceGuestReadinessProbe struct {
	calls    int
	requests []firecracker.GuestReadinessRequest
	results  []firecracker.GuestReadinessResult
	err      error
}

type recordingGuestAgentReadinessClient struct {
	calls     int
	request   guestagent.ReadinessRequest
	response  *guestagent.ReadinessResponse
	err       error
	readiness func(context.Context, guestagent.ReadinessRequest) (*guestagent.ReadinessResponse, error)
}

func (client *recordingGuestAgentReadinessClient) Readiness(ctx context.Context, req guestagent.ReadinessRequest) (*guestagent.ReadinessResponse, error) {
	client.calls++
	client.request = req
	if client.readiness != nil {
		return client.readiness(ctx, req)
	}
	if client.err != nil {
		return nil, client.err
	}
	return client.response, nil
}

func (probe *sequenceGuestReadinessProbe) ProbeGuestReadiness(_ context.Context, req firecracker.GuestReadinessRequest) (firecracker.GuestReadinessResult, error) {
	probe.calls++
	probe.requests = append(probe.requests, req)
	if probe.err != nil {
		return firecracker.GuestReadinessResult{}, probe.err
	}
	if len(probe.results) == 0 {
		return firecracker.GuestReadinessResult{}, nil
	}
	if probe.calls <= len(probe.results) {
		return probe.results[probe.calls-1], nil
	}
	return probe.results[len(probe.results)-1], nil
}

type guestReadinessFakeClock struct {
	now time.Time
}

func (clock *guestReadinessFakeClock) Now() time.Time {
	return clock.now
}

type guestReadinessAdvancingSleeper struct {
	clock     *guestReadinessFakeClock
	calls     int
	durations []time.Duration
	err       error
}

func (sleeper *guestReadinessAdvancingSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	sleeper.calls++
	sleeper.durations = append(sleeper.durations, duration)
	if sleeper.err != nil {
		return sleeper.err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sleeper.clock != nil {
		sleeper.clock.now = sleeper.clock.now.Add(duration)
	}
	return nil
}

func assertGuestReadinessPublicTextRedacted(t *testing.T, publicText string, unsafeFragments ...string) {
	t.Helper()
	for _, unsafe := range unsafeFragments {
		if strings.TrimSpace(unsafe) == "" {
			continue
		}
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
}
