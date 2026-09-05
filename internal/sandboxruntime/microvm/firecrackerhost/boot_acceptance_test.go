package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestAdapterPollsBootAcceptanceUntilAPISocketReady(t *testing.T) {
	clock := &bootAcceptanceFakeClock{now: time.Unix(100, 0)}
	sleeper := &bootAcceptanceAdvancingSleeper{clock: clock}
	poller := &sequenceBootAcceptancePoller{
		results: []firecracker.BootAcceptanceResult{
			{ProcessAccepted: true},
			{ProcessAccepted: true},
			{ProcessAccepted: true, APISocketAvailable: true},
		},
	}
	req := firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: "/tmp/hal/firecracker-state/firecracker.sock",
		},
	}
	adapter := NewAdapter(
		WithBootAcceptancePoller(poller),
		WithClock(clock),
		WithSleeper(sleeper),
		WithBootAcceptanceTimeout(10*time.Second),
		WithBootAcceptancePollInterval(time.Second),
	)

	got, err := adapter.WaitForBootAcceptance(context.Background(), req)
	if err != nil {
		t.Fatalf("WaitForBootAcceptance() error = %v, want nil", err)
	}

	if !got.ProcessAccepted || !got.APISocketAvailable {
		t.Fatalf("boot acceptance result = %#v, want process and API socket accepted", got)
	}
	if poller.calls != 3 {
		t.Fatalf("poller calls = %d, want 3", poller.calls)
	}
	if sleeper.calls != 2 {
		t.Fatalf("sleeper calls = %d, want 2", sleeper.calls)
	}
	if got := clock.now; !got.Equal(time.Unix(102, 0)) {
		t.Fatalf("fake clock = %s, want two deterministic intervals", got)
	}
	if len(poller.requests) != 3 {
		t.Fatalf("poller requests = %d, want 3", len(poller.requests))
	}
	if poller.requests[0].APISocket.Path != req.APISocket.Path {
		t.Fatalf("poller API socket path = %q, want raw injected path", poller.requests[0].APISocket.Path)
	}
}

func TestAdapterBootAcceptancePollingTimesOutDeterministically(t *testing.T) {
	clock := &bootAcceptanceFakeClock{now: time.Unix(200, 0)}
	sleeper := &bootAcceptanceAdvancingSleeper{clock: clock}
	poller := &sequenceBootAcceptancePoller{
		results: []firecracker.BootAcceptanceResult{
			{ProcessAccepted: true},
		},
	}
	adapter := NewAdapter(
		WithBootAcceptancePoller(poller),
		WithClock(clock),
		WithSleeper(sleeper),
		WithBootAcceptanceTimeout(3*time.Second),
		WithBootAcceptancePollInterval(time.Second),
	)

	got, err := adapter.WaitForBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: "/tmp/hal/firecracker-state/firecracker.sock",
		},
	})

	if err == nil {
		t.Fatal("WaitForBootAcceptance() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(timeout, DeadlineExceeded) = false for %v", err)
	}
	var pollingErr *BootAcceptancePollingError
	if !errors.As(err, &pollingErr) {
		t.Fatalf("error type = %T, want *BootAcceptancePollingError", err)
	}
	if pollingErr.Operation != bootAcceptanceOperationTimeout {
		t.Fatalf("polling operation = %q, want %q", pollingErr.Operation, bootAcceptanceOperationTimeout)
	}
	if got.ProcessAccepted || got.APISocketAvailable {
		t.Fatalf("boot acceptance result = %#v, want zero result on timeout", got)
	}
	if poller.calls != 3 {
		t.Fatalf("poller calls = %d, want one deterministic call per second before timeout", poller.calls)
	}
	if sleeper.calls != 3 {
		t.Fatalf("sleeper calls = %d, want 3", sleeper.calls)
	}
	if got := clock.now; !got.Equal(time.Unix(203, 0)) {
		t.Fatalf("fake clock = %s, want timeout deadline", got)
	}
}

func TestAdapterBootAcceptancePollingErrorsAreSanitized(t *testing.T) {
	clock := &bootAcceptanceFakeClock{now: time.Unix(300, 0)}
	socketPath := "/Users/alice/private/firecracker-state/firecracker.sock"
	unsafeErr := fmt.Errorf("stat %s failed in /Users/alice/private/firecracker-state token=ghp_secret OPENAI_API_KEY=sk-live-secret", socketPath)
	poller := &sequenceBootAcceptancePoller{err: unsafeErr}
	adapter := NewAdapter(
		WithBootAcceptancePoller(poller),
		WithClock(clock),
		WithSleeper(&bootAcceptanceAdvancingSleeper{clock: clock}),
		WithBootAcceptanceTimeout(time.Second),
		WithBootAcceptancePollInterval(time.Second),
	)

	_, err := adapter.WaitForBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: socketPath,
		},
	})

	if err == nil {
		t.Fatal("WaitForBootAcceptance() error = nil, want poll error")
	}
	if !errors.Is(err, unsafeErr) {
		t.Fatalf("errors.Is(poll error, unsafeErr) = false for %v", err)
	}
	assertBootAcceptancePublicTextRedacted(t, err.Error(),
		socketPath,
		"/Users/alice",
		"private",
		"firecracker.sock",
		"ghp_secret",
		"OPENAI_API_KEY",
		"sk-live-secret",
	)
}

func TestAdapterBootAcceptanceRequestMappingRedactsUnsafeHandleFromReturnedErrors(t *testing.T) {
	clock := &bootAcceptanceFakeClock{now: time.Unix(400, 0)}
	socketPath := "/Users/alice/private/firecracker-state/firecracker.sock"
	poller := &requestEchoBootAcceptancePoller{}
	adapter := NewAdapter(
		WithBootAcceptancePoller(poller),
		WithClock(clock),
		WithSleeper(&bootAcceptanceAdvancingSleeper{clock: clock}),
		WithBootAcceptanceTimeout(time.Second),
		WithBootAcceptancePollInterval(time.Second),
	)

	_, err := adapter.WaitForBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{
			ID:     "/Users/alice/private/pid-4242-ghp_secret",
			Source: "firecrackerhost/../../secret",
		},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: socketPath,
		},
	})

	if err == nil {
		t.Fatal("WaitForBootAcceptance() error = nil, want request echo poll error")
	}
	if len(poller.requests) != 1 {
		t.Fatalf("poller requests = %d, want 1", len(poller.requests))
	}
	mapped := poller.requests[0]
	if mapped.Handle.ID != "" || mapped.Handle.Source != "" {
		t.Fatalf("mapped handle = %#v, want unsafe handle metadata cleared", mapped.Handle)
	}
	if mapped.APISocket.Path != socketPath {
		t.Fatalf("mapped API socket path = %q, want raw path available only to poller", mapped.APISocket.Path)
	}
	assertBootAcceptancePublicTextRedacted(t, err.Error(),
		socketPath,
		"/Users/alice",
		"private",
		"pid-4242",
		"ghp_secret",
		"firecrackerhost/../../secret",
		"firecracker.sock",
	)
}

func TestAPISocketBootAcceptancePollerReportsReadyOnlyForSocket(t *testing.T) {
	socketPath := "/tmp/hal/firecracker-state/firecracker.sock"
	tests := []struct {
		name string
		info os.FileInfo
		err  error
		want firecracker.BootAcceptanceResult
	}{
		{
			name: "socket",
			info: fakeBootAcceptanceFileInfo{mode: os.ModeSocket},
			want: firecracker.BootAcceptanceResult{
				ProcessAccepted:    true,
				APISocketAvailable: true,
			},
		},
		{
			name: "regular file",
			info: fakeBootAcceptanceFileInfo{mode: 0},
			want: firecracker.BootAcceptanceResult{},
		},
		{
			name: "directory",
			info: fakeBootAcceptanceFileInfo{mode: os.ModeDir},
			want: firecracker.BootAcceptanceResult{},
		},
		{
			name: "missing",
			err:  fmt.Errorf("socket missing: %w", os.ErrNotExist),
			want: firecracker.BootAcceptanceResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filesystem := &fakeBootAcceptanceFilesystem{info: tt.info, err: tt.err}
			poller := APISocketBootAcceptancePoller{fs: filesystem}

			got, err := poller.PollBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{
				Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
				APISocket: firecracker.OperationPathReference{
					Role: firecracker.OperationPathRoleAPISocket,
					Path: socketPath,
				},
			})

			if err != nil {
				t.Fatalf("PollBootAcceptance() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("PollBootAcceptance() = %#v, want %#v", got, tt.want)
			}
			if filesystem.calls != 1 {
				t.Fatalf("filesystem calls = %d, want 1", filesystem.calls)
			}
			if filesystem.paths[0] != socketPath {
				t.Fatalf("filesystem path = %q, want planned API socket path", filesystem.paths[0])
			}
		})
	}
}

func TestAPISocketBootAcceptancePollerStatErrorsAreSanitized(t *testing.T) {
	socketPath := "/Users/alice/private/firecracker-state/firecracker.sock"
	statErr := &bootAcceptanceTypedStatError{
		message: "stat " + socketPath + " failed for /Users/alice/private/rootfs.ext4 endpoint=127.0.0.1:8080 token=ghp_secret OPENAI_API_KEY=sk-live-secret",
	}
	poller := APISocketBootAcceptancePoller{
		fs: &fakeBootAcceptanceFilesystem{err: statErr},
	}

	_, err := poller.PollBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: socketPath,
		},
	})

	if err == nil {
		t.Fatal("PollBootAcceptance() error = nil, want sanitized stat error")
	}
	if !errors.Is(err, statErr) {
		t.Fatalf("errors.Is(poll error, statErr) = false for %v", err)
	}
	var typedErr *bootAcceptanceTypedStatError
	if !errors.As(err, &typedErr) {
		t.Fatalf("errors.As(poll error, *bootAcceptanceTypedStatError) = false for %v", err)
	}
	var pollingErr *BootAcceptancePollingError
	if !errors.As(err, &pollingErr) {
		t.Fatalf("error type = %T, want *BootAcceptancePollingError", err)
	}
	assertBootAcceptancePublicTextRedacted(t, err.Error(),
		socketPath,
		"/Users/alice",
		"private",
		"rootfs.ext4",
		"127.0.0.1:8080",
		"ghp_secret",
		"OPENAI_API_KEY",
		"sk-live-secret",
	)
}

func TestAdapterWithAPISocketBootAcceptancePollerTimeoutIsSanitized(t *testing.T) {
	clock := &bootAcceptanceFakeClock{now: time.Unix(500, 0)}
	socketPath := "/Users/alice/private/firecracker-state/firecracker.sock"
	adapter := NewAdapter(
		WithBootAcceptancePoller(APISocketBootAcceptancePoller{
			fs: &fakeBootAcceptanceFilesystem{err: os.ErrNotExist},
		}),
		WithClock(clock),
		WithSleeper(&bootAcceptanceAdvancingSleeper{clock: clock}),
		WithBootAcceptanceTimeout(2*time.Second),
		WithBootAcceptancePollInterval(time.Second),
	)

	got, err := adapter.WaitForBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: socketPath,
		},
	})

	if err == nil {
		t.Fatal("WaitForBootAcceptance() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(timeout, DeadlineExceeded) = false for %v", err)
	}
	var pollingErr *BootAcceptancePollingError
	if !errors.As(err, &pollingErr) {
		t.Fatalf("error type = %T, want *BootAcceptancePollingError", err)
	}
	if got.ProcessAccepted || got.APISocketAvailable {
		t.Fatalf("boot acceptance result = %#v, want zero result on timeout", got)
	}
	assertBootAcceptancePublicTextRedacted(t, err.Error(),
		socketPath,
		"/Users/alice",
		"private",
		"firecracker.sock",
	)
}

type sequenceBootAcceptancePoller struct {
	calls    int
	requests []firecracker.BootAcceptanceRequest
	results  []firecracker.BootAcceptanceResult
	err      error
}

func (poller *sequenceBootAcceptancePoller) PollBootAcceptance(_ context.Context, req firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error) {
	poller.calls++
	poller.requests = append(poller.requests, req)
	if poller.err != nil {
		return firecracker.BootAcceptanceResult{}, poller.err
	}
	if len(poller.results) == 0 {
		return firecracker.BootAcceptanceResult{}, nil
	}
	if poller.calls <= len(poller.results) {
		return poller.results[poller.calls-1], nil
	}
	return poller.results[len(poller.results)-1], nil
}

type requestEchoBootAcceptancePoller struct {
	requests []firecracker.BootAcceptanceRequest
}

func (poller *requestEchoBootAcceptancePoller) PollBootAcceptance(_ context.Context, req firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error) {
	poller.requests = append(poller.requests, req)
	return firecracker.BootAcceptanceResult{}, fmt.Errorf("handle=%s source=%s apiSocket=%s", req.Handle.ID, req.Handle.Source, req.APISocket.Path)
}

type fakeBootAcceptanceFilesystem struct {
	calls int
	paths []string
	info  os.FileInfo
	err   error
}

func (filesystem *fakeBootAcceptanceFilesystem) Lstat(path string) (os.FileInfo, error) {
	filesystem.calls++
	filesystem.paths = append(filesystem.paths, path)
	return filesystem.info, filesystem.err
}

type fakeBootAcceptanceFileInfo struct {
	mode os.FileMode
}

func (info fakeBootAcceptanceFileInfo) Name() string {
	return "firecracker.sock"
}

func (info fakeBootAcceptanceFileInfo) Size() int64 {
	return 0
}

func (info fakeBootAcceptanceFileInfo) Mode() os.FileMode {
	return info.mode
}

func (info fakeBootAcceptanceFileInfo) ModTime() time.Time {
	return time.Time{}
}

func (info fakeBootAcceptanceFileInfo) IsDir() bool {
	return info.mode.IsDir()
}

func (info fakeBootAcceptanceFileInfo) Sys() any {
	return nil
}

type bootAcceptanceTypedStatError struct {
	message string
}

func (err *bootAcceptanceTypedStatError) Error() string {
	return err.message
}

type bootAcceptanceFakeClock struct {
	now time.Time
}

func (clock *bootAcceptanceFakeClock) Now() time.Time {
	return clock.now
}

type bootAcceptanceAdvancingSleeper struct {
	clock     *bootAcceptanceFakeClock
	calls     int
	durations []time.Duration
	err       error
}

func (sleeper *bootAcceptanceAdvancingSleeper) Sleep(ctx context.Context, duration time.Duration) error {
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

func assertBootAcceptancePublicTextRedacted(t *testing.T, publicText string, unsafeFragments ...string) {
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
