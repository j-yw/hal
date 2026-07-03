package firecrackerhost

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const (
	defaultBootAcceptanceTimeout      = 10 * time.Second
	defaultBootAcceptancePollInterval = 100 * time.Millisecond

	bootAcceptanceOperationPoll    = "poll"
	bootAcceptanceOperationRequest = "request"
	bootAcceptanceOperationSleep   = "sleep"
	bootAcceptanceOperationTimeout = "timeout"
)

var bootAcceptancePathLikePattern = regexp.MustCompile(`(?i)(?:[A-Za-z0-9._~@%+-]+/)+[^\s:'",]+|[^\s:'",/]+\.sock\b`)

// BootAcceptancePollingError wraps host-side API socket acceptance failures
// with sanitized public detail while preserving the original cause.
type BootAcceptancePollingError struct {
	Operation string
	Detail    string
	Err       error
}

func (err *BootAcceptancePollingError) Error() string {
	if err == nil {
		return ""
	}
	operation := safeBootAcceptanceOperation(err.Operation)
	message := "firecracker boot acceptance " + operation + " failed"
	if operation == bootAcceptanceOperationTimeout {
		message = "firecracker boot acceptance timed out"
	}
	if detail := strings.TrimSpace(err.Detail); detail != "" {
		return message + ": " + detail
	}
	return message
}

func (err *BootAcceptancePollingError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func (adapter *Adapter) waitForBootAcceptance(ctx context.Context, req firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error) {
	req, err := bootAcceptancePollRequest(req)
	if err != nil {
		return firecracker.BootAcceptanceResult{}, newBootAcceptancePollingError(bootAcceptanceOperationRequest, err)
	}

	clock := adapter.bootAcceptanceClock()
	sleeper := adapter.bootAcceptanceSleeper()
	timeout := adapter.bootAcceptanceTimeout()
	interval := adapter.bootAcceptancePollInterval()
	deadline := clock.Now().Add(timeout)
	firstPoll := true

	for {
		if err := ctx.Err(); err != nil {
			return firecracker.BootAcceptanceResult{}, newBootAcceptancePollingError(bootAcceptanceOperationPoll, err)
		}
		if !firstPoll && !clock.Now().Before(deadline) {
			return firecracker.BootAcceptanceResult{}, bootAcceptanceTimeoutError()
		}
		firstPoll = false

		result, err := adapter.poller.PollBootAcceptance(ctx, req)
		if err != nil {
			return firecracker.BootAcceptanceResult{}, newBootAcceptancePollingError(bootAcceptanceOperationPoll, err)
		}
		if result.ProcessAccepted && result.APISocketAvailable {
			return firecracker.BootAcceptanceResult{
				ProcessAccepted:    true,
				APISocketAvailable: true,
			}, nil
		}
		if !clock.Now().Before(deadline) {
			return firecracker.BootAcceptanceResult{}, bootAcceptanceTimeoutError()
		}
		if err := sleeper.Sleep(ctx, interval); err != nil {
			return firecracker.BootAcceptanceResult{}, newBootAcceptancePollingError(bootAcceptanceOperationSleep, err)
		}
	}
}

func (adapter *Adapter) bootAcceptanceClock() Clock {
	if adapter == nil || adapter.clock == nil {
		return systemClock{}
	}
	return adapter.clock
}

func (adapter *Adapter) bootAcceptanceSleeper() Sleeper {
	if adapter == nil || adapter.sleeper == nil {
		return contextSleeper{}
	}
	return adapter.sleeper
}

func (adapter *Adapter) bootAcceptanceTimeout() time.Duration {
	if adapter == nil || adapter.bootTimeout <= 0 {
		return defaultBootAcceptanceTimeout
	}
	return adapter.bootTimeout
}

func (adapter *Adapter) bootAcceptancePollInterval() time.Duration {
	if adapter == nil || adapter.bootInterval <= 0 {
		return defaultBootAcceptancePollInterval
	}
	return adapter.bootInterval
}

func bootAcceptancePollRequest(req firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceRequest, error) {
	apiSocket := req.APISocket
	apiSocket.Path = strings.TrimSpace(apiSocket.Path)
	if apiSocket.Role != firecracker.OperationPathRoleAPISocket {
		return firecracker.BootAcceptanceRequest{}, errors.New("API socket path role is invalid")
	}
	if apiSocket.Path == "" {
		return firecracker.BootAcceptanceRequest{}, errors.New("API socket path is required")
	}
	if hasBootAcceptancePathControl(apiSocket.Path) {
		return firecracker.BootAcceptanceRequest{}, errors.New("API socket path is invalid")
	}
	return firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{
			ID:     safeBootAcceptanceMetadataToken(req.Handle.ID),
			Source: safeBootAcceptanceMetadataToken(req.Handle.Source),
		},
		APISocket: apiSocket,
	}, nil
}

func hasBootAcceptancePathControl(path string) bool {
	for _, r := range path {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func safeBootAcceptanceMetadataToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || processSecretValuePattern.MatchString(value) {
		return ""
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "pid-"),
		strings.HasPrefix(lower, "pid_"),
		strings.HasPrefix(lower, "pid."),
		strings.HasPrefix(lower, "process-"),
		strings.HasPrefix(lower, "process_"),
		strings.HasPrefix(lower, "process."):
		return ""
	}
	hasNonDigit := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			hasNonDigit = true
		case r >= 'A' && r <= 'Z':
			hasNonDigit = true
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
			hasNonDigit = true
		default:
			return ""
		}
	}
	if !hasNonDigit {
		return ""
	}
	return value
}

func bootAcceptanceTimeoutError() *BootAcceptancePollingError {
	return &BootAcceptancePollingError{
		Operation: bootAcceptanceOperationTimeout,
		Detail:    "host-side API socket was not accepted before timeout",
		Err:       context.DeadlineExceeded,
	}
}

func newBootAcceptancePollingError(operation string, cause error) *BootAcceptancePollingError {
	if cause == nil {
		cause = errors.New("boot acceptance failed")
	}
	return &BootAcceptancePollingError{
		Operation: safeBootAcceptanceOperation(operation),
		Detail:    sanitizeBootAcceptanceErrorDetail(cause),
		Err:       cause,
	}
}

func safeBootAcceptanceOperation(operation string) string {
	switch strings.TrimSpace(operation) {
	case bootAcceptanceOperationPoll:
		return bootAcceptanceOperationPoll
	case bootAcceptanceOperationRequest:
		return bootAcceptanceOperationRequest
	case bootAcceptanceOperationSleep:
		return bootAcceptanceOperationSleep
	case bootAcceptanceOperationTimeout:
		return bootAcceptanceOperationTimeout
	default:
		return bootAcceptanceOperationPoll
	}
}

func sanitizeBootAcceptanceErrorDetail(cause error) string {
	if cause == nil {
		return ""
	}
	detail := sanitizeProcessLifecycleErrorDetail(cause)
	detail = bootAcceptancePathLikePattern.ReplaceAllString(detail, "[redacted-path]")
	detail = strings.Join(strings.Fields(detail), " ")
	return detail
}
