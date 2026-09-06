package firecrackerhost

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const (
	defaultGuestReadinessTimeout      = 30 * time.Second
	defaultGuestReadinessPollInterval = 250 * time.Millisecond

	guestReadinessOperationProbe   = "probe"
	guestReadinessOperationSleep   = "sleep"
	guestReadinessOperationTimeout = "timeout"
)

var (
	guestReadinessURLPattern        = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"]+`)
	guestReadinessAssignmentPattern = regexp.MustCompile(`(?i)\b(?:endpoint|address|transport|socket|host|hostname|ip|port|path|url|uri|secret|token|password|credential|authorization|bearer)\s*[:=]\s*\S+`)
	guestReadinessIPv4Pattern       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?::[0-9]+)?\b`)
	guestReadinessHostPortPattern   = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9.-]*:[0-9]+\b`)
	guestReadinessDomainPattern     = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`)
)

// GuestReadinessPollingError wraps host-side guest readiness failures with
// sanitized public detail while preserving the original cause.
type GuestReadinessPollingError struct {
	Operation string
	Detail    string
	Err       error
}

func (err *GuestReadinessPollingError) Error() string {
	if err == nil {
		return ""
	}
	operation := safeGuestReadinessOperation(err.Operation)
	message := "firecracker guest readiness " + operation + " failed"
	if operation == guestReadinessOperationTimeout {
		message = "firecracker guest readiness timed out"
	}
	if detail := strings.TrimSpace(err.Detail); detail != "" {
		return message + ": " + detail
	}
	return message
}

func (err *GuestReadinessPollingError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func (adapter *Adapter) waitForGuestReadiness(ctx context.Context, req firecracker.GuestReadinessRequest) (firecracker.GuestReadinessResult, error) {
	req = firecracker.SanitizeGuestReadinessRequest(req)

	clock := adapter.guestReadinessClock()
	sleeper := adapter.guestReadinessSleeper()
	timeout := adapter.guestReadinessTimeout()
	interval := adapter.guestReadinessPollInterval()
	deadline := clock.Now().Add(timeout)
	firstProbe := true

	for {
		if err := ctx.Err(); err != nil {
			return firecracker.GuestReadinessResult{}, newGuestReadinessPollingError(guestReadinessOperationProbe, err)
		}
		if !firstProbe && !clock.Now().Before(deadline) {
			return firecracker.GuestReadinessResult{}, guestReadinessTimeoutError()
		}
		firstProbe = false

		result, err := adapter.guestReadinessProbe.ProbeGuestReadiness(ctx, req)
		if err != nil {
			return firecracker.GuestReadinessResult{}, newGuestReadinessPollingError(guestReadinessOperationProbe, err)
		}
		result = firecracker.SanitizeGuestReadinessResult(result)
		if result.State == sandboxruntime.RuntimeGuestReadinessStateReady {
			return result, nil
		}
		if !clock.Now().Before(deadline) {
			return firecracker.GuestReadinessResult{}, guestReadinessTimeoutError()
		}
		if err := sleeper.Sleep(ctx, interval); err != nil {
			return firecracker.GuestReadinessResult{}, newGuestReadinessPollingError(guestReadinessOperationSleep, err)
		}
	}
}

func (adapter *Adapter) guestReadinessClock() Clock {
	if adapter == nil || adapter.clock == nil {
		return systemClock{}
	}
	return adapter.clock
}

func (adapter *Adapter) guestReadinessSleeper() Sleeper {
	if adapter == nil || adapter.sleeper == nil {
		return contextSleeper{}
	}
	return adapter.sleeper
}

func (adapter *Adapter) guestReadinessTimeout() time.Duration {
	if adapter == nil || adapter.guestTimeout <= 0 {
		return defaultGuestReadinessTimeout
	}
	return adapter.guestTimeout
}

func (adapter *Adapter) guestReadinessPollInterval() time.Duration {
	if adapter == nil || adapter.guestInterval <= 0 {
		return defaultGuestReadinessPollInterval
	}
	return adapter.guestInterval
}

func guestReadinessTimeoutError() *GuestReadinessPollingError {
	return &GuestReadinessPollingError{
		Operation: guestReadinessOperationTimeout,
		Detail:    "guest readiness was not reported before timeout",
		Err:       context.DeadlineExceeded,
	}
}

func newGuestReadinessPollingError(operation string, cause error) *GuestReadinessPollingError {
	if cause == nil {
		cause = errors.New("guest readiness failed")
	}
	return &GuestReadinessPollingError{
		Operation: safeGuestReadinessOperation(operation),
		Detail:    sanitizeGuestReadinessErrorDetail(cause),
		Err:       cause,
	}
}

func safeGuestReadinessOperation(operation string) string {
	switch strings.TrimSpace(operation) {
	case guestReadinessOperationProbe:
		return guestReadinessOperationProbe
	case guestReadinessOperationSleep:
		return guestReadinessOperationSleep
	case guestReadinessOperationTimeout:
		return guestReadinessOperationTimeout
	default:
		return guestReadinessOperationProbe
	}
}

func sanitizeGuestReadinessErrorDetail(cause error) string {
	if cause == nil {
		return ""
	}
	detail := sanitizeProcessLifecycleErrorDetail(cause)
	detail = guestReadinessURLPattern.ReplaceAllString(detail, "[redacted-endpoint]")
	detail = guestReadinessAssignmentPattern.ReplaceAllString(detail, "[redacted-detail]")
	detail = guestReadinessIPv4Pattern.ReplaceAllString(detail, "[redacted-ip]")
	detail = guestReadinessHostPortPattern.ReplaceAllString(detail, "[redacted-endpoint]")
	detail = guestReadinessDomainPattern.ReplaceAllString(detail, "[redacted-endpoint]")
	detail = bootAcceptancePathLikePattern.ReplaceAllString(detail, "[redacted-path]")
	detail = strings.Join(strings.Fields(detail), " ")
	return detail
}
