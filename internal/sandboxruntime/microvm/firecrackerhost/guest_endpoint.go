package firecrackerhost

import (
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// GuestAgentEndpointOptions configures an optional sandboxd guest-agent
// transport endpoint for live Firecracker targets.
type GuestAgentEndpointOptions struct {
	Endpoint         string
	DialTimeout      time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

// NewGuestTransportFromEndpoint validates a configured endpoint and returns
// the Firecracker guest transport backed by the guest-agent protocol client.
func NewGuestTransportFromEndpoint(options GuestAgentEndpointOptions) (firecracker.GuestTransport, error) {
	if strings.TrimSpace(options.Endpoint) == "" {
		return nil, nil
	}
	transport, err := newGuestAgentUnixSocketTransport(guestAgentUnixSocketTransportOptions{
		endpoint:      options.Endpoint,
		dialTimeout:   options.DialTimeout,
		responseLimit: options.MaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	client, err := guestagent.NewClient(guestagent.ClientOptions{
		Transport:        transport,
		MaxRequestBytes:  options.MaxRequestBytes,
		MaxResponseBytes: options.MaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	return NewGuestAgentTransport(GuestAgentTransportOptions{Client: client}), nil
}

// ValidateGuestAgentEndpoint validates endpoint metadata without constructing
// a Firecracker live driver.
func ValidateGuestAgentEndpoint(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	_, err := guestAgentUnixSocketPathFromEndpoint(endpoint)
	return err
}
