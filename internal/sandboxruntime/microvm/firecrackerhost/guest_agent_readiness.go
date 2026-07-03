package firecrackerhost

import (
	"context"
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const (
	defaultGuestAgentReadinessTransport = "protocol"
	guestAgentReadinessProtocolLabel    = "protocol"
)

var errGuestAgentReadinessClientRequired = errors.New("guest agent readiness client is required")

// GuestAgentReadinessClient is the host-side guest-agent readiness boundary.
type GuestAgentReadinessClient interface {
	Readiness(context.Context, guestagent.ReadinessRequest) (*guestagent.ReadinessResponse, error)
}

// GuestAgentReadinessProbeOptions configures the Firecracker guest readiness
// probe that talks through the versioned guest-agent protocol.
type GuestAgentReadinessProbeOptions struct {
	Client    GuestAgentReadinessClient
	Transport string
	Labels    []string
	Timing    *guestagent.TimingMetadata
}

// GuestAgentReadinessProbe adapts guest-agent readiness responses onto the
// Firecracker guest readiness probe boundary.
type GuestAgentReadinessProbe struct {
	client    GuestAgentReadinessClient
	transport string
	labels    []string
	timing    *guestagent.TimingMetadata
}

var _ GuestReadinessProbe = (*GuestAgentReadinessProbe)(nil)

// NewGuestAgentReadinessProbe constructs a guest readiness probe backed by an
// injected guest-agent protocol client.
func NewGuestAgentReadinessProbe(options GuestAgentReadinessProbeOptions) *GuestAgentReadinessProbe {
	transport := strings.TrimSpace(options.Transport)
	if transport == "" {
		transport = defaultGuestAgentReadinessTransport
	}
	return &GuestAgentReadinessProbe{
		client:    options.Client,
		transport: transport,
		labels:    append([]string(nil), options.Labels...),
		timing:    cloneGuestAgentTransportTiming(options.Timing),
	}
}

// ProbeGuestReadiness asks the guest agent whether protocol operations are
// ready, returning only sanitized Firecracker readiness metadata.
func (probe *GuestAgentReadinessProbe) ProbeGuestReadiness(ctx context.Context, _ firecracker.GuestReadinessRequest) (firecracker.GuestReadinessResult, error) {
	client, err := probe.clientFor()
	if err != nil {
		return firecracker.GuestReadinessResult{}, err
	}

	response, err := client.Readiness(nonNilContext(ctx), guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		Timing:          probe.timingMetadata(),
	})
	if err != nil {
		return firecracker.GuestReadinessResult{}, guestAgentTransportClientError(ctx, guestagent.OperationReadiness, err)
	}
	if response == nil {
		return firecracker.GuestReadinessResult{}, guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedResponse, guestagent.OperationReadiness, "response", errors.New("guest agent returned no readiness response"))
	}
	if response.Error != nil {
		return firecracker.GuestReadinessResult{}, response.Error
	}
	if err := guestagent.ValidateReadinessResponse(*response); err != nil {
		return firecracker.GuestReadinessResult{}, err
	}

	state := sandboxruntime.RuntimeGuestReadinessStateWaiting
	if response.Ready && response.Status != guestagent.ReadinessStatusNotReady {
		state = sandboxruntime.RuntimeGuestReadinessStateReady
	}
	return firecracker.NewGuestReadinessResult(state, probe.transport, probe.readinessLabels()), nil
}

func (probe *GuestAgentReadinessProbe) clientFor() (GuestAgentReadinessClient, error) {
	if probe == nil || probe.client == nil {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationReadiness, "client", errGuestAgentReadinessClientRequired)
	}
	return probe.client, nil
}

func (probe *GuestAgentReadinessProbe) timingMetadata() *guestagent.TimingMetadata {
	if probe == nil {
		return nil
	}
	return cloneGuestAgentTransportTiming(probe.timing)
}

func (probe *GuestAgentReadinessProbe) readinessLabels() []string {
	labels := []string{guestAgentReadinessProtocolLabel}
	if probe == nil || len(probe.labels) == 0 {
		return labels
	}
	labels = append(labels, probe.labels...)
	return labels
}
