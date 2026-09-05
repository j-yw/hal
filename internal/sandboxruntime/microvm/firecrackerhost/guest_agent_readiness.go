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
	Client                   GuestAgentReadinessClient
	Transport                string
	Labels                   []string
	Timing                   *guestagent.TimingMetadata
	RequireIsolationProof    bool
	RequireNetworkProof      bool
	IsolationProofGeneration string
}

// GuestAgentReadinessProbe adapts guest-agent readiness responses onto the
// Firecracker guest readiness probe boundary.
type GuestAgentReadinessProbe struct {
	client                   GuestAgentReadinessClient
	transport                string
	labels                   []string
	timing                   *guestagent.TimingMetadata
	requireIsolationProof    bool
	requireNetworkProof      bool
	isolationProofGeneration string
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
		client:                   options.Client,
		transport:                transport,
		labels:                   append([]string(nil), options.Labels...),
		timing:                   cloneGuestAgentTransportTiming(options.Timing),
		requireIsolationProof:    options.RequireIsolationProof || options.RequireNetworkProof,
		requireNetworkProof:      options.RequireNetworkProof,
		isolationProofGeneration: strings.TrimSpace(options.IsolationProofGeneration),
	}
}

// ProbeGuestReadiness asks the guest agent whether protocol operations are
// ready, returning only sanitized Firecracker readiness metadata.
func (probe *GuestAgentReadinessProbe) ProbeGuestReadiness(ctx context.Context, firecrackerRequest firecracker.GuestReadinessRequest) (firecracker.GuestReadinessResult, error) {
	client, err := probe.clientFor()
	if err != nil {
		return firecracker.GuestReadinessResult{}, err
	}

	request := guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		Timing:          probe.timingMetadata(),
	}
	if probe.requireIsolationProof {
		firecrackerRequest = firecracker.SanitizeGuestReadinessRequest(firecrackerRequest)
		if firecrackerRequest.RuntimeID == "" {
			return firecracker.GuestReadinessResult{}, guestagent.NewProtocolError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationReadiness, "isolationProof.runtimeGeneration", errors.New("guest runtime generation is required"))
		}
		request.IsolationProof = &guestagent.IsolationProofRequest{
			Generation:          probe.isolationProofGeneration,
			RuntimeGeneration:   firecrackerRequest.RuntimeID,
			RequireNetworkProof: probe.requireNetworkProof,
		}
		if err := guestagent.ValidateReadinessRequest(request); err != nil {
			return firecracker.GuestReadinessResult{}, err
		}
	}
	response, err := client.Readiness(nonNilContext(ctx), request)
	if err != nil {
		return firecracker.GuestReadinessResult{}, guestAgentTransportClientError(ctx, guestagent.OperationReadiness, err)
	}
	if response == nil {
		return firecracker.GuestReadinessResult{}, guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedResponse, guestagent.OperationReadiness, "response", errors.New("guest agent returned no readiness response"))
	}
	if response.Error != nil {
		return firecracker.GuestReadinessResult{}, response.Error
	}
	if err := guestagent.ValidateReadinessResponseForRequest(*response, request); err != nil {
		return firecracker.GuestReadinessResult{}, err
	}

	state := sandboxruntime.RuntimeGuestReadinessStateWaiting
	if response.Ready && response.Status != guestagent.ReadinessStatusNotReady {
		state = sandboxruntime.RuntimeGuestReadinessStateReady
	}
	labels := probe.readinessLabels()
	if request.IsolationProof != nil && response.IsolationProof != nil && response.IsolationProof.Status == guestagent.IsolationProofStatusVerified {
		labels = append(labels, "guest_isolation_verified")
		if response.IsolationProof.Network != nil && response.IsolationProof.Network.Status == guestagent.IsolationProofStatusVerified {
			labels = append(labels, "guest_topology_verified")
		}
	}
	result := firecracker.NewGuestReadinessResult(state, probe.transport, labels)
	if response.IsolationProof != nil && response.IsolationProof.Status == guestagent.IsolationProofStatusVerified {
		result.IsolationProofGeneration = response.IsolationProof.Generation
		result.IsolationRuntimeGeneration = response.IsolationProof.RuntimeGeneration
	}
	return firecracker.SanitizeGuestReadinessResult(result), nil
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
