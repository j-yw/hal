package runner

import (
	"context"
	"fmt"
	"time"

	daytona "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// SDKClientConfig holds configuration for the Daytona SDK runner client.
type SDKClientConfig struct {
	// APIKey is the Daytona API key (required).
	APIKey string
	// APIURL is the Daytona API URL (optional; SDK default used when empty).
	APIURL string
	// Target is the Daytona target environment (optional).
	Target string
}

// SDKClient is a Daytona SDK implementation of the Runner interface.
type SDKClient struct {
	client *daytona.Client
}

// NewSDKClient creates a new SDK runner client with the given configuration.
// APIKey is required; all other fields are optional.
func NewSDKClient(cfg SDKClientConfig) (*SDKClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("sdk runner client: api_key must not be empty")
	}

	client, err := daytona.NewClientWithConfig(&types.DaytonaConfig{
		APIKey: cfg.APIKey,
		APIUrl: cfg.APIURL,
		Target: cfg.Target,
	})
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: init: %w", err)
	}

	return &SDKClient{client: client}, nil
}

// CreateSandbox provisions a new Daytona sandbox via the SDK.
func (s *SDKClient) CreateSandbox(ctx context.Context, req *CreateSandboxRequest) (*Sandbox, error) {
	if req == nil {
		return nil, fmt.Errorf("sdk runner client: create request must not be nil")
	}
	if req.Image == "" {
		return nil, fmt.Errorf("sdk runner client: create: image must not be empty")
	}

	sandbox, err := s.client.Create(ctx, types.ImageParams{
		Image: req.Image,
		SandboxBaseParams: types.SandboxBaseParams{
			EnvVars: req.EnvVars,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: create sandbox: %w", err)
	}

	return &Sandbox{
		ID:        sandbox.ID,
		Status:    string(sandbox.State),
		CreatedAt: time.Now(),
	}, nil
}

// DestroySandbox tears down an existing sandbox by ID via the SDK.
func (s *SDKClient) DestroySandbox(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: destroy: get sandbox: %w", err)
	}

	if err := sandbox.Delete(ctx); err != nil {
		return fmt.Errorf("sdk runner client: destroy sandbox: %w", err)
	}

	return nil
}
