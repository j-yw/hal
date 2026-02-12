package runner

import (
	"fmt"

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
