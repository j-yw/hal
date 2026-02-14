package sandbox

import (
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// NewClient creates a configured Daytona SDK client from the given API key
// and server URL. If serverURL is empty, the SDK default is used.
func NewClient(apiKey, serverURL string) (*daytona.Client, error) {
	cfg := &types.DaytonaConfig{
		APIKey: apiKey,
	}
	if serverURL != "" {
		cfg.APIUrl = serverURL
	}
	return daytona.NewClientWithConfig(cfg)
}
