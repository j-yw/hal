package sandbox

import "fmt"

// EnsureAuth checks that a non-empty API key is available. If the key is empty
// and a setupFn is provided, it calls setupFn to trigger the interactive setup
// flow. After setupFn returns, it rechecks the API key via reloadFn.
//
// - If apiKey is non-empty, returns nil immediately.
// - If apiKey is empty and setupFn is nil, returns an error.
// - If apiKey is empty and setupFn succeeds, reloadFn must return the new key.
func EnsureAuth(apiKey string, setupFn func() error, reloadFn func() (string, error)) error {
	if apiKey != "" {
		return nil
	}

	if setupFn == nil {
		return fmt.Errorf("daytona API key not configured - run 'hal sandbox setup' first")
	}

	if err := setupFn(); err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}

	if reloadFn == nil {
		return nil
	}

	newKey, err := reloadFn()
	if err != nil {
		return fmt.Errorf("reloading config after setup: %w", err)
	}
	if newKey == "" {
		return fmt.Errorf("API key still empty after setup")
	}

	return nil
}
