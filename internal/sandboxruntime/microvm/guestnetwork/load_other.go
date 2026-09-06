//go:build !linux

package guestnetwork

import "context"

// LoadLinuxBootConfig fails closed away from Linux.
func LoadLinuxBootConfig(context.Context) (BootConfig, bool, error) {
	return BootConfig{}, false, ErrInvalidBootConfig
}
