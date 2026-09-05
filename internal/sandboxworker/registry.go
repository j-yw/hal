package sandboxworker

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrDriverRequired          = errors.New("runtime driver is required")
	ErrDriverIDRequired        = errors.New("runtime driver id is required")
	ErrDriverAlreadyRegistered = errors.New("runtime driver already registered")
	ErrDriverNotFound          = errors.New("runtime driver not found")
)

// DriverRegistry stores sandbox runtime drivers behind the worker boundary.
// Concrete adapters are registered by callers outside this package.
type DriverRegistry struct {
	mu      sync.RWMutex
	drivers map[string]sandboxruntime.Driver
}

// NewDriverRegistry returns a registry populated with drivers.
func NewDriverRegistry(drivers ...sandboxruntime.Driver) (*DriverRegistry, error) {
	registry := &DriverRegistry{}
	for _, driver := range drivers {
		if err := registry.Register(driver); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// Register adds driver to the registry using its stable runtime driver ID.
func (registry *DriverRegistry) Register(driver sandboxruntime.Driver) error {
	if driver == nil {
		return ErrDriverRequired
	}
	driverID := strings.TrimSpace(driver.ID())
	if driverID == "" {
		return ErrDriverIDRequired
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.ensureDrivers()
	if _, exists := registry.drivers[driverID]; exists {
		return fmt.Errorf("%w: %s", ErrDriverAlreadyRegistered, driverID)
	}
	registry.drivers[driverID] = driver
	return nil
}

// Lookup returns the driver registered for driverID.
func (registry *DriverRegistry) Lookup(driverID string) (sandboxruntime.Driver, error) {
	driverID = strings.TrimSpace(driverID)
	if driverID == "" {
		return nil, ErrDriverIDRequired
	}

	registry.mu.RLock()
	defer registry.mu.RUnlock()
	driver, exists := registry.drivers[driverID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrDriverNotFound, driverID)
	}
	return driver, nil
}

// DriverIDs returns registered driver IDs in deterministic order.
func (registry *DriverRegistry) DriverIDs() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	ids := make([]string, 0, len(registry.drivers))
	for id := range registry.drivers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (registry *DriverRegistry) ensureDrivers() {
	if registry.drivers == nil {
		registry.drivers = map[string]sandboxruntime.Driver{}
	}
}
