package sandboxworker

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestDriverRegistryRegistersAndDispatchesFakeDriver(t *testing.T) {
	driver := &fakeWorkerRuntimeDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	got, err := registry.Lookup(" fake_runtime ")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if got != driver {
		t.Fatalf("Lookup() driver = %#v, want registered fake driver", got)
	}

	created, err := got.Create(context.Background(), sandboxruntime.CreateRequest{Name: "worker-dev"})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if created.Name != "worker-dev" || created.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Create() target = %#v, want fake runtime target", created)
	}
	if driver.created != "worker-dev" {
		t.Fatalf("fake driver created = %q, want request name", driver.created)
	}
}

func TestDriverRegistryRejectsDuplicateDriverIDs(t *testing.T) {
	registry, err := NewDriverRegistry(
		&fakeWorkerRuntimeDriver{id: sandboxruntime.DriverRootlessPodman},
		&fakeWorkerRuntimeDriver{id: sandboxruntime.DriverRootlessPodman},
	)
	if err == nil {
		t.Fatal("NewDriverRegistry() error = nil, want duplicate driver error")
	}
	if registry != nil {
		t.Fatalf("NewDriverRegistry() registry = %#v, want nil on duplicate", registry)
	}
	if !errors.Is(err, ErrDriverAlreadyRegistered) {
		t.Fatalf("NewDriverRegistry() error = %v, want ErrDriverAlreadyRegistered", err)
	}
}

func TestDriverRegistryLookupUnknownDriverReturnsExplicitError(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: sandboxruntime.DriverSSHMachine})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	got, err := registry.Lookup(sandboxruntime.DriverRootlessPodman)
	if err == nil {
		t.Fatal("Lookup() error = nil, want missing driver error")
	}
	if got != nil {
		t.Fatalf("Lookup() driver = %#v, want nil for missing driver", got)
	}
	if !errors.Is(err, ErrDriverNotFound) {
		t.Fatalf("Lookup() error = %v, want ErrDriverNotFound", err)
	}
}

func TestDriverRegistryDriverIDsAreDeterministic(t *testing.T) {
	registry, err := NewDriverRegistry(
		&fakeWorkerRuntimeDriver{id: "zeta"},
		&fakeWorkerRuntimeDriver{id: "alpha"},
		&fakeWorkerRuntimeDriver{id: "middle"},
	)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	got := registry.DriverIDs()
	want := []string{"alpha", "middle", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DriverIDs() = %#v, want %#v", got, want)
	}
}

func TestDriverRegistryRejectsMissingDriversAndIDs(t *testing.T) {
	registry := &DriverRegistry{}
	if err := registry.Register(nil); !errors.Is(err, ErrDriverRequired) {
		t.Fatalf("Register(nil) error = %v, want ErrDriverRequired", err)
	}
	if err := registry.Register(&fakeWorkerRuntimeDriver{id: "   "}); !errors.Is(err, ErrDriverIDRequired) {
		t.Fatalf("Register(blank ID) error = %v, want ErrDriverIDRequired", err)
	}
	if _, err := registry.Lookup(" "); !errors.Is(err, ErrDriverIDRequired) {
		t.Fatalf("Lookup(blank ID) error = %v, want ErrDriverIDRequired", err)
	}
}

func TestDriverRegistryZeroValueIsUsable(t *testing.T) {
	var registry DriverRegistry
	if err := registry.Register(&fakeWorkerRuntimeDriver{id: "local"}); err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if got := registry.DriverIDs(); !reflect.DeepEqual(got, []string{"local"}) {
		t.Fatalf("DriverIDs() = %#v, want [local]", got)
	}
}

type fakeWorkerRuntimeDriver struct {
	id      string
	created string
}

func (driver *fakeWorkerRuntimeDriver) ID() string {
	return driver.id
}

func (driver *fakeWorkerRuntimeDriver) Create(_ context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	driver.created = req.Name
	return &sandboxruntime.Target{
		Name: req.Name,
		Runtime: sandboxruntime.RuntimeState{
			Driver: driver.id,
		},
	}, nil
}

func (driver *fakeWorkerRuntimeDriver) Start(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (driver *fakeWorkerRuntimeDriver) Stop(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (driver *fakeWorkerRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (driver *fakeWorkerRuntimeDriver) Inspect(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (driver *fakeWorkerRuntimeDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}

func (driver *fakeWorkerRuntimeDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (driver *fakeWorkerRuntimeDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}
