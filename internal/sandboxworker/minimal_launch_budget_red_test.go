package sandboxworker

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestMinimalLaunchPreparationBudgetRequiredBeforeStateMutation(t *testing.T) {
	for _, name := range []string{"missing", "zero", "negative", "over limit"} {
		t.Run(name, func(t *testing.T) {
			fixture := newMinimalLaunchDispatchFixture(t)
			options := fixture.options()
			switch name {
			case "missing":
				options.MinimalLaunch = &L8MinimalLaunchOptions{Authorizer: fixture.authorizer, Provider: fixture.binding}
			case "zero":
				options.MinimalLaunch.PreparationTimeout = 0
			case "negative":
				options.MinimalLaunch.PreparationTimeout = -time.Nanosecond
			case "over limit":
				options.MinimalLaunch.PreparationTimeout = maxMinimalLaunchPreparationTimeout + time.Nanosecond
			}
			service, err := NewL8DurableService(options)
			if service != nil {
				service.Close()
			}
			if service != nil || !errors.Is(err, ErrL8ServiceUnavailable) {
				t.Fatalf("invalid preparation budget admitted: service=%t error=%v", service != nil, err)
			}
			if _, err := os.Stat(fixture.stateDir); !os.IsNotExist(err) {
				t.Fatalf("invalid budget mutated state directory: %v", err)
			}
		})
	}
}

func TestMinimalLaunchPreparationBudgetValidConstructorControls(t *testing.T) {
	for _, budget := range []time.Duration{time.Second, maxMinimalLaunchPreparationTimeout} {
		t.Run(budget.String(), func(t *testing.T) {
			fixture := newMinimalLaunchDispatchFixture(t)
			options := fixture.options()
			options.MinimalLaunch.PreparationTimeout = budget
			service, err := NewL8DurableService(options)
			if err != nil {
				t.Fatal(err)
			}
			service.Close()
		})
	}
}
