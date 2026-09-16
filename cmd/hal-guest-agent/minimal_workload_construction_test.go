package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

func TestMinimalGuestCommandConstructionFailuresOwnCleanup(t *testing.T) {
	for _, boundary := range []string{"network", "workload", "backend", "listener"} {
		for _, fault := range []string{"error", "nil", "typed-nil", "panic", "cancel", "value-and-error"} {
			t.Run(boundary+"/"+fault, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				backend, proof := &minimalCommandBackend{}, &minimalCommandVerifier{}
				listener := &bootstrapEntryListener{}
				var calls []string
				private := errors.New("private constructor path/token canary")
				trip := func(name string) error {
					calls = append(calls, name)
					if name != boundary {
						return nil
					}
					switch fault {
					case "error", "value-and-error":
						return private
					case "panic":
						panic(private)
					case "cancel":
						cancel()
					}
					return nil
				}
				dependencies := minimalCommandDependencies(t, backend, proof, nil)
				dependencies.newNetworkVerifier = func(guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error) {
					err := trip("network")
					if boundary == "network" {
						if fault == "nil" || fault == "error" {
							return nil, err
						}
						if fault == "typed-nil" {
							return (*minimalCommandVerifier)(nil), nil
						}
					}
					return proof, err
				}
				dependencies.newWorkloadVerifier = func(server.LinuxIsolationVerifierOptions) (server.WorkloadIsolationVerifier, error) {
					err := trip("workload")
					if boundary == "workload" {
						if fault == "nil" || fault == "error" {
							return nil, err
						}
						if fault == "typed-nil" {
							return (*minimalCommandVerifier)(nil), nil
						}
					}
					return proof, err
				}
				dependencies.newBackend = func(server.LinuxBackendOptions) (server.Backend, error) {
					err := trip("backend")
					if boundary == "backend" {
						if fault == "nil" || fault == "error" {
							return nil, err
						}
						if fault == "typed-nil" {
							return (*minimalCommandBackend)(nil), nil
						}
					}
					return backend, err
				}
				dependencies.listen = func() (vsock.Listener, error) {
					err := trip("listener")
					if boundary == "listener" {
						if fault == "nil" || fault == "error" {
							return nil, err
						}
						if fault == "typed-nil" {
							return (*bootstrapEntryListener)(nil), nil
						}
					}
					return listener, err
				}
				err := minimalCommandCapturePanic(t, func() error {
					return runMinimalGuestAgentWithDependencies(ctx, minimalBootstrapREDBootLine()+" "+minimalCommandL7Line, dependencies)
				})
				wantCalls := []string{"network", "workload", "backend", "listener"}
				for index, name := range wantCalls {
					if name == boundary {
						wantCalls = wantCalls[:index+1]
						break
					}
				}
				if !reflect.DeepEqual(calls, wantCalls) || err == nil || strings.Contains(err.Error(), "private") {
					t.Errorf("construction did not fail closed: calls=%v want=%v error=%v", calls, wantCalls, err)
				}
				if fault == "cancel" && !errors.Is(err, context.Canceled) {
					t.Errorf("constructor cancellation lost: %v", err)
				}
				wantBackendClose := int32(0)
				if boundary == "listener" || boundary == "backend" && (fault == "cancel" || fault == "value-and-error") {
					wantBackendClose = 1
				}
				wantListenerClose := int32(0)
				if boundary == "listener" && (fault == "cancel" || fault == "value-and-error") {
					wantListenerClose = 1
				}
				if backend.closeCalls.Load() != wantBackendClose || listener.closed.Load() != wantListenerClose || listener.accepted != 0 || backend.readyCalls.Load() != 0 || proof.calls.Load() != 0 {
					t.Errorf("partial construction ownership wrong: backendClose=%d want=%d listenerClose=%d want=%d accepts=%d ready=%d proof=%d", backend.closeCalls.Load(), wantBackendClose, listener.closed.Load(), wantListenerClose, listener.accepted, backend.readyCalls.Load(), proof.calls.Load())
				}
			})
		}
	}
}

func TestMinimalGuestCommandInvalidDependenciesDoNotConstruct(t *testing.T) {
	for _, missing := range []string{"context", "lookup", "network", "workload", "backend", "listener"} {
		t.Run(missing, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			dependencies := minimalGuestAgentDependencies{
				lookupEnvironment: func(string) (string, bool) { calls++; return "", false },
				newNetworkVerifier: func(guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error) {
					calls++
					return nil, nil
				},
				newWorkloadVerifier: func(server.LinuxIsolationVerifierOptions) (server.WorkloadIsolationVerifier, error) {
					calls++
					return nil, nil
				},
				newBackend: func(server.LinuxBackendOptions) (server.Backend, error) { calls++; return nil, nil },
				listen:     func() (vsock.Listener, error) { calls++; return nil, nil },
			}
			switch missing {
			case "context":
				ctx = nil
			case "lookup":
				dependencies.lookupEnvironment = nil
			case "network":
				dependencies.newNetworkVerifier = nil
			case "workload":
				dependencies.newWorkloadVerifier = nil
			case "backend":
				dependencies.newBackend = nil
			case "listener":
				dependencies.listen = nil
			}
			err := minimalCommandCapturePanic(t, func() error {
				return runMinimalGuestAgentWithDependencies(ctx, minimalBootstrapREDBootLine()+" "+minimalCommandL7Line, dependencies)
			})
			if err != minimalcontrol.ErrInvalid || calls != 0 {
				t.Errorf("invalid dependency invoked construction: calls=%d error=%v", calls, err)
			}
		})
	}
}

func minimalCommandCapturePanic(t *testing.T, run func() error) (err error) {
	t.Helper()
	defer func() {
		if recover() != nil {
			t.Error("selected command leaked a constructor panic")
			err = errors.New("test observed panic")
		}
	}()
	return run()
}
