package main

import (
	"context"
	"errors"
	"reflect"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

// Construction-only injection: the selected path owns its actual transport and
// server. No request handler, proof result, or serving algorithm is injectable.
type minimalGuestAgentDependencies struct {
	lookupEnvironment   func(string) (string, bool)
	listen              func() (vsock.Listener, error)
	newBackend          func(server.LinuxBackendOptions) (server.Backend, error)
	newNetworkVerifier  func(guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error)
	newWorkloadVerifier func(server.LinuxIsolationVerifierOptions) (server.WorkloadIsolationVerifier, error)
}

func runMinimalGuestAgentWithDependencies(ctx context.Context, line string, dependencies minimalGuestAgentDependencies) (result error) {
	if ctx == nil || dependencies.lookupEnvironment == nil || dependencies.listen == nil || dependencies.newBackend == nil ||
		dependencies.newNetworkVerifier == nil || dependencies.newWorkloadVerifier == nil {
		return minimalcontrol.ErrInvalid
	}
	var backend server.Backend
	var listener vsock.Listener
	serving := false
	defer func() {
		if recover() != nil {
			result = minimalcontrol.ErrUnavailable
		}
		// Before Serve, even a value returned alongside an error is owned here.
		// After handoff the accepted server/transport are the sole cleanup owners.
		if !serving {
			if minimalCommandDependencyPresent(listener) {
				if err := minimalCommandClose(listener.Close); err != nil {
					result = errors.Join(result, err)
				}
			}
			if minimalCommandDependencyPresent(backend) {
				cleanup, cancel := context.WithTimeout(context.Background(), server.DefaultMaxShutdownTime)
				defer cancel()
				if err := minimalCommandClose(func() error { return backend.Close(cleanup) }); err != nil {
					result = errors.Join(result, err)
				}
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, selected, err := minimalcontrol.ParseBootCommandLine(line)
	if err != nil || !selected {
		return minimalcontrol.ErrInvalid
	}
	networkBoot, present, err := guestnetwork.ParseBootCommandLine(line)
	if err != nil || !present || !networkBoot.Valid() {
		return minimalcontrol.ErrInvalid
	}
	configuration, err := linuxGuestAgentConfigurationFromLookup(dependencies.lookupEnvironment)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil || !configuration.requireNetworkProofBeforeWork || configuration.proxyURL != networkBoot.ProxyURL() {
		return minimalcontrol.ErrInvalid
	}
	network, err := dependencies.newNetworkVerifier(guestnetwork.LinuxNetworkIsolationVerifierOptions{BootConfig: networkBoot})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil || !minimalCommandDependencyPresent(network) {
		return minimalcontrol.ErrUnavailable
	}
	verifier, err := dependencies.newWorkloadVerifier(server.LinuxIsolationVerifierOptions{NetworkVerifier: network})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil || !minimalCommandDependencyPresent(verifier) {
		return minimalcontrol.ErrUnavailable
	}
	backend, err = dependencies.newBackend(configuration.backend)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil || !minimalCommandDependencyPresent(backend) {
		return minimalcontrol.ErrUnavailable
	}
	listener, err = dependencies.listen()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return minimalcontrol.ErrUnavailable
	}
	transport, err := minimalcontrol.NewWorkloadTransport(minimalcontrol.BootstrapOptions{Listener: listener, Boot: boot, OwnerDone: ctx.Done()})
	if err != nil {
		return err
	}
	agent, err := server.New(server.Options{Transport: transport, Backend: backend, WorkloadIsolationVerifier: verifier,
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
	if err != nil {
		return minimalcontrol.ErrUnavailable
	}
	serving = true
	err = agent.Serve(ctx)
	if ctx.Err() != nil && err != nil {
		return errors.Join(ctx.Err(), err)
	}
	return err
}

func minimalCommandDependencyPresent(value any) bool {
	if value == nil {
		return false
	}
	switch reflected := reflect.ValueOf(value); reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

func minimalCommandClose(close func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = minimalcontrol.ErrUnavailable
		}
	}()
	if close() != nil {
		return minimalcontrol.ErrUnavailable
	}
	return nil
}
