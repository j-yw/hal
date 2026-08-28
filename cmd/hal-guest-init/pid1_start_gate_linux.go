//go:build linux

package main

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"

// loadPID1StartGateExpected would snapshot sealed image-profile helper, client,
// and composition digests. This binary has no compiled-in or inherited sealed
// digest channel; unsigned file/env/cmdline reads are rejected.
func loadPID1StartGateExpected() (l8composition.PID1StartGateExpected, bool, error) {
	return l8composition.PID1StartGateExpected{}, false, nil
}

// releasePID1AgentStartGate admits helper-then-client descriptors before the
// L7 child start. Missing sealed expected leaves the L7 supervisor path;
// a claimed expected without authenticated descriptors fails closed.
func releasePID1AgentStartGate() int {
	_, present, err := loadPID1StartGateExpected()
	if err != nil {
		return 127
	}
	if !present {
		return 0
	}
	return 127
}

// admitPID1StartGate is the exact helper-then-client start-gate. Tests inject
// sealed expected plus descriptors; PID1 never constructs helper or client.
func admitPID1StartGate(
	expected l8composition.PID1StartGateExpected,
	helper l8composition.ProcessDescriptor,
	client l8composition.ProcessDescriptor,
) int {
	state, err := l8composition.NewPID1StartGateState(expected)
	if err != nil {
		return 127
	}
	decision, err := state.AcceptHelperDescriptor(helper)
	if err != nil || decision != l8composition.PID1StartGateDecisionContinue {
		return 127
	}
	decision, err = state.AcceptClientDescriptor(client)
	if err != nil || decision != l8composition.PID1StartGateDecisionRelease {
		return 127
	}
	return 0
}
