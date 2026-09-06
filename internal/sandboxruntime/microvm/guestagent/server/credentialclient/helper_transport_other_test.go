//go:build !linux

package credentialclient

import (
	"context"
	"errors"
	"testing"
)

func TestL8D7GuestHelperPreopenedOwnerIsUnacceptedOffLinux(t *testing.T) {
	owner, err := newPreopenedHelperConnectionOwner(newFakeHelperStream())
	if err != nil {
		if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
			t.Fatalf("newPreopenedHelperConnectionOwner() error = %v", err)
		}
		return
	}
	identity := testDispatchTransportIdentity()
	expectation, err := newHelperAcceptExpectation(identity.sessionID, [32]byte{1}, identity.helperGeneration, identity.identity.GuestBootNonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.AcceptVerified(context.Background(), expectation); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("AcceptVerified() error = %v, want unaccepted", err)
	}
}
