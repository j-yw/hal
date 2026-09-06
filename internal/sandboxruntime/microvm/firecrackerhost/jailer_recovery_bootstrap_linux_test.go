//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

func TestJailerRecoveryBootstrapFailureRetainsAuthenticatedRetry(t *testing.T) {
	for _, postPID := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_pid", true: "published_pid_release_failed"}[postPID], func(t *testing.T) {
			ctx := context.Background()
			owned, root, identityStore, events := jailerRecoveryRuntimeFixture(t)
			root.removeErrors = []error{errors.New("owned cleanup incomplete"), nil}
			if postPID {
				_ = owned.selected.starter.gate.Close()
			} else {
				owned.selected.coordinator.deps.lifecycle.(*coordinatorFakeLifecycle).startErr = errors.New("fake start refused")
			}
			next := byte(12)
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: owned.store, GenesisRecord: owned.genesis, ExpectedUID: 0, CommitKey: make([]byte, 32), CommitID: jailerRecoveryCommitID, RandomToken: func() (string, error) { next++; return l8RuntimeOwnerTestToken(next), nil }, StartChild: owned.startChild, ContainChild: owned.containChild, ReinspectAbsence: owned.reinspectAbsence, CloseNamespaces: owned.closeNamespaces})
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.HandleBootstrap(ctx, 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: make([]byte, 32)}, Files: make([]*os.File, 2)})
			if err == nil {
				t.Fatal("bootstrap failure fixture succeeded")
			}
			prior, err := owned.store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retained := owned.selected.coordinator.generation
			if prior.State != "starting" || retained == nil || (prior.FirecrackerPID != 0) != postPID || owned.store.selected.terminal {
				t.Fatal("fixture lost actual unresolved ownership")
			}
			if err := owned.quarantineJailerBootstrap(); err != nil {
				t.Fatalf("retained selected bootstrap cannot expose authenticated cleanup retry: %v", err)
			}
			record, err := owned.store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if record.State != "uncertain" || record.ControllerState != "unclaimed" || record.Revision != prior.Revision+1 || record.FirecrackerPID != prior.FirecrackerPID || owned.selected.coordinator.generation != retained {
				t.Fatal("quarantine invented or discarded ownership")
			}
			base := l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret}
			for name, mutate := range map[string]func(*l8RuntimeOwnerHandshakeV1){"supervisor": func(h *l8RuntimeOwnerHandshakeV1) { h.SupervisorGeneration = l8RuntimeOwnerTestToken(45) }, "runtime": func(h *l8RuntimeOwnerHandshakeV1) { h.RuntimeGeneration = "another" }, "revision": func(h *l8RuntimeOwnerHandshakeV1) { h.RecordRevision-- }, "secret": func(h *l8RuntimeOwnerHandshakeV1) { h.ReconnectSecret = l8RuntimeOwnerTestToken(46) }} {
				t.Run(name, func(t *testing.T) {
					h := base
					mutate(&h)
					body, _ := encodeL8RuntimeOwnerHandshake(h)
					before := slices.Clone(*events)
					if _, err := owner.AdmitController(ctx, 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}}); err == nil || !slices.Equal(*events, before) {
						t.Fatal("wrong auth reached cleanup")
					}
				})
			}
			body, _ := encodeL8RuntimeOwnerHandshake(base)
			admitted, err := owner.AdmitController(ctx, 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}})
			if err != nil {
				t.Fatal(err)
			}
			ack, err := decodeL8RuntimeOwnerHandshakeAck(admitted.Packet.Body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.AdmitController(ctx, 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}}); err == nil {
				t.Fatal("replayed one-use handshake accepted")
			}
			if _, err := jailerRecoveryFakeStop(owner, ack.ControllerSessionGeneration); err != nil {
				t.Fatalf("same-owner cleanup retry: %v events %v", err, *events)
			}
			idle, err := readJailerIdentityRecord(identityStore.snapshot(), owned.selected.coordinator.deps.identity.slot)
			if err != nil || idle.State != "idle" || !owned.store.selected.terminal || owned.selected.coordinator.generation != nil {
				t.Fatal("retry did not reach exact terminal checkpoint")
			}
		})
	}
}
