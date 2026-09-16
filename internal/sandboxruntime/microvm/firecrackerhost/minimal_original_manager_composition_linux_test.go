//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

// This prerequisite composes unchanged accepted components. It does not select
// the executable, publish a readiness event, cross an exec boundary, implement
// a provider, stop the P observer on success, or run a real guest backend.
func TestMinimalOriginalManagerBootstrapAuthenticatedWorkload(t *testing.T) {
	withMinimalOriginalManagerFixture(t, func(f *minimalOriginalManagerFixture) {
		selected, prep := f.owned.selected, f.owned.minimalPreparation
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("same-owner bootstrap prerequisite", err)
		}
		for _, fd := range []int{f.gatePeer, f.peer} {
			if setL8RuntimeOwnerSocketTimeout(fd, time.Second) != nil {
				t.Fatal("bounded packet observation")
			}
		}
		gate, gateErr := receiveL8RuntimeOwnerSeqpacket(f.gatePeer)
		defer closeL8RuntimeOwnerFiles(gate.Files)
		reply, replyErr := receiveL8RuntimeOwnerSeqpacket(f.peer)
		defer closeL8RuntimeOwnerFiles(reply.Files)
		record, err := f.owned.store.Load(prep.ctx)
		if gateErr != nil || gate.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease || len(gate.Files) != 0 ||
			replyErr != nil || reply.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished || len(reply.Files) != 0 || len(reply.Packet.Body) != 8 ||
			binary.BigEndian.Uint64(reply.Packet.Body) != 2 || err != nil || record.Revision != 2 || record.State != "running" ||
			record.SeedCorrelationDigest != hex.EncodeToString(f.admission.configDigest[:]) || !selected.starter.released {
			t.Fatal("actual gate, reply and durable revision-2 prerequisites", gateErr, replyErr, err)
		}
		f.order = append(f.order, "revision2-reply")
		if !slices.Equal(f.order, []string{"genesis", "armed", "revision1", "release", "revision2-reply"}) {
			t.Fatal("actual bootstrap ordering", f.order)
		}
		selected.coordinator.mu.Lock()
		generation := selected.coordinator.generation
		if generation == nil {
			selected.coordinator.mu.Unlock()
			t.Fatal("missing original coordinator generation after bootstrap")
		}
		process := generation.process
		selected.coordinator.mu.Unlock()
		before, err := f.manager.resolveLiveProcessIdentity(process.handle)
		if err != nil || selected.lifecycle != f.lifecycle || f.lifecycle.manager != f.manager || selected.coordinator.deps.lifecycle != f.lifecycle ||
			!f.manager.productionVsock || selected.session.coordinator != selected.coordinator || selected.session.generation != generation.id ||
			generation.state != strictJailerCoordinatorActive || !generation.hasProcess || f.tracked.calls != 1 || f.stages != 1 ||
			before.pid != os.Getpid() || before.done != f.tracked.process.Done() || before.paths != f.paths || process.hostPaths != f.paths ||
			before.owner == nil || !before.owner.active() || before.owner.parent != f.parent || before.owner.uid != uint32(os.Geteuid()) ||
			f.owned.store.selected.reservation != generation.identity || generation.cgroup != f.tracked.cgroup || !generation.cgroup.launched ||
			f.tracked.launch == nil || f.tracked.launch.Fd() != ^uintptr(0) {
			t.Fatal("original launched manager did not retain its actual prelaunch parent/lease/process", err)
		}
		window, ok := selected.starter.minimalGate.releaseWindow()
		wantD := window.startedAt.Add(minimalControlStartupTimeout)
		if prep.deadline.Before(wantD) {
			wantD = prep.deadline
		}
		if !ok || !window.deadline.Equal(wantD) || !time.Now().Before(window.deadline) || prep.ctx.Err() != nil {
			t.Fatal("missing original completed release window")
		}
		transport, err := newMinimalControlTransport(f.manager, process.handle, f.admission.config.Job.RuntimeID)
		if err != nil || transport.checks.observe != nil || transport.checks.peer != nil || transport.dial != nil {
			t.Fatal("actual original-manager transport", err)
		}
		if resolved, err := transport.resolveProcess(); err != nil || resolved.handle != process.handle || resolved.paths != f.paths {
			t.Fatal("original transport canonical path prerequisite", err)
		}
		// Start the listener only after release: the manager's start must have
		// recorded the directory without a pre-existing socket or replacement.
		listener := &minimalControllerGuestListener{listener: l5ListenBridgeSocket(t, f.paths.VsockSocketPath)}
		listener.listener.(*net.UnixListener).SetUnlinkOnClose(false)
		defer listener.Close()
		c := f.admission.config.Control
		identity, expectedLine := minimalOriginalManagerBoot(t, f.admission.config)
		fc, err := readMinimalControlFirecrackerConfig(f.admission.borrowed[6], f.admission.config.Config)
		if err != nil {
			t.Fatal(err)
		}
		boot, present, err := minimalcontrol.ParseBootCommandLine(fc.BootSource.BootArgs)
		if err != nil || !present || fc.BootSource.BootArgs != expectedLine {
			t.Fatal("actual shared boot pins", err)
		}
		guestCtx, cancelGuest := context.WithCancel(prep.ctx)
		defer cancelGuest()
		workload, err := minimalcontrol.NewWorkloadTransport(minimalcontrol.BootstrapOptions{Listener: listener, Boot: boot,
			OwnerDone: guestCtx.Done(), Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
		if err != nil {
			t.Fatal(err)
		}
		backend := &minimalJointBackend{exec: func(_ context.Context, plan server.ExecPlan) (server.ExecResult, error) {
			if !reflect.DeepEqual(plan.Args, []string{"hal", "--version"}) || plan.WorkDir != "/workspace" ||
				len(plan.Environment) != 0 || len(plan.Stdin) != 0 || plan.StdoutMaxBytes != 64 || plan.StderrMaxBytes != 64 {
				return server.ExecResult{}, errors.New("unexpected composition exec plan")
			}
			return server.ExecResult{ExitCode: 7, Stdout: []byte("same original manager\n")}, nil
		}}
		verifier := &minimalJointVerifier{}
		guest, err := server.New(server.Options{Transport: workload, Backend: backend, WorkloadIsolationVerifier: verifier,
			RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
		if err != nil {
			t.Fatal(err)
		}
		guestDone := make(chan struct{})
		go func() { defer close(guestDone); _ = guest.Serve(guestCtx) }()
		defer func() {
			cancelGuest()
			_ = listener.Close()
			minimalJointAwait(t, guestDone, "same-owner guest cleanup")
			if backend.closes.Load() != 1 {
				t.Error("guest backend not closed exactly once")
			}
		}()
		err = withMinimalWorkloadController(prep.ctx, transport, f.admission, window.deadline, func(controller *minimalControlController) error {
			client, _, ready := minimalJointClient(t, controller)
			identity.FirecrackerProcessGeneration = process.handle.ID
			identity.VsockGeneration = strconv.FormatUint(ready.transportGeneration, 10)
			fields := maps.Clone(c.Prelaunch)
			fields["processGeneration"], fields["vsockGeneration"] = identity.FirecrackerProcessGeneration, identity.VsockGeneration
			binding, err := minimalcontrol.NewBinding(identity, fields)
			want, wantErr := binding.Digest(ready.sessionID)
			got, gotErr := ready.binding.Digest(ready.sessionID)
			if err != nil || wantErr != nil || gotErr != nil || got != want || ready.handle != process.handle || ready.transportGeneration == 0 ||
				ready.sessionID == ([32]byte{}) || verifier.calls.Load() != 1 || backend.calls.Load() != 0 || !ready.Current() {
				t.Fatal("real authenticated readiness differs from original manager/binding", err)
			}
			response, err := client.Exec(prep.ctx, minimalJointExecRequest())
			if err != nil || response.ExitCode != 7 || response.Stdout.Data != base64.StdEncoding.EncodeToString([]byte("same original manager\n")) ||
				backend.calls.Load() != 1 || verifier.calls.Load() != 2 || listener.connects.Load() != 1 || !ready.Current() {
				t.Fatal("single actual authenticated Client Exec did not reach injected backend", err)
			}
			after, err := f.manager.resolveLiveProcessIdentity(process.handle)
			if err != nil || after.handle != before.handle || after.done != before.done || after.paths != before.paths ||
				!sameVsockProcessOwner(after.owner, before.owner) || selected.lifecycle != f.lifecycle || f.lifecycle.manager != f.manager ||
				selected.coordinator.generation != generation || generation.process != process || f.tracked.calls != 1 {
				t.Fatal("authenticated work replaced its original manager/process", err)
			}
			if controller.Close() != nil || ready.Current() {
				t.Fatal("controller retirement")
			}
			minimalControllerRequireJoined(t, controller, f.admission.controllerKey)
			minimalJointAwait(t, guestDone, "guest joins from actual host stream closure")
			minimalJointAwait(t, controller.stream.watchDone, "original transport watcher")
			return nil
		})
		if err != nil {
			t.Fatal("original authenticated controller scope", err)
		}
		if f.owned.shutdownMinimalControlPreparation() != nil {
			t.Fatal("same-owner preparation close")
		}
		for _, done := range []<-chan struct{}{prep.operation, prep.ioDone, prep.monitorDone, prep.observerDone, prep.closeDone} {
			minimalJointAwait(t, done, "original preparation task")
		}
	})
}
