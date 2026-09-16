//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestMinimalHostInspectionStrictSchemasFromActualProof(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		o, rescue := minimalHostInspectionGuest(t, f)
		defer rescue()
		_, candidate := minimalSupervisorWorkClient(t, f)
		response, err := candidate.RoundTrip(context.Background(), minimalHostInspectionCarrier(minimalInspectionOperation))
		defer clear(response.Encoded)
		if err != nil || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
			t.Fatal("actual fresh inspection prerequisite", err)
		}
		topology, runtime := f.admission.config.Control.Prelaunch["topologyGenerationId"], f.admission.config.Job.RuntimeGeneration
		base, err := decodeMinimalHostInspection(response.Encoded, topology, runtime)
		if err != nil {
			t.Fatal("actual host proof decode", err)
		}
		serving := f.serving(t)
		serving.mu.Lock()
		ready := serving.server.ready
		serving.mu.Unlock()
		if ready.inspectionTopology != topology || ready.inspectionRuntime != runtime || !ready.Current() {
			t.Fatal("original validated handshake pins were not retained")
		}
		guest, err := json.Marshal(base.minimalGuestInspectionReply)
		defer clear(guest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeMinimalGuestInspection(guest, topology, runtime); err != nil {
			t.Fatal("actual guest proof extraction is not canonical")
		}
		if _, err := decodeMinimalGuestInspection(response.Encoded, topology, runtime); err == nil {
			t.Fatal("guest-controlled host timing was accepted")
		}
		if _, err := decodeMinimalHostInspection(guest, topology, runtime); err == nil {
			t.Fatal("host response missing its timing fields was accepted")
		}
		faults := []struct {
			name string
			edit func(*minimalGuestInspectionReply)
		}{
			{"operation", func(r *minimalGuestInspectionReply) { r.Operation = guestagent.OperationReadiness }},
			{"version", func(r *minimalGuestInspectionReply) { r.ProtocolVersion = string(guestagent.ProtocolVersionV1) }},
			{"topology", func(r *minimalGuestInspectionReply) { r.IsolationProof.Generation += "-other" }},
			{"runtime", func(r *minimalGuestInspectionReply) { r.IsolationProof.RuntimeGeneration += "-other" }},
			{"status", func(r *minimalGuestInspectionReply) { r.IsolationProof.Status = "unsupported" }},
			{"identity", func(r *minimalGuestInspectionReply) { r.IsolationProof.RestrictedIdentity = false }},
			{"capabilities", func(r *minimalGuestInspectionReply) { r.IsolationProof.CapabilitiesCleared = false }},
			{"privileges", func(r *minimalGuestInspectionReply) { r.IsolationProof.NoNewPrivileges = false }},
			{"groups", func(r *minimalGuestInspectionReply) { r.IsolationProof.SupplementaryGroupsCleared = false }},
			{"raw", func(r *minimalGuestInspectionReply) { r.IsolationProof.RawPacketSocketDenied = false }},
			{"network", func(r *minimalGuestInspectionReply) { r.IsolationProof.Network = nil }},
			{"network-status", func(r *minimalGuestInspectionReply) { r.IsolationProof.Network.Status = "unsupported" }},
			{"interface", func(r *minimalGuestInspectionReply) { r.IsolationProof.Network.SingleInterface = false }},
			{"routes", func(r *minimalGuestInspectionReply) { r.IsolationProof.Network.StaticRoutes = false }},
			{"proxy", func(r *minimalGuestInspectionReply) { r.IsolationProof.Network.ProxyReachable = false }},
		}
		for _, fault := range faults {
			t.Run(fault.name, func(t *testing.T) {
				r := base
				network := *r.IsolationProof.Network
				r.IsolationProof.Network = &network
				fault.edit(&r.minimalGuestInspectionReply)
				badGuest, _ := json.Marshal(r.minimalGuestInspectionReply)
				badHost, _ := json.Marshal(r)
				defer clear(badGuest)
				defer clear(badHost)
				if _, err := decodeMinimalGuestInspection(badGuest, topology, runtime); err == nil {
					t.Error("guest proof predicate accepted mutation")
				}
				if _, err := decodeMinimalHostInspection(badHost, topology, runtime); err == nil {
					t.Error("host proof predicate accepted mutation")
				}
			})
		}
		for _, original := range [][]byte{guest, response.Encoded} {
			for _, bad := range [][]byte{
				append(bytes.Clone(original), '\n'), append(bytes.Clone(original[:len(original)-1]), []byte(`,"error":"unavailable"}`)...),
				append(bytes.Clone(original[:len(original)-1]), []byte(`,"operation":"inspect_isolation"}`)...),
				bytes.Replace(original, []byte(`"operation"`), []byte(`"Operation"`), 1),
				bytes.Replace(original, []byte("inspect_isolation"), []byte(`inspect\u005fisolation`), 1),
				bytes.Repeat([]byte{'x'}, 2049),
			} {
				_, guestErr := decodeMinimalGuestInspection(bad, topology, runtime)
				_, hostErr := decodeMinimalHostInspection(bad, topology, runtime)
				clear(bad)
				if guestErr == nil || hostErr == nil {
					t.Fatal("noncanonical/unknown/duplicate/oversized response accepted")
				}
			}
		}
		f.producer.retire()
		minimalSupervisorWorkJoined(t, f)
	})
}

func TestMinimalHostInspectionLifetimeConservativeBounds(t *testing.T) {
	admitted := time.Now()
	hard := admitted.Add(session.MaxGuestCredentialSessionLifetime)
	observed := admitted.Add(time.Second)
	remaining := hard.Sub(observed)
	pin, err := (minimalInspectionLifetime{}).accept(admitted, observed, hard.UnixNano(), int64(remaining))
	if err != nil || pin.hardExpiry != hard.UnixNano() || pin.notAfter != admitted.Add(remaining) || !pin.notAfter.Before(hard) {
		t.Fatal("did not conservatively anchor remaining at request admission")
	}
	laterAdmission, laterReceipt := admitted.Add(2*time.Second), admitted.Add(2100*time.Millisecond)
	next, err := pin.accept(laterAdmission, laterReceipt, hard.UnixNano(), int64(hard.Sub(laterReceipt)))
	if err != nil || next != pin {
		t.Fatal("later receipt rebased or extended original monotonic bound")
	}
	if !pin.currentAt(pin.notAfter.Add(-time.Nanosecond), hard.UnixNano()-1) ||
		pin.currentAt(pin.notAfter, hard.UnixNano()-1) || pin.currentAt(pin.notAfter.Add(time.Second), 0) ||
		pin.currentAt(observed, hard.UnixNano()) {
		t.Fatal("exact expiry or independent backward/forward wall step extended lifetime")
	}
	for _, bad := range []struct {
		name            string
		at              time.Time
		hard, remaining int64
	}{
		{"changed-H", observed, hard.UnixNano() + 1, int64(remaining)},
		{"missing-H", observed, 0, int64(remaining)},
		{"expired-H", observed, observed.UnixNano(), int64(remaining)},
		{"zero-remaining", observed, hard.UnixNano(), 0},
		{"negative-remaining", observed, hard.UnixNano(), -1},
		{"excess-remaining", observed, hard.UnixNano(), int64(session.MaxGuestCredentialSessionLifetime) + 1},
		{"overflow-remaining", observed, hard.UnixNano(), math.MaxInt64},
		{"response-delayed-to-derived-expiry", pin.notAfter, hard.UnixNano(), int64(remaining)},
		{"response-delayed-past-derived-expiry", pin.notAfter.Add(time.Nanosecond), hard.UnixNano(), int64(remaining)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if got, err := pin.accept(admitted, bad.at, bad.hard, bad.remaining); err == nil || got != (minimalInspectionLifetime{}) {
				t.Fatal("invalid timing yielded a pin")
			}
		})
	}
}

func TestMinimalHostInspectionMalformedAdmissionPreservesOriginalWork(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		o, rescue := minimalHostInspectionGuest(t, f)
		defer rescue()
		client, candidate := minimalSupervisorWorkClient(t, f)
		for _, payload := range []string{
			minimalInspectionRequest + "\n", " " + minimalInspectionRequest,
			`{"protocolVersion":"guest-agent-minimal-v1","operation":"inspect_isolation"}`,
			strings.TrimSuffix(minimalInspectionRequest, "}") + `,"environment":[]}`,
			strings.TrimSuffix(minimalInspectionRequest, "}") + `,"hardExpiryUnixNano":1}`,
			strings.TrimSuffix(minimalInspectionRequest, "}") + `,"operation":"exec"}`,
			strings.Replace(minimalInspectionRequest, `"operation"`, `"Operation"`, 1),
			strings.Replace(minimalInspectionRequest, "inspect_isolation", `inspect\u005fisolation`, 1),
		} {
			for _, operation := range []guestagent.Operation{minimalInspectionOperation, guestagent.OperationExec, guestagent.OperationCopyIn, guestagent.OperationCopyOut} {
				request := minimalHostInspectionCarrier(operation)
				request.Encoded = []byte(payload)
				response, err := candidate.RoundTrip(context.Background(), request)
				clear(response.Encoded)
				if err == nil || o.counts() != [7]int32{1, 1, 1, 1, 1, 0, 0} {
					t.Fatal("malformed inspection dispatched or yielded bytes")
				}
			}
		}
		result, err := client.Exec(context.Background(), minimalJointExecRequest())
		if err != nil || result.ExitCode != 7 || o.counts() != [7]int32{2, 2, 2, 2, 1, 1, 0} {
			t.Fatal("rejected local requests consumed original work owner")
		}
		f.producer.retire()
		minimalSupervisorWorkJoined(t, f)
	})
}
