package l8composition

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestL8ControllerSupervisorWireConstantsAreExact(t *testing.T) {
	t.Parallel()

	if ControllerSupervisorMagic != "HL8L" {
		t.Fatalf("ControllerSupervisorMagic = %q", ControllerSupervisorMagic)
	}
	if ControllerSupervisorVersion != 1 {
		t.Fatalf("ControllerSupervisorVersion = %d", ControllerSupervisorVersion)
	}
	if ControllerSupervisorFlags != 0 {
		t.Fatalf("ControllerSupervisorFlags = %d", ControllerSupervisorFlags)
	}
	if ControllerSupervisorHeaderBytes != 68 {
		t.Fatalf("ControllerSupervisorHeaderBytes = %d", ControllerSupervisorHeaderBytes)
	}
	if MaxControllerSupervisorBodyBytes != 8192 {
		t.Fatalf("MaxControllerSupervisorBodyBytes = %d", MaxControllerSupervisorBodyBytes)
	}
	if MaxControllerSupervisorDatagramBytes != 8260 {
		t.Fatalf("MaxControllerSupervisorDatagramBytes = %d", MaxControllerSupervisorDatagramBytes)
	}
	if MaxControllerSupervisorPacketsPerDirection != uint64(1)<<32 {
		t.Fatalf("MaxControllerSupervisorPacketsPerDirection = %d", MaxControllerSupervisorPacketsPerDirection)
	}
}

func TestL8ControllerSupervisorCatalogsAreClosed(t *testing.T) {
	validators := []struct {
		name        string
		max         uint8
		validate    func(uint8) error
		zeroAllowed bool
	}{{"packet", 0x7f, func(v uint8) error { return ValidateControllerSupervisorPacketType(ControllerSupervisorPacketType(v)) }, false}, {"direction", 2, func(v uint8) error { return ValidateControllerSupervisorDirection(ControllerSupervisorDirection(v)) }, false}, {"right kind", 9, func(v uint8) error { return ValidateControllerSupervisorRightKind(ControllerSupervisorRightKind(v)) }, false}, {"right access", 7, func(v uint8) error {
		return ValidateControllerSupervisorRightAccess(ControllerSupervisorRightAccess(v))
	}, false}, {"reason", 8, func(v uint8) error { return ValidateControllerSupervisorReason(ControllerSupervisorReason(v)) }, false}, {"event", 5, func(v uint8) error { return ValidateControllerSupervisorEventCode(ControllerSupervisorEventCode(v)) }, false}, {"failure", 9, func(v uint8) error {
		return ValidateControllerSupervisorFailureCode(ControllerSupervisorFailureCode(v))
	}, true}, {"exit", 4, func(v uint8) error {
		return ValidateControllerSupervisorExitCategory(ControllerSupervisorExitCategory(v))
	}, true}, {"monitor", 5, func(v uint8) error {
		return ValidateControllerSupervisorMonitorState(ControllerSupervisorMonitorState(v))
	}, true}, {"cleanup", 4, func(v uint8) error {
		return ValidateControllerSupervisorCleanupCategory(ControllerSupervisorCleanupCategory(v))
	}, false}}
	for _, test := range validators {
		test := test
		t.Run(test.name, func(t *testing.T) {
			start := uint8(1)
			if test.zeroAllowed {
				start = 0
			}
			for value := start; value <= test.max; value++ {
				if test.name == "packet" && value > 0x0a && value != 0x7f {
					continue
				}
				if err := test.validate(value); err != nil {
					t.Fatalf("%d rejected: %v", value, err)
				}
			}
			if !test.zeroAllowed && test.validate(0) == nil {
				t.Fatal("zero accepted")
			}
			if test.max < 0x7f && test.validate(test.max+1) == nil {
				t.Fatal("plus one accepted")
			}
			if test.name == "packet" && test.validate(0x0b) == nil {
				t.Fatal("packet gap accepted")
			}
		})
	}
}

func TestL8ControllerSupervisorMalformedBoundsAndCanonicalTokenRejection(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	wire := mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready))
	tests := []struct {
		name string
		wire []byte
		want error
	}{{"truncated header", append([]byte(nil), wire[:67]...), ErrControllerSupervisorHeaderLength}, {"truncated body", append([]byte(nil), wire[:len(wire)-1]...), ErrControllerSupervisorDatagramLength}, {"trailing", append(append([]byte(nil), wire...), 0), ErrControllerSupervisorDatagramTrailingData}, {"magic", controllerSupervisorMutate(wire, 0, 'X'), ErrControllerSupervisorMagic}, {"version", controllerSupervisorMutate(wire, 4, 2), ErrControllerSupervisorVersion}, {"type", controllerSupervisorMutate(wire, 5, 0), ErrControllerSupervisorPacketType}, {"flags", controllerSupervisorMutate(wire, 7, 1), ErrControllerSupervisorFlags}, {"request semantics", controllerSupervisorMutate(wire, 31, 1), ErrControllerSupervisorRequestID}, {"identity semantics", controllerSupervisorMutate(wire, 63, 1), ErrControllerSupervisorJobIdentity}}
	for _, test := range tests {
		if _, err := DecodeControllerSupervisorPacket(test.wire); !errors.Is(err, test.want) {
			t.Errorf("%s error = %v, want %v", test.name, err, test.want)
		}
	}
	max := ControllerSupervisorHeader{Type: ControllerSupervisorPacketTypeSupervisorReady, BodyLength: MaxControllerSupervisorBodyBytes}
	if _, err := EncodeControllerSupervisorHeader(max); err != nil {
		t.Fatal(err)
	}
	max.BodyLength++
	if _, err := EncodeControllerSupervisorHeader(max); !errors.Is(err, ErrControllerSupervisorBodyLength) {
		t.Fatalf("body plus one = %v", err)
	}
	maxID := credentialprotocol.SafeID("a" + strings.Repeat("b", 127))
	ready := f.ready
	ready.BootGeneration = maxID
	if _, err := EncodeControllerSupervisorSupervisorReadyBody(ready); err != nil {
		t.Fatalf("max token = %v", err)
	}
	ready.BootGeneration = credentialprotocol.SafeID("a" + strings.Repeat("b", 128))
	if _, err := EncodeControllerSupervisorSupervisorReadyBody(ready); err == nil {
		t.Fatal("token plus one accepted")
	}
	ready = f.ready
	ready.BootGeneration = "bad:colon"
	if _, err := EncodeControllerSupervisorSupervisorReadyBody(ready); err == nil {
		t.Fatal("safe ID colon accepted")
	}
}

func TestL8ControllerSupervisorCanonicalDigestsAndBodies(t *testing.T) {
	t.Parallel()
	f := controllerSupervisorVectorFixture(t)

	ready, err := ControllerSupervisorReadySHA256(f.ready.BootGeneration, f.ready.HelperGeneration, f.ready.SupervisorGeneration, f.ready.LimitSetID)
	if err != nil || ready != f.ready.SupervisorReadySHA256 {
		t.Fatalf("ready digest = %x, %v", ready, err)
	}
	monitor, err := ControllerSupervisorMonitorConfigSHA256(f.identity, f.create.JobGeneration, f.create.MonitorGeneration, f.create.MountGeneration, f.create.LimitSetID)
	if err != nil || monitor != f.create.MonitorConfigSHA256 {
		t.Fatalf("monitor digest = %x, %v", monitor, err)
	}
	cgroup, err := ControllerSupervisorCgroupConfigSHA256(f.identity, f.create.JobGeneration, f.create.CgroupGeneration, f.create.LimitSetID)
	if err != nil || cgroup != f.create.CgroupConfigSHA256 {
		t.Fatalf("cgroup digest = %x, %v", cgroup, err)
	}
	create, err := ControllerSupervisorCreateJobSHA256(f.identity, f.create)
	if err != nil || create != f.created.CreateJobSHA256 {
		t.Fatalf("create digest = %x, %v", create, err)
	}
	monitorReady, err := ControllerSupervisorMonitorReadySHA256(f.identity, f.created)
	if err != nil || monitorReady != f.created.MonitorReadySHA256 {
		t.Fatalf("monitor-ready digest = %x, %v", monitorReady, err)
	}
	launch, err := ControllerSupervisorLaunchShimSHA256(f.identity, f.launch)
	if err != nil || launch != f.started.LaunchShimSHA256 {
		t.Fatalf("launch digest = %x, %v", launch, err)
	}

	tests := []struct {
		name   string
		encode func() ([]byte, error)
		want   string
	}{
		{"ready", func() ([]byte, error) { return EncodeControllerSupervisorSupervisorReadyBody(f.ready) }, "0006626f6f742d31000868656c7065722d31000c73757065727669736f722d31001068656c7065722d6c696d6974732d7631f184ff36331fa69007751e7a567f03dd9c9b369125a984f99ac7f5b02cfb70b3"},
		{"create", func() ([]byte, error) { return EncodeControllerSupervisorCreateJobBody(f.create) }, "000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001068656c7065722d6c696d6974732d76318f77e47200fe4b9fc5f8cb48f2840a50487f80b3b1fc6b373d29199778c8e3d44c0b5daf0102f695bfa60c63c5a993612d61f99161a735217eb9d12f76e6b05b"},
		{"created", func() ([]byte, error) { return EncodeControllerSupervisorJobCreatedBody(f.created) }, "000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001068656c7065722d6c696d6974732d7631f4ff4d17dfe08c11946ddb35dbb7c7c53f72c31ea14f0655c5e30c66819b0d38fef4fb8972101ac91c792380e1f06cc3713c69ba68ca89cbcaf63aee73458cae"},
		{"launch", func() ([]byte, error) { return EncodeControllerSupervisorLaunchShimBody(f.launch) }, "000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001641414543417751464267634943516f4c4441304f4477001068656c7065722d6c696d6974732d7631202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"},
		{"started", func() ([]byte, error) { return EncodeControllerSupervisorShimStartedBody(f.started) }, "000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001641414543417751464267634943516f4c4441304f44778b2dedea6f00f15c8d1e404ee84efee46c905e1e8f4aa27e7a03d06b1e1ae404"},
		{"terminate", func() ([]byte, error) { return EncodeControllerSupervisorTerminateJobBody(f.terminate) }, "000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d3101"},
		{"destroy", func() ([]byte, error) {
			return EncodeControllerSupervisorDestroyJobBody(ControllerSupervisorDestroyJobBody(f.terminate))
		}, "000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d3101"},
		{"event", func() ([]byte, error) { return EncodeControllerSupervisorEventBody(f.event) }, "01040000000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001641414543417751464267634943516f4c4441304f44770100000000000201"},
		{"attestation", func() ([]byte, error) { return EncodeControllerSupervisorControllerAttestationBody(f.attestation) }, "002a484c3844010100000000702f1015d6dded7d0991d3275cb3f36d4ddab234d208a9b851369dc6d5fb7df6"},
		{"accepted", func() ([]byte, error) { return EncodeControllerSupervisorCompositionAcceptedBody(f.accepted) }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
		{"close", func() ([]byte, error) {
			return EncodeControllerSupervisorCloseNotifyBody(ControllerSupervisorCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
		}, "01"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got, err := test.encode()
			if err != nil {
				t.Fatal(err)
			}
			want := controllerSupervisorHex(t, test.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("body = %x\nwant = %x", got, want)
			}
			got[0] ^= 0xff
			again, err := test.encode()
			if err != nil || reflect.DeepEqual(got, again) {
				t.Fatalf("encoder aliases output: %v", err)
			}
		})
	}
}

func TestL8ControllerSupervisorCanonicalDatagrams(t *testing.T) {
	t.Parallel()
	f := controllerSupervisorVectorFixture(t)
	createID := controllerSupervisor16(t, "101112131415161718191a1b1c1d1e1f")
	tests := []struct {
		name   string
		encode func() ([]byte, error)
		want   string
	}{
		{"ready", func() ([]byte, error) { return EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready) }, "484c384c010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000520006626f6f742d31000868656c7065722d31000c73757065727669736f722d31001068656c7065722d6c696d6974732d7631f184ff36331fa69007751e7a567f03dd9c9b369125a984f99ac7f5b02cfb70b3"},
		{"create", func() ([]byte, error) {
			return EncodeControllerSupervisorCreateJobPacket(1, createID, f.identity, f.create)
		}, "484c384c010200000000000000000001101112131415161718191a1b1c1d1e1fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000007f000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001068656c7065722d6c696d6974732d76318f77e47200fe4b9fc5f8cb48f2840a50487f80b3b1fc6b373d29199778c8e3d44c0b5daf0102f695bfa60c63c5a993612d61f99161a735217eb9d12f76e6b05b"},
		{"created", func() ([]byte, error) {
			return EncodeControllerSupervisorJobCreatedPacket(2, createID, f.identity, f.created)
		}, "484c384c010300000000000000000002101112131415161718191a1b1c1d1e1fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000007f000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001068656c7065722d6c696d6974732d7631f4ff4d17dfe08c11946ddb35dbb7c7c53f72c31ea14f0655c5e30c66819b0d38fef4fb8972101ac91c792380e1f06cc3713c69ba68ca89cbcaf63aee73458cae"},
		{"launch", func() ([]byte, error) {
			return EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)
		}, "484c384c010400000000000000000002000102030405060708090a0b0c0d0e0fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000097000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001641414543417751464267634943516f4c4441304f4477001068656c7065722d6c696d6974732d7631202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"},
		{"started", func() ([]byte, error) {
			return EncodeControllerSupervisorShimStartedPacket(3, f.launchRequest, f.identity, f.started)
		}, "484c384c010500000000000000000003000102030405060708090a0b0c0d0e0fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000065000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e742d3100086367726f75702d31001641414543417751464267634943516f4c4441304f44778b2dedea6f00f15c8d1e404ee84efee46c905e1e8f4aa27e7a03d06b1e1ae404"},
		{"composition", func() ([]byte, error) {
			return EncodeControllerSupervisorCompositionAcceptedPacket(1, f.accepted)
		}, "484c384c010a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			wire, err := test.encode()
			if err != nil {
				t.Fatal(err)
			}
			want := controllerSupervisorHex(t, test.want)
			if !reflect.DeepEqual(wire, want) {
				t.Fatalf("wire = %x\nwant = %x", wire, want)
			}
			packet, err := DecodeControllerSupervisorPacket(wire)
			if err != nil {
				t.Fatal(err)
			}
			round, err := EncodeControllerSupervisorPacket(packet)
			if err != nil || !reflect.DeepEqual(round, want) {
				t.Fatalf("round = %x, %v", round, err)
			}
			wire[0] = 'X'
			round2, err := EncodeControllerSupervisorPacket(packet)
			if err != nil || !reflect.DeepEqual(round2, want) {
				t.Fatalf("decoded packet aliases input")
			}
		})
	}
}

func TestL8ControllerSupervisorPacketReencodeRejectsForgedPrivateUnionAndHeader(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	readyWire := mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready))
	ready, err := DecodeControllerSupervisorPacket(readyWire)
	if err != nil {
		t.Fatal(err)
	}
	launchWire := mustControllerSupervisorWire(EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch))
	launch, err := DecodeControllerSupervisorPacket(launchWire)
	if err != nil {
		t.Fatal(err)
	}
	startedWire := mustControllerSupervisorWire(EncodeControllerSupervisorShimStartedPacket(3, f.launchRequest, f.identity, f.started))
	started, err := DecodeControllerSupervisorPacket(startedWire)
	if err != nil {
		t.Fatal(err)
	}
	eventWire := mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(4, f.launchRequest, f.identity, f.event))
	event, err := DecodeControllerSupervisorPacket(eventWire)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		packet ControllerSupervisorPacket
	}{
		{"body length", func() ControllerSupervisorPacket { packet := ready; packet.header.BodyLength++; return packet }()},
		{"changed type retains inactive ready arm", func() ControllerSupervisorPacket {
			packet := ready
			packet.header.Type = ControllerSupervisorPacketTypeCloseNotify
			return packet
		}()},
		{"inactive create arm", func() ControllerSupervisorPacket { packet := ready; packet.create = f.create; return packet }()},
		{"inactive created arm", func() ControllerSupervisorPacket { packet := ready; packet.created = f.created; return packet }()},
		{"inactive launch arm", func() ControllerSupervisorPacket { packet := ready; packet.launch = f.launch; return packet }()},
		{"inactive started arm", func() ControllerSupervisorPacket { packet := ready; packet.started = f.started; return packet }()},
		{"inactive terminate arm", func() ControllerSupervisorPacket { packet := ready; packet.terminate = f.terminate; return packet }()},
		{"inactive destroy arm", func() ControllerSupervisorPacket {
			packet := ready
			packet.destroy = ControllerSupervisorDestroyJobBody(f.terminate)
			return packet
		}()},
		{"inactive event arm", func() ControllerSupervisorPacket { packet := ready; packet.event = f.event; return packet }()},
		{"inactive descriptor arm", func() ControllerSupervisorPacket { packet := ready; packet.attestation = f.attestation; return packet }()},
		{"inactive accepted arm", func() ControllerSupervisorPacket { packet := ready; packet.accepted = f.accepted; return packet }()},
		{"inactive close arm", func() ControllerSupervisorPacket { packet := ready; packet.closeBody.Reason = 1; return packet }()},
		{"launch request ID no longer derives launch ID", func() ControllerSupervisorPacket { packet := launch; packet.header.RequestID[0] ^= 0xff; return packet }()},
		{"started request ID no longer derives launch ID", func() ControllerSupervisorPacket {
			packet := started
			packet.header.RequestID[0] ^= 0xff
			return packet
		}()},
		{"event request ID no longer derives launch ID", func() ControllerSupervisorPacket { packet := event; packet.header.RequestID[0] ^= 0xff; return packet }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if encoded, err := EncodeControllerSupervisorPacket(test.packet); err == nil || encoded != nil {
				t.Fatalf("forged encode = %x/%v", encoded, err)
			}
		})
	}
	for _, canonical := range []struct {
		packet ControllerSupervisorPacket
		wire   []byte
	}{{ready, readyWire}, {launch, launchWire}, {started, startedWire}, {event, eventWire}} {
		encoded, err := EncodeControllerSupervisorPacket(canonical.packet)
		if err != nil || !reflect.DeepEqual(encoded, canonical.wire) {
			t.Fatalf("canonical round trip = %x/%v", encoded, err)
		}
	}
}

func TestL8ControllerSupervisorReceiveMetadataBoundsBeforeIndexAndExactRoles(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	wire, err := EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := DecodeControllerSupervisorPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	pid1 := ControllerSupervisorKernelCredential{PID: 1}
	controller := ControllerSupervisorKernelCredential{PID: 2147483647}
	agent := ControllerSupervisorKernelCredential{PID: 2, UID: 1000, GID: 1000}
	digest, _ := ControllerSupervisorLaunchShimSHA256(f.identity, f.launch)
	meta := ControllerSupervisorReceiveMetadata{Direction: ControllerSupervisorDirectionControllerToPID1, Credential: controller, CredentialCount: 1, RightsCount: 8, Rights: [8]ControllerSupervisorRightMetadata{{ControllerSupervisorRightMonitorNamespace, ControllerSupervisorAccessNamespaceEnter, f.launch.MountGeneration, digest}, {ControllerSupervisorRightWorkdir, ControllerSupervisorAccessDirectoryChdir, f.launch.MountGeneration, digest}, {ControllerSupervisorRightExecutable, ControllerSupervisorAccessExecutableRead, f.launch.JobGeneration, f.launch.ExecutableSHA256}, {ControllerSupervisorRightStdinRead, ControllerSupervisorAccessPipeRead, f.launch.LaunchID, digest}, {ControllerSupervisorRightStdoutWrite, ControllerSupervisorAccessPipeWrite, f.launch.LaunchID, digest}, {ControllerSupervisorRightStderrWrite, ControllerSupervisorAccessPipeWrite, f.launch.LaunchID, digest}, {ControllerSupervisorRightStartGateRead, ControllerSupervisorAccessPipeRead, f.launch.LaunchID, digest}, {ControllerSupervisorRightLaunchBlockRead, ControllerSupervisorAccessSealedPipeRead, f.launch.LaunchID, f.launch.LaunchBlockSHA256}}}
	if err := ValidateControllerSupervisorReceiveMetadata(packet, meta, pid1, controller, agent.PID); err != nil {
		t.Fatal(err)
	}
	meta.RightsCount = 9
	if err := ValidateControllerSupervisorReceiveMetadata(packet, meta, pid1, controller, agent.PID); err != ErrControllerSupervisorRights {
		t.Fatalf("rights > 8 error = %v", err)
	}
	meta.RightsCount = 8
	meta.Rights[0], meta.Rights[1] = meta.Rights[1], meta.Rights[0]
	if err := ValidateControllerSupervisorReceiveMetadata(packet, meta, pid1, controller, agent.PID); err != ErrControllerSupervisorRightMetadata {
		t.Fatalf("reordered error = %v", err)
	}
	meta.Rights[0], meta.Rights[1] = meta.Rights[1], meta.Rights[0]
	agent.PID = controller.PID
	if err := ValidateControllerSupervisorReceiveMetadata(packet, meta, pid1, controller, agent.PID); err != ErrControllerSupervisorRoleIdentityAlias {
		t.Fatalf("alias error = %v", err)
	}
}

type controllerSupervisorFixture struct {
	ready         ControllerSupervisorSupervisorReadyBody
	create        ControllerSupervisorCreateJobBody
	created       ControllerSupervisorJobCreatedBody
	launch        ControllerSupervisorLaunchShimBody
	started       ControllerSupervisorShimStartedBody
	terminate     ControllerSupervisorTerminateJobBody
	event         ControllerSupervisorEventBody
	attestation   ControllerSupervisorControllerAttestationBody
	accepted      ControllerSupervisorCompositionAcceptedBody
	identity      [32]byte
	launchRequest [16]byte
}

func controllerSupervisorVectorFixture(t *testing.T) controllerSupervisorFixture {
	t.Helper()
	f := controllerSupervisorFixture{}
	f.identity = controllerSupervisor32(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	f.launchRequest = controllerSupervisor16(t, "000102030405060708090a0b0c0d0e0f")
	f.ready = ControllerSupervisorSupervisorReadyBody{"boot-1", "helper-1", "supervisor-1", ControllerSupervisorLimitSetID, controllerSupervisor32(t, "f184ff36331fa69007751e7a567f03dd9c9b369125a984f99ac7f5b02cfb70b3")}
	f.create = ControllerSupervisorCreateJobBody{1, "job-1", "monitor-1", "mount-1", "cgroup-1", ControllerSupervisorLimitSetID, controllerSupervisor32(t, "8f77e47200fe4b9fc5f8cb48f2840a50487f80b3b1fc6b373d29199778c8e3d4"), controllerSupervisor32(t, "4c0b5daf0102f695bfa60c63c5a993612d61f99161a735217eb9d12f76e6b05b")}
	f.created = ControllerSupervisorJobCreatedBody{1, "job-1", "monitor-1", "mount-1", "cgroup-1", ControllerSupervisorLimitSetID, controllerSupervisor32(t, "f4ff4d17dfe08c11946ddb35dbb7c7c53f72c31ea14f0655c5e30c66819b0d38"), controllerSupervisor32(t, "fef4fb8972101ac91c792380e1f06cc3713c69ba68ca89cbcaf63aee73458cae")}
	f.launch = ControllerSupervisorLaunchShimBody{1, "job-1", "monitor-1", "mount-1", "cgroup-1", "AAECAwQFBgcICQoLDA0ODw", ControllerSupervisorLimitSetID, controllerSupervisor32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"), controllerSupervisor32(t, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")}
	f.started = ControllerSupervisorShimStartedBody{1, "job-1", "monitor-1", "mount-1", "cgroup-1", f.launch.LaunchID, controllerSupervisor32(t, "8b2dedea6f00f15c8d1e404ee84efee46c905e1e8f4aa27e7a03d06b1e1ae404")}
	f.terminate = ControllerSupervisorTerminateJobBody{1, "job-1", "monitor-1", "mount-1", "cgroup-1", ControllerSupervisorReasonRequested}
	f.event = ControllerSupervisorEventBody{ControllerSupervisorEventShimExited, ControllerSupervisorPacketTypeLaunchShim, ControllerSupervisorFailureNone, 1, "job-1", "monitor-1", "mount-1", "cgroup-1", f.launch.LaunchID, ControllerSupervisorExitExited, 0, false, ControllerSupervisorMonitorReady, ControllerSupervisorCleanupNotApplicable}
	descriptor, err := DecodeProcessDescriptor(controllerSupervisorHex(t, "484c3844010100000000702f1015d6dded7d0991d3275cb3f36d4ddab234d208a9b851369dc6d5fb7df6"))
	if err != nil {
		t.Fatal(err)
	}
	f.attestation = ControllerSupervisorControllerAttestationBody{descriptor}
	copy(f.accepted.CompositionSHA256[:], controllerSupervisorHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	return f
}
func controllerSupervisorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
func controllerSupervisor32(t *testing.T, value string) (out [32]byte) {
	t.Helper()
	copy(out[:], controllerSupervisorHex(t, value))
	return out
}
func controllerSupervisor16(t *testing.T, value string) (out [16]byte) {
	t.Helper()
	copy(out[:], controllerSupervisorHex(t, value))
	return out
}
func controllerSupervisorMutate(input []byte, index int, value byte) []byte {
	out := append([]byte(nil), input...)
	out[index] = value
	return out
}
