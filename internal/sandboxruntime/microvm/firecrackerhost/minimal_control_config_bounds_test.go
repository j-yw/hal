//go:build linux

package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlConfigPublicDecoderAcceptsFrozenFixture(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	if !boundedMinimalControlConfigJSON(f.payload) {
		t.Fatal("fixture exceeds bounded schema")
	}
	if err := validateJailerRecoveryCommonConfig(f.config.jailerRecoverySupervisorConfig); err != nil {
		t.Fatal("fixture common metadata rejected")
	}
	if _, _, err := decodeMinimalControlSupervisorConfig(f.payload); err != nil {
		t.Fatal("fixture public config rejected")
	}
	if err := validateL8RuntimeOwnerSeqpacketFD(int(f.files[0].Fd())); err != nil {
		t.Fatal("fixture socket rejected")
	}
	if err := validateL8RuntimeOwnerDirectoryFD(int(f.files[1].Fd())); err != nil {
		t.Fatal("fixture directory rejected")
	}
	var all []int
	for _, file := range f.files {
		all = append(all, int(file.Fd()))
	}
	if !minimalControlAdmissionFDsDistinct(all) {
		t.Fatal("fixture descriptors not distinct")
	}
	for i, asset := range []jailerRecoveryAsset{f.config.Kernel, f.config.Rootfs, f.config.Config} {
		fd := []int{all[3], all[4], all[6]}[i]
		if validateL8RuntimeOwnerAssetFD(fd, l8RuntimeOwnerDescriptorIdentityV1{Kind: asset.Kind, Device: asset.Device, Inode: asset.Inode, Digest: asset.SHA256}) != nil {
			t.Fatalf("fixture asset %d rejected", i)
		}
	}
}

func TestMinimalControlConfigBoundsAndRemainingSchemaNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*minimalControlAdmissionFixture){
		"directory mode": func(f *minimalControlAdmissionFixture) {
			if err := f.files[1].Chmod(0o755); err != nil {
				f.t.Fatal(err)
			}
		},
		"socket kind": func(f *minimalControlAdmissionFixture) {
			_ = f.files[0].Close()
			file, err := os.Open(f.files[1].Name())
			if err != nil {
				f.t.Fatal(err)
			}
			f.files[0] = file
		},
		"aliased source inode": func(f *minimalControlAdmissionFixture) {
			_ = f.files[7].Close()
			fd, err := unix.FcntlInt(f.files[6].Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				f.t.Fatal(err)
			}
			f.files[7] = os.NewFile(uintptr(fd), "aliased-test-input")
		},
		"changed actual kernel bytes": func(f *minimalControlAdmissionFixture) {
			_ = f.files[3].Close()
			f.files[3] = minimalControlTestMemfd(f.t, []byte("different-content!!"), l8RuntimeOwnerRequiredSeals, 0o400, true)
		},
		"wrong declared kernel size": func(f *minimalControlAdmissionFixture) { f.config.Kernel.Size++; f.reseal(nil) },
		"wrong declared rootfs size": func(f *minimalControlAdmissionFixture) { f.config.Rootfs.Size++; f.reseal(nil) },
		"wrong declared FC size":     func(f *minimalControlAdmissionFixture) { f.config.Config.Size++; f.reseal(nil) },
		"missing public key":         func(f *minimalControlAdmissionFixture) { f.config.Control.ControllerPublicKey = ""; f.reseal(nil) },
		"padded public key":          func(f *minimalControlAdmissionFixture) { f.config.Control.ControllerPublicKey += "="; f.reseal(nil) },
		"padded nonce":               func(f *minimalControlAdmissionFixture) { f.config.Control.BootNonce += "="; f.reseal(nil) },
		"binding alias": func(f *minimalControlAdmissionFixture) {
			c := f.config.Control.Prelaunch
			c["PlanId"] = c["planId"]
			delete(c, "planId")
			f.reseal(nil)
		},
		"overlong binding": func(f *minimalControlAdmissionFixture) {
			f.config.Control.Prelaunch["planId"] = strings.Repeat("x", 65)
			f.reseal(nil)
		},
		"noncanonical admission revision": func(f *minimalControlAdmissionFixture) {
			f.config.Control.Prelaunch["admissionRevision"] = "07"
			f.reseal(nil)
		},
		"absent NIC": func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface = minimalL7NetworkInterface{}
			f.reseal(nil)
		},
		"wrong fixed NIC": func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.InterfaceID = "net2"
			f.reseal(nil)
		},
		"unsafe TAP": func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.HostDeviceName = "a/b"
			f.reseal(nil)
		},
		"overlong TAP": func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.HostDeviceName = strings.Repeat("x", 16)
			f.reseal(nil)
		},
		"noncanonical MAC": func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.GuestMAC = "0200.0000.0001"
			f.reseal(nil)
		},
		"multicast MAC": func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.GuestMAC = "03:00:00:00:00:01"
			f.reseal(nil)
		},
		"absent static fields":        func(f *minimalControlAdmissionFixture) { f.config.Control.StaticNetwork = [6]string{}; f.reseal(nil) },
		"wrong fixed guest interface": func(f *minimalControlAdmissionFixture) { f.config.Control.StaticNetwork[0] = "eth1"; f.reseal(nil) },
		"normalized IPv6": func(f *minimalControlAdmissionFixture) {
			f.config.Control.StaticNetwork[3] = "fd00:0:0:0:0:0:0:2/126"
			f.reseal(nil)
		},
		"proxy credentials": func(f *minimalControlAdmissionFixture) {
			f.config.Control.StaticNetwork[5] = "http://user:public-test@192.0.2.1:3128"
			f.reseal(nil)
		},
		"network tuple missing inode": func(f *minimalControlAdmissionFixture) { f.config.Control.Namespace.NetworkInode = 0; f.reseal(nil) },
		"negative preparation timestamp": func(f *minimalControlAdmissionFixture) {
			f.config.Control.PreparationDeadlineUnixNano = -1
			f.reseal(nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			mutate(f)
			f.reject(t)
		})
	}
}

func TestMinimalControlConfigCanonicalSchemaAndDiscriminatorDowngrade(t *testing.T) {
	for _, name := range []string{"escaped discriminator", "duplicate discriminator", "conflicting discriminator", "aliased discriminator", "null discriminator", "legacy downgrade", "nested null", "nested array", "excess depth", "oversized field", "static short array", "static extra array"} {
		t.Run(name, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			payload := bytes.Clone(f.payload)
			version, _ := json.Marshal(f.config.Version)
			field := append([]byte(`"version":`), version...)
			switch name {
			case "escaped discriminator":
				payload = bytes.Replace(payload, []byte(`"version"`), []byte(`"ver\u0073ion"`), 1)
			case "duplicate discriminator":
				payload = bytes.Replace(payload, field, append(append(bytes.Clone(field), ','), field...), 1)
			case "conflicting discriminator":
				payload = bytes.Replace(payload, field, append([]byte(`"version":"`), []byte(jailerRecoveryConfigVersion+`",`+string(field))...), 1)
			case "aliased discriminator":
				payload = bytes.Replace(payload, []byte(`"version"`), []byte(`"Version"`), 1)
			case "null discriminator":
				payload = bytes.Replace(payload, field, []byte(`"version":null`), 1)
			case "legacy downgrade":
				legacy, err := encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerTestSupervisorConfig())
				if err != nil {
					t.Fatal(err)
				}
				payload = append(append(bytes.Clone(legacy[:len(legacy)-1]), ','), append(field, '}')...)
			case "nested null":
				payload = bytes.Replace(payload, []byte(`"namespace":{`), []byte(`"namespace":null,"discard":{`), 1)
			case "nested array":
				payload = bytes.Replace(payload, []byte(`"prelaunch":{`), []byte(`"prelaunch":[],"discard":{`), 1)
			case "excess depth":
				payload = bytes.Replace(payload, []byte(`"launchGrantId":"launch-grant-1"`), []byte(`"launchGrantId":{"a":{"b":{"c":1}}}`), 1)
			case "oversized field":
				payload = bytes.Replace(payload, []byte(`"launch-grant-1"`), []byte(`"`+strings.Repeat("x", l8RuntimeOwnerSupervisorConfigLimit)+`"`), 1)
			case "static short array":
				fields, _ := json.Marshal(f.config.Control.StaticNetwork)
				payload = bytes.Replace(payload, fields, []byte(`[]`), 1)
			case "static extra array":
				fields, _ := json.Marshal(f.config.Control.StaticNetwork)
				payload = bytes.Replace(payload, fields, append(bytes.Clone(fields[:len(fields)-1]), []byte(`,"extra"]`)...), 1)
			}
			if bytes.Equal(payload, f.payload) {
				t.Fatal("unmodified negative")
			}
			f.reseal(payload)
			f.reject(t)
		})
	}
}

func TestMinimalControlConfigByteAdmissionDoesNotClaimActiveDeadline(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	f.config.Control.PreparationDeadlineUnixNano = 1
	f.reseal(nil)
	if code := f.run("supervise", unavailableMinimalControlSupervisor); code != 127 || f.admissions != 1 || f.legacy != 0 {
		t.Fatal("positive timestamp syntax was confused with active deadline or runtime success")
	}
}

func TestMinimalControlConfigMeasuresEveryActualAssetAfterPublicValidation(t *testing.T) {
	for _, kind := range []string{"kernel", "rootfs", "config"} {
		t.Run(kind, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			badDigest := strings.Repeat("e", 64)
			switch kind {
			case "kernel":
				f.config.Kernel.SHA256 = badDigest
			case "rootfs":
				f.config.Rootfs.SHA256 = badDigest
				f.config.Control.Prelaunch["imageDigest"] = "sha256-" + badDigest
			case "config":
				f.config.Config.SHA256 = badDigest
			}
			f.reseal(nil)
			if _, _, err := decodeMinimalControlSupervisorConfig(f.payload); err != nil {
				t.Fatal("asset negative rejected before real FD measurement")
			}
			f.reject(t)
			if len(f.opened) != 8 || len(f.closed) != 8 {
				t.Fatal("measurement negative missed full owned admission")
			}
		})
	}
}
