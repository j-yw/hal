//go:build linux

package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlFirecrackerConfigRejectsMalformedMeasuredBytes(t *testing.T) {
	fixture := newMinimalControlAdmissionFixture(t)
	base := minimalControlFCFixtureBytes(t, fixture)
	var parsed strictJailerConfigFile
	if err := json.Unmarshal(base, &parsed); err != nil {
		t.Fatal(err)
	}
	encode := func(config strictJailerConfigFile) []byte {
		payload, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	tests := map[string][]byte{
		"null":              []byte("null"),
		"array":             []byte("[]"),
		"truncated":         bytes.Clone(base[:len(base)-1]),
		"trailing-document": append(bytes.Clone(base), []byte(" {}")...),
		"unknown-root":      bytes.Replace(base, []byte(`"boot-source":`), []byte(`"unknown":0,"boot-source":`), 1),
		"wrong-case-root":   bytes.Replace(base, []byte(`"boot-source":`), []byte(`"Boot-source":`), 1),
		"duplicate-root":    bytes.Replace(base, []byte(`"boot-source":`), []byte(`"boot-source":{},"boot-source":`), 1),
		"escaped-duplicate": bytes.Replace(base, []byte(`"boot-source":`), []byte(`"\u0062oot-source":{},"boot-source":`), 1),
		"unknown-nested":    bytes.Replace(base, []byte(`"kernel_image_path":`), []byte(`"unknown":0,"kernel_image_path":`), 1),
		"duplicate-nested":  bytes.Replace(base, []byte(`"kernel_image_path":`), []byte(`"kernel_image_path":"other","kernel_image_path":`), 1),
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(base, &object); err != nil {
		t.Fatal(err)
	}
	tests["wrong-boot-type"] = bytes.Replace(base, object["boot-source"], []byte("7"), 1)
	nic := string(parsed.NetworkInterfaces)
	for name, raw := range map[string]string{
		"absent": "", "null": "null", "empty": "[]", "object": "{}", "null-member": "[null]",
		"extra-interface":   strings.TrimSuffix(nic, "]") + "," + strings.TrimPrefix(nic, "["),
		"unknown-member":    strings.Replace(nic, `"iface_id":`, `"unknown":0,"iface_id":`, 1),
		"duplicate-member":  strings.Replace(nic, `"iface_id":`, `"iface_id":"net1","iface_id":`, 1),
		"wrong-case-member": strings.Replace(nic, `"iface_id":`, `"Iface_id":`, 1),
		"wrong-member-type": strings.Replace(nic, `"iface_id":"net1"`, `"iface_id":7`, 1),
	} {
		candidate := parsed
		candidate.NetworkInterfaces = json.RawMessage(raw)
		tests["nic-"+name] = encode(candidate)
	}
	boot := parsed.BootSource.BootArgs
	for name, line := range map[string]string{
		"missing-minimal":        minimalL7BootFragment(fixture.config.Control.StaticNetwork),
		"missing-minimal-member": strings.Replace(boot, "hal_minimal_boot_generation=boot-1", "", 1),
		"duplicate-minimal":      boot + " hal_minimal_boot_generation=boot-1",
		"unknown-minimal":        boot + " hal_minimal_unknown=value",
		"bare-minimal":           boot + " hal_minimal",
		"wrong-case-minimal":     strings.Replace(boot, "hal_minimal_boot_generation=", "HAL_MINIMAL_BOOT_GENERATION=", 1),
		"quoted-minimal":         strings.Replace(boot, "hal_minimal_boot_generation=", "'hal_minimal_boot_generation'=", 1),
		"quoted-minimal-value":   strings.Replace(boot, "hal_minimal_boot_generation=boot-1", `hal_minimal_boot_generation="boot-1"`, 1),
		"wrong-minimal-profile":  strings.Replace(boot, "guest-agent-minimal-v1", "guest-agent-v1", 1),
		"missing-l7-member":      strings.Replace(boot, "hal_l7_net_if=eth0", "", 1),
		"duplicate-l7":           boot + " hal_l7_net_if=eth0",
		"unknown-l7":             boot + " hal_l7_unknown=value",
		"bare-l7":                boot + " hal_l7",
		"wrong-case-l7":          strings.Replace(boot, "hal_l7_net_if=", "HAL_L7_NET_IF=", 1),
		"quoted-l7":              strings.Replace(boot, "hal_l7_net_if=", "'hal_l7_net_if'=", 1),
		"normalized-ipv6-alias":  strings.Replace(boot, "hal_l7_ipv6=fd00::2/126", "hal_l7_ipv6=fd00:0::2/126", 1),
		"proxy-port-alias":       strings.Replace(boot, "http://192.0.2.1:3128", "http://192.0.2.1:03128", 1),
		"control-character":      boot + "\x00",
		"newline-in-fc":          boot + "\n",
		"combined-4096-bytes":    boot + " " + strings.Repeat("x", 4096-len(boot)-1),
	} {
		candidate := parsed
		candidate.BootSource.BootArgs = line
		tests["boot-"+name] = encode(candidate)
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			replaceMinimalControlFCFixture(t, f, payload)
			if _, _, err := decodeMinimalControlSupervisorConfig(f.payload); err != nil {
				t.Fatal("outer config rejected fixture; measured-byte test not reached")
			}
			asset := f.config.Config
			if validateL8RuntimeOwnerAssetFD(int(f.files[6].Fd()), l8RuntimeOwnerDescriptorIdentityV1{Kind: asset.Kind, Device: asset.Device, Inode: asset.Inode, Digest: asset.SHA256}) != nil {
				t.Fatal("fixture bytes did not match their independent asset measurement")
			}
			code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { return nil })
			if code != 127 || f.admissions != 0 || f.legacy != 0 || len(f.closed) != 8 {
				t.Fatalf("malformed measured config escaped closed admission: exit=%d callbacks=%d legacy=%d closes=%d", code, f.admissions, f.legacy, len(f.closed))
			}
		})
	}
}

func TestMinimalControlFirecrackerConfigAcceptedBounds(t *testing.T) {
	for _, name := range []string{"combined-4095-bytes", "one-MiB-config"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			payload := minimalControlFCFixtureBytes(t, f)
			if name == "combined-4095-bytes" {
				var config strictJailerConfigFile
				if err := json.Unmarshal(payload, &config); err != nil {
					t.Fatal(err)
				}
				config.BootSource.BootArgs += " " + strings.Repeat("x", 4095-len(config.BootSource.BootArgs)-1)
				var err error
				payload, err = json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				payload = append(payload, bytes.Repeat([]byte(" "), maxStrictJailerConfigBytes-len(payload))...)
			}
			replaceMinimalControlFCFixture(t, f, payload)
			if code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { return nil }); code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
				t.Fatal("valid bounded measured config failed admission")
			}
		})
	}
}

func TestMinimalControlFirecrackerConfigReaderPreservesBorrowedFD(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	original := minimalControlFCFixtureBytes(t, f)
	fd, asset := int(f.files[6].Fd()), f.config.Config
	for name, altered := range map[string]jailerRecoveryAsset{
		"matching":      asset,
		"negative-size": {Size: -1}, "zero-size": {Size: 0},
		"over-limit": {Size: maxStrictJailerConfigBytes + 1}, "extreme-size": {Size: math.MaxInt64},
		"short-read":     {Size: asset.Size + 1, SHA256: asset.SHA256},
		"truncated-read": {Size: asset.Size - 1, SHA256: asset.SHA256},
		"wrong-digest":   {Size: asset.Size, SHA256: strings.Repeat("0", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := unix.Seek(fd, 7, 0); err != nil {
				t.Fatal(err)
			}
			got, err := readMinimalControlFirecrackerConfig(fd, altered)
			if (err == nil) != (name == "matching") || err != nil && !reflect.DeepEqual(got, strictJailerConfigFile{}) {
				t.Fatal("reader did not enforce its exact size/digest boundary")
			}
			if offset, err := unix.Seek(fd, 0, 1); err != nil || offset != 7 || !bytes.Equal(minimalControlFCFixtureBytes(t, f), original) {
				t.Fatal("reader closed, sought or changed the retained borrowed descriptor")
			}
		})
	}
	if _, err := readMinimalControlFirecrackerConfig(-1, asset); err == nil {
		t.Fatal("unavailable retained descriptor accepted")
	}
	// A genuinely measured, otherwise valid JSON object just over the cap
	// must fail in the reader itself, not only in the outer config validator.
	oversized := append(bytes.Clone(original), bytes.Repeat([]byte(" "), maxStrictJailerConfigBytes+1-len(original))...)
	replaceMinimalControlFCFixture(t, f, oversized)
	if _, err := readMinimalControlFirecrackerConfig(int(f.files[6].Fd()), f.config.Config); err == nil {
		t.Fatal("reader accepted an otherwise valid measured object over its fixed cap")
	}
}

func replaceMinimalControlFCFixture(t *testing.T, f *minimalControlAdmissionFixture, payload []byte) {
	t.Helper()
	if err := f.files[6].Close(); err != nil {
		t.Fatal(err)
	}
	f.files[6] = minimalControlTestMemfd(t, payload, l8RuntimeOwnerRequiredSeals, 0o400, true)
	f.config.Config = minimalControlTestMeasuredAsset(t, f.files[6], "config", payload)
	f.reseal(nil)
}
