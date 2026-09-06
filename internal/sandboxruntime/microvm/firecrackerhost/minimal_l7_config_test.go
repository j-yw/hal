//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

func TestMinimalL7ConfigRejectsMalformedNICBeforeHostDependencies(t *testing.T) {
	expected := minimalL7ConfigTestExpectation(t, "127.0.0.1:43123")
	base := minimalL7ConfigTestJSON(t, expected, true)
	iface, tap, mac, _ := expected.descriptor.NetworkInterface()
	if strings.ToUpper(mac) == mac {
		t.Fatal("fixture MAC must exercise canonical lowercase spelling")
	}
	nic := `{"iface_id":"` + iface + `","host_dev_name":"` + tap + `","guest_mac":"` + mac + `"}`
	for name, value := range map[string]string{
		"absent": "", "null": "null", "empty array": "[]", "object": nic,
		"boolean": "true", "number": "1", "string": `"network"`, "null entry": "[null]",
		"two entries": "[" + nic + "," + nic + "]", "empty entry": "[{}]",
		"unknown entry field": "[" + strings.TrimSuffix(nic, "}") + `,"unknown":true}]`,
		// boot_args is canonical elsewhere in the outer schema. This must fail
		// the typed NIC decoder rather than relying only on the global key set.
		"misplaced canonical field": "[" + strings.TrimSuffix(nic, "}") + `,"boot_args":"x"}]`,
		"nested canonical field":    "[" + strings.Replace(nic, `"`+tap+`"`, `{"host_dev_name":"`+tap+`"}`, 1) + "]",
		"wrong interface":           "[" + strings.Replace(nic, `"`+iface+`"`, `"net2"`, 1) + "]",
		"wrong TAP":                 "[" + strings.Replace(nic, `"`+tap+`"`, `"foreign-tap"`, 1) + "]",
		"TAP whitespace":            "[" + strings.Replace(nic, `"`+tap+`"`, `" `+tap+`"`, 1) + "]",
		"wrong MAC":                 "[" + strings.Replace(nic, `"`+mac+`"`, `"02:00:00:00:00:01"`, 1) + "]",
		"noncanonical MAC case":     "[" + strings.Replace(nic, `"`+mac+`"`, `"`+strings.ToUpper(mac)+`"`, 1) + "]",
		"wrong case key":            "[" + strings.Replace(nic, `"iface_id"`, `"Iface_ID"`, 1) + "]",
		"duplicate key":             "[" + strings.TrimSuffix(nic, "}") + `,"iface_id":"net1"}]`,
		"missing iface":             "[" + strings.Replace(nic, `"iface_id":"`+iface+`",`, "", 1) + "]",
		"missing TAP":               "[" + strings.Replace(nic, `"host_dev_name":"`+tap+`",`, "", 1) + "]",
		"missing MAC":               "[" + strings.Replace(nic, `,"guest_mac":"`+mac+`"`, "", 1) + "]",
		"null MAC":                  "[" + strings.Replace(nic, `"`+mac+`"`, "null", 1) + "]",
	} {
		t.Run(name, func(t *testing.T) {
			minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceJSONField(t, base, "network-interfaces", value))
		})
	}
	for name, config := range map[string]string{
		"duplicate network field":  strings.TrimSuffix(base, "}") + `,"network-interfaces":[` + nic + "]}",
		"wrong case network field": strings.Replace(base, `"network-interfaces"`, `"Network-Interfaces"`, 1),
		"trailing document":        base + " {}",
	} {
		t.Run(name, func(t *testing.T) { minimalL7AssertInvalidBeforeHost(t, expected, config) })
	}
}

func TestMinimalL7ConfigRejectsNamespaceAliasesAndRawValueSubstitution(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:43123", "[::1]:43123"} {
		t.Run(endpoint, func(t *testing.T) {
			expected := minimalL7ConfigTestExpectation(t, endpoint)
			base := minimalL7ConfigTestJSON(t, expected, true)
			_, boot, err := renderMinimalL7Config("console=ttyS0", expected)
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{
				"hal_l7", "hal_l7=x", "hal_l7_net_if", "hal_l7_net_if=", "hal_l7_unknown=x",
				"hal_l7_net_if=eth0", "HAL_L7_NET_IF=eth0", "HAL_L7=x", "HaL_L7_Unknown=x",
				`"hal_l7_net_if"=eth0`, `'hal_l7_net_if'=eth0`, `"hal_l7_net_if=eth0"`, `'hal_l7_net_if=eth0'`,
				`"hal_l7"=x`, `'HAL_L7_UNKNOWN'=x`,
			} {
				t.Run(token, func(t *testing.T) {
					minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceBoot(t, base, boot+" "+token))
					if _, _, err := renderMinimalL7Config("console=ttyS0 "+token, expected); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
						t.Fatalf("renderer accepted existing/malformed namespace: %v", err)
					}
				})
			}
			values, err := minimalL7BootFields(boot)
			if err != nil {
				t.Fatal(err)
			}
			for index, key := range minimalL7BootKeys {
				t.Run("missing "+key, func(t *testing.T) {
					minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceBoot(t, base,
						strings.Replace(boot, key+"="+values[index], "", 1)))
				})
				t.Run("changed "+key, func(t *testing.T) {
					minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceBoot(t, base,
						strings.Replace(boot, key+"="+values[index], key+"="+values[index]+"-other", 1)))
				})
			}
			prefix := netip.MustParsePrefix(values[3])
			expanded := prefix.Addr().StringExpanded() + "/126"
			if expanded == values[3] {
				t.Fatal("fixture did not exercise noncanonical IPv6 spelling")
			}
			normalizable := strings.Replace(boot, values[3], expanded, 1)
			parsed, present, err := guestnetwork.ParseBootCommandLine(normalizable)
			if err != nil || !present || parsed.IPv6Address() != values[3] {
				t.Fatalf("guest parser no longer normalizes equivalent fixture: %v", err)
			}
			minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceBoot(t, base, normalizable))
			for _, changed := range []string{
				strings.Replace(boot, values[3], strings.ToUpper(values[3]), 1),
				strings.Replace(boot, values[4], netip.MustParseAddr(values[4]).StringExpanded(), 1),
				strings.Replace(boot, values[5], values[5]+"/", 1),
				strings.Replace(boot, ":43123", ":043123", 1),
				strings.Replace(boot, "http://", "HTTP://", 1),
				"", boot + "\n", boot + "\r", boot + "\x00", boot + "\x7f",
			} {
				if changed == boot {
					t.Fatal("mutation did not change selected raw fields")
				}
				minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceBoot(t, base, changed))
			}
		})
	}
}

func TestMinimalL7ConfigRejectsUnissuedAndMismatchedExpectations(t *testing.T) {
	expected := minimalL7ConfigTestExpectation(t, "127.0.0.1:43123")
	config := minimalL7ConfigTestJSON(t, expected, true)
	for name, mutate := range map[string]func(*minimalL7ConfigExpectation){
		"zero descriptor": func(e *minimalL7ConfigExpectation) { e.descriptor = l7network.LaunchDescriptor{} },
		"JSON descriptor": func(e *minimalL7ConfigExpectation) {
			e.descriptor = l7network.LaunchDescriptor{}
			if err := json.Unmarshal([]byte(`{"seal":true,"identity":{},"spec":{}}`), &e.descriptor); err != nil {
				t.Fatal(err)
			}
		},
		"runtime mismatch":  func(e *minimalL7ConfigExpectation) { e.runtimeGeneration += "-other" },
		"topology mismatch": func(e *minimalL7ConfigExpectation) { e.topologyGeneration += "-other" },
		"runtime absent":    func(e *minimalL7ConfigExpectation) { e.runtimeGeneration = "" },
		"topology absent":   func(e *minimalL7ConfigExpectation) { e.topologyGeneration = "" },
		"generation swap": func(e *minimalL7ConfigExpectation) {
			e.runtimeGeneration, e.topologyGeneration = e.topologyGeneration, e.runtimeGeneration
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := *expected
			mutate(&copy)
			minimalL7AssertInvalidBeforeHost(t, &copy, config)
			if nic, boot, err := renderMinimalL7Config("console=ttyS0", &copy); !errors.Is(err, errStrictJailerCoordinatorInvalid) || nic != (minimalL7NetworkInterface{}) || boot != "" {
				t.Fatalf("invalid expectation renderer returned output: %v", err)
			}
		})
	}
	if _, _, err := renderMinimalL7Config("console=ttyS0", nil); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
		t.Fatalf("nil expectation renderer = %v", err)
	}
}

func TestMinimalL7ConfigCombinedMinimalRendererBudgetAndImmutableInputs(t *testing.T) {
	expected := minimalL7ConfigTestExpectation(t, "[::1]:43123")
	beforeExpectation := *expected
	identity, key, fields := minimalL7BootstrapTestInputs(expected)
	beforeIdentity, beforeKey, beforeFields := identity, bytes.Clone(key), maps.Clone(fields)
	const base = "console=ttyS0 root=/dev/vda init=/sbin/init"
	nic, networkBoot, err := renderMinimalL7Config(base, expected)
	if err != nil {
		t.Fatal(err)
	}
	iface, tap, mac, _ := expected.descriptor.NetworkInterface()
	if nic != (minimalL7NetworkInterface{InterfaceID: iface, HostDeviceName: tap, GuestMAC: mac}) || !strings.HasPrefix(networkBoot, base+" hal_l7_net_if=eth0 ") {
		t.Fatal("renderer changed descriptor values or caller base")
	}
	line, err := minimalcontrol.RenderBootCommandLine(networkBoot, identity, key, fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []int{0, 1} {
		// padding= adds nine bytes including its preceding separator.
		padding := minimalcontrol.MaximumBootCommandLineBytes - 1 - len(line) - len(" padding=") + extra
		paddedBase := base + " padding=" + strings.Repeat("x", padding)
		_, paddedNetwork, err := renderMinimalL7Config(paddedBase, expected)
		if err != nil {
			t.Fatal(err)
		}
		combined, err := minimalcontrol.RenderBootCommandLine(paddedNetwork, identity, key, fields)
		if extra != 0 {
			if !errors.Is(err, minimalcontrol.ErrInvalid) || combined != "" {
				t.Fatalf("combined renderer accepted 4096 bytes before proc newline: %v", err)
			}
			continue
		}
		if err != nil || len(combined) != 4095 {
			t.Fatalf("combined boundary length=%d err=%v", len(combined), err)
		}
		if _, present, err := minimalcontrol.ParseBootCommandLine(combined + "\n"); err != nil || !present {
			t.Fatalf("minimal parser rejected exact whole-line boundary: %v", err)
		}
		if _, present, err := guestnetwork.ParseBootCommandLine(combined + "\n"); err != nil || !present {
			t.Fatalf("L7 parser rejected exact whole-line boundary: %v", err)
		}
		request := validStrictJailerCoordinatorRequest(t)
		request.minimalL7 = expected
		candidate := minimalL7ReplaceBoot(t, minimalL7ConfigTestJSON(t, expected, true), combined)
		replaceCoordinatorConfig(t, &request, candidate)
		if err := validateStrictJailerCoordinatorConfig(request); err != nil {
			t.Fatalf("coordinator rejected final combined boot line: %v", err)
		}
		minimalL7AssertInvalidBeforeHost(t, expected, minimalL7ReplaceBoot(t, candidate, combined+"x"))
	}
	for _, base := range []string{strings.Repeat("x", 4096), "console=ttyS0\n", "console=ttyS0\x00"} {
		if _, _, err := renderMinimalL7Config(base, expected); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
			t.Fatalf("invalid base accepted: %v", err)
		}
	}
	for _, unrelated := range []string{"", "other=hal_l7_net_if", "hal_l7extra=value", "console=ttyS0\tquiet"} {
		if _, _, err := renderMinimalL7Config(unrelated, expected); err != nil {
			t.Fatalf("renderer misclassified unrelated base token: %v", err)
		}
	}
	if *expected != beforeExpectation || identity != beforeIdentity || !bytes.Equal(key, beforeKey) || !maps.Equal(fields, beforeFields) {
		t.Fatal("mapping or final renderer changed caller inputs")
	}
	fields["workerId"], key[0], expected.runtimeGeneration = "changed", key[0]^1, "changed"
	if _, present, err := minimalcontrol.ParseBootCommandLine(line); err != nil || !present || nic.GuestMAC != mac {
		t.Fatalf("caller mutation changed returned values: %v", err)
	}
}

func minimalL7AssertInvalidBeforeHost(t *testing.T, expected *minimalL7ConfigExpectation, config string) {
	t.Helper()
	request := validStrictJailerCoordinatorRequest(t)
	request.minimalL7 = expected
	replaceCoordinatorConfig(t, &request, config)
	// No dependency can run: validation must reject before even checking the
	// missing downstream authority. Otherwise this returns a different error.
	coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		prepareCgroup: func(context.Context, strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
			panic("invalid selected config reached cgroup preparation")
		},
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			panic("invalid selected config reached host inspection")
		},
	})
	_, err := coordinator.start(context.Background(), request)
	if !errors.Is(err, errStrictJailerCoordinatorInvalid) || err.Error() != "strict Jailer coordinator request is invalid: config" {
		t.Fatalf("invalid selected config did not stop at validation: %v", err)
	}
}

func minimalL7ReplaceJSONField(t *testing.T, config, key, raw string) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &fields); err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		delete(fields, key)
	} else {
		fields[key] = json.RawMessage(raw)
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func minimalL7ReplaceBoot(t *testing.T, config, boot string) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"kernel_image_path": "/boot/vmlinux", "boot_args": boot})
	if err != nil {
		t.Fatal(err)
	}
	return minimalL7ReplaceJSONField(t, config, "boot-source", string(encoded))
}

func minimalL7BootstrapTestInputs(expected *minimalL7ConfigExpectation) (session.Identity, ed25519.PublicKey, map[string]string) {
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		GuestBootNonce: [32]byte{1}, ControllerKeyGeneration: "controller-key-1", RuntimeID: "run-1",
		RuntimeGeneration: expected.runtimeGeneration, BootGeneration: "boot-1", ImageGeneration: "image-1", ImageSHA256: [32]byte{2}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fields := map[string]string{
		"sandboxId": "sandbox-minimal-config", "executionId": "execution-minimal-config", "workerId": "worker-minimal-config", "hostId": "host-1",
		"runtimeDriver": "microvm", "runtimeId": identity.RuntimeID, "runtimeGeneration": identity.RuntimeGeneration,
		"bootGeneration": identity.BootGeneration, "imageGeneration": identity.ImageGeneration,
		"workerJobId": "job-1", "submissionId": "submission-1", "planId": "plan-1", "jobGeneration": "job-generation-1",
		"admissionGrantId": "admission-1", "admissionRevision": "1", "principalId": "principal-1",
		"templatePolicyId": "template-policy-1", "workspacePolicyId": "workspace-policy-1", "networkPlanId": "plan-minimal-config",
		"policySnapshotId": "policy-minimal-config", "proxySessionId": "proxy-session-minimal-config", "proxyGenerationId": "proxy-generation-minimal-config",
		"topologyGenerationId": expected.topologyGeneration, "ruleGenerationId": "rule-generation-minimal-config",
		"imageDigest": "sha256-" + hex.EncodeToString(identity.ImageSHA256[:]),
	}
	return identity, key, fields
}
