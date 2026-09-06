package minimalcontrol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func prelaunchFixture() (session.Identity, ed25519.PublicKey, map[string]string) {
	identity := testIdentity()
	identity.FirecrackerProcessGeneration, identity.VsockGeneration = "", ""
	fields := testBindingFields()
	delete(fields, "processGeneration")
	delete(fields, "vsockGeneration")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	return identity, key.Public().(ed25519.PublicKey), fields
}

func testBootLine(t *testing.T) string {
	t.Helper()
	id, key, fields := prelaunchFixture()
	line, err := RenderBootCommandLine("console=ttyS0 hal_l7_net_if=eth0", id, key, fields)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func testBoot(t *testing.T) BootConfig {
	t.Helper()
	boot, present, err := ParseBootCommandLine(testBootLine(t) + "\n")
	if err != nil || !present {
		t.Fatalf("boot: present=%v error=%v", present, err)
	}
	return boot
}

func testBootstrapPrelude(t *testing.T) []byte {
	t.Helper()
	binding, err := NewBinding(testIdentity(), testBindingFields())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := binding.BootstrapPrelude()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestBootstrapPrelaunchGoldenAndImmutableInputs(t *testing.T) {
	identity, key, fields := prelaunchFixture()
	beforeIdentity, beforeKey, beforeFields := identity, bytes.Clone(key), maps.Clone(fields)
	line, err := RenderBootCommandLine("console=ttyS0", identity, key, fields)
	if err != nil {
		t.Fatal(err)
	}
	// Independently calculated with Python hashlib + struct.pack('>H'), from
	// these explicit fixture values: 25 fields, 853 bytes including NUL domain
	// and count. No session ID or late generation is part of this vector.
	const golden = "380806f309fa7e04e6061d84f2e864ebb332706dcb7becba035b65d3e875cca8"
	if !strings.HasSuffix(line, "hal_minimal_prelaunch_binding_sha256="+golden) {
		t.Fatalf("prelaunch digest differs from independent golden: %s", line)
	}
	if identity != beforeIdentity || !bytes.Equal(key, beforeKey) || !maps.Equal(fields, beforeFields) {
		t.Fatal("renderer mutated caller inputs")
	}
	boot, _, err := ParseBootCommandLine(line)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1
	fields["workerId"] = "changed"
	identity.RuntimeID = "changed"
	completed, binding, err := boot.complete(testBootstrapPrelude(t))
	if err != nil || completed != testIdentity() || !maps.Equal(binding.fields, testBindingFields()) {
		t.Fatalf("caller mutation changed pinned completion: %v", err)
	}
	if got := hex.EncodeToString(boot.prelaunchDigest[:]); got != golden {
		t.Fatalf("parser digest = %s", got)
	}
	for _, opaque := range []any{boot, binding} {
		encoded, err := json.Marshal(opaque)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("public descriptor exposed authority fields")
		}
	}
	var forged BootConfig
	if err := json.Unmarshal([]byte(`{"valid":true,"identity":{},"controllerKey":"public"}`), &forged); err != nil {
		t.Fatal(err)
	}
	if _, _, err := forged.complete(testBootstrapPrelude(t)); !errors.Is(err, ErrInvalid) {
		t.Fatal("JSON minted boot pins")
	}
}

func TestBootstrapWholeCommandLineIncludesProcNewline(t *testing.T) {
	identity, key, fields := prelaunchFixture()
	identity.ControllerKeyGeneration = strings.Repeat("k", 64)
	identity.RuntimeID = strings.Repeat("r", 64)
	identity.RuntimeGeneration = strings.Repeat("g", 64)
	identity.BootGeneration = strings.Repeat("b", 64)
	identity.ImageGeneration = strings.Repeat("i", 64)
	fields["runtimeId"], fields["runtimeGeneration"] = identity.RuntimeID, identity.RuntimeGeneration
	fields["bootGeneration"], fields["imageGeneration"] = identity.BootGeneration, identity.ImageGeneration
	suffix, err := RenderBootCommandLine("", identity, key, fields)
	if err != nil || len(suffix) != 846 {
		t.Fatalf("maximum suffix bytes=%d, want 846; error=%v", len(suffix), err)
	}
	base := strings.Repeat("x", 4095-len(suffix)-1)
	line, err := RenderBootCommandLine(base, identity, key, fields)
	if err != nil || len(line) != 4095 {
		t.Fatalf("combined renderer boundary: len=%d error=%v", len(line), err)
	}
	for _, usable := range []string{line, line + "\n", line + " "} {
		if _, present, err := ParseBootCommandLine(usable); err != nil || !present {
			t.Fatalf("usable whole input len=%d: present=%v error=%v", len(usable), present, err)
		}
	}
	if rendered, err := RenderBootCommandLine(base+"x", identity, key, fields); !errors.Is(err, ErrInvalid) || rendered != "" {
		t.Fatal("renderer did not reserve proc newline")
	}
	for _, bad := range []string{line + " \n", line + "\n\n", strings.Replace(line, " hal_minimal_", "\nhal_minimal_", 1)} {
		if _, _, err := ParseBootCommandLine(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overflow or nonterminal newline accepted: %v", err)
		}
	}
	for _, base := range []string{"console=ttyS0\n", "hal_minimal", "HAL_MINIMAL_PROFILE=x", testBootLine(t)} {
		if _, err := RenderBootCommandLine(base, identity, key, fields); !errors.Is(err, ErrInvalid) {
			t.Fatal("renderer accepted conflicting or proc-form base")
		}
	}
}

func TestBootstrapBootNamespaceAndCanonicalPins(t *testing.T) {
	valid := testBootLine(t)
	for _, token := range strings.Fields(valid) {
		key, _, _ := strings.Cut(token, "=")
		if !strings.HasPrefix(key, "hal_minimal_") {
			continue
		}
		for name, invalid := range map[string]string{
			"missing":      strings.Replace(valid, token, "", 1),
			"duplicate":    valid + " " + token,
			"bare":         strings.Replace(valid, token, key, 1),
			"empty":        strings.Replace(valid, token, key+"=", 1),
			"uppercase":    strings.Replace(valid, key, strings.ToUpper(key), 1),
			"quoted-key":   strings.Replace(valid, key, `"`+key+`"`, 1),
			"quoted-token": strings.Replace(valid, token, `'`+token+`'`, 1),
		} {
			t.Run(key+"/"+name, func(t *testing.T) {
				if _, present, err := ParseBootCommandLine(invalid); !errors.Is(err, ErrInvalid) || !present {
					t.Fatalf("explicit namespace fell back: present=%v error=%v", present, err)
				}
			})
		}
	}
	for _, bad := range []string{"hal_minimal", "hal_minimal=anything", "hal_minimal_=x", `"HAL_MINIMAL"`, "hal_minimal_unknown=x"} {
		if _, _, err := ParseBootCommandLine(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("reserved namespace %q accepted", bad)
		}
	}
	for _, absent := range []string{"", "console=ttyS0\n", "hal_l7_net_if=eth0", "hal_minimality=x", "other=hal_minimal_profile"} {
		if _, present, err := ParseBootCommandLine(absent); err != nil || present {
			t.Fatalf("legacy absence changed: present=%v error=%v", present, err)
		}
	}
	for _, bad := range []struct{ key, value string }{
		{"profile", "guest-agent-v1"}, {"controller_key", strings.Repeat("A", 43)},
		{"controller_key", strings.Repeat("B", 43)}, {"controller_key", strings.Repeat("A", 43) + "="},
		{"boot_nonce", strings.Repeat("A", 43)}, {"boot_nonce", "short"},
		{"image_sha256", strings.Repeat("0", 64)}, {"image_sha256", strings.Repeat("AB", 32)},
		{"prelaunch_binding_sha256", strings.Repeat("0", 64)}, {"prelaunch_binding_sha256", "abcd"},
		{"controller_key_generation", "-key"}, {"runtime_id", "../runtime"}, {"runtime_generation", "has:colon"},
		{"boot_generation", strings.Repeat("a", 65)}, {"image_generation", "unicode-é"},
	} {
		parts := strings.Fields(valid)
		for index, token := range parts {
			if strings.HasPrefix(token, "hal_minimal_"+bad.key+"=") {
				parts[index] = "hal_minimal_" + bad.key + "=" + bad.value
			}
		}
		if _, _, err := ParseBootCommandLine(strings.Join(parts, " ")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("noncanonical %s accepted", bad.key)
		}
	}
}

func TestBootstrapEveryPrelaunchFieldAndIdentityIsValidated(t *testing.T) {
	identity, key, fields := prelaunchFixture()
	boot := testBoot(t)
	for name := range fields {
		t.Run(name, func(t *testing.T) {
			missing := maps.Clone(fields)
			delete(missing, name)
			if _, err := RenderBootCommandLine("", identity, key, missing); !errors.Is(err, ErrInvalid) {
				t.Fatal("missing renderer field accepted")
			}
			for _, value := range []string{"changed", "", "../unsafe", strings.Repeat("x", 65)} {
				changed := testBindingFields()
				changed[name] = value
				payload, _ := json.Marshal(bootstrapPrelude{Binding: changed, Operation: "bootstrap", ProtocolVersion: ProtocolVersion})
				if _, _, err := boot.complete(payload); !errors.Is(err, ErrInvalid) {
					t.Fatal("changed provisional field accepted")
				}
			}
		})
	}
	for _, mutate := range []func(*session.Identity){
		func(id *session.Identity) { id.Channel = session.ChannelSSHRelay },
		func(id *session.Identity) { id.GuestCID++ }, func(id *session.Identity) { id.GuestPort++ },
		func(id *session.Identity) { id.GuestBootNonce = [32]byte{} }, func(id *session.Identity) { id.ImageSHA256 = [32]byte{} },
		func(id *session.Identity) { id.ControllerKeyGeneration = "" }, func(id *session.Identity) { id.RuntimeID = "other" },
		func(id *session.Identity) { id.RuntimeGeneration = "other" }, func(id *session.Identity) { id.BootGeneration = "other" },
		func(id *session.Identity) { id.ImageGeneration = "other" },
		func(id *session.Identity) { id.FirecrackerProcessGeneration = "must-stay-empty" }, func(id *session.Identity) { id.VsockGeneration = "must-stay-empty" },
		func(id *session.Identity) { id.JobGeneration = "must-stay-empty" }, func(id *session.Identity) { id.ActivationGeneration = "must-stay-empty" },
		func(id *session.Identity) { id.RelayGeneration = "must-stay-empty" },
	} {
		changed := identity
		mutate(&changed)
		if _, err := RenderBootCommandLine("", changed, key, fields); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid prelaunch identity accepted")
		}
	}
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if _, err := RenderBootCommandLine("", identity, key, fields); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid public key accepted")
		}
	}
	for _, name := range []string{"processGeneration", "vsockGeneration", "unknown"} {
		extra := maps.Clone(fields)
		extra[name] = ""
		if _, err := RenderBootCommandLine("", identity, key, extra); !errors.Is(err, ErrInvalid) {
			t.Fatal("extra prelaunch field accepted")
		}
	}
}

func TestBootstrapPreludeCanonicalNegatives(t *testing.T) {
	boot := testBoot(t)
	payload := testBootstrapPrelude(t)
	replace := func(old, new string) []byte { return bytes.Replace(payload, []byte(old), []byte(new), 1) }
	for name, bad := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "truncated": payload[:len(payload)-1],
		"trailing": append(bytes.Clone(payload), []byte("{}")...), "whitespace": append([]byte(" "), payload...),
		"oversized": bytes.Repeat([]byte("x"), MaxMessageBytes+1), "depth": []byte(`{"a":{"b":{"c":{}}}}`),
		"unknown":          replace(`"operation":`, `"unknown":true,"operation":`),
		"root-duplicate":   replace(`"operation":"bootstrap"`, `"operation":"bootstrap","operation":"bootstrap"`),
		"case-alias":       replace(`"binding":`, `"Binding":`),
		"escaped-key":      replace(`"binding":`, `"b\u0069nding":`),
		"escaped-value":    replace(`"microvm"`, `"micro\u0076m"`),
		"nested-duplicate": replace(`"hostId":"host-1"`, `"hostId":"host-1","hostId":"host-1"`),
		"nested-null":      replace(`"hostId":"host-1"`, `"hostId":null`),
		"wrong-type":       replace(`"hostId":"host-1"`, `"hostId":1`),
		"missing-late":     replace(`"processGeneration":"process-generation-1",`, ``),
		"wrong-profile":    replace(ProtocolVersion, "guest-agent-v1"),
		"wrong-operation":  replace(`"bootstrap"`, `"readiness"`),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(bad, payload) {
				t.Fatal("mutation missed fixture")
			}
			if _, _, err := boot.complete(bad); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed provisional input accepted: %v", err)
			}
		})
	}
	if _, err := (Binding{}).BootstrapPrelude(); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty binding emitted provisional input")
	}
}
