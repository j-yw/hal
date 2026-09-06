package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func jailerRecoveryTestGateConfig(t *testing.T) jailerRecoveryGateConfig {
	t.Helper()
	request := validStrictJailerLaunchRequest()
	plan, err := planStrictJailerLaunch(request)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := plan.validatedAuthority()
	if err != nil {
		t.Fatal(err)
	}
	return jailerRecoveryGateConfig{
		Version: jailerRecoveryGateRole, ParentPID: 123, ParentStartTime: 456,
		Jailer:      jailerRecoveryMountedExecutable{Path: request.JailerPath, Device: 1, Inode: 2, Size: 10, SHA256: strings.Repeat("a", 64)},
		Firecracker: jailerRecoveryMountedExecutable{Path: request.CanonicalFirecrackerPath, Device: 1, Inode: 3, Size: 20, SHA256: strings.Repeat("b", 64)},
		Args:        authority.process.Args,
	}
}

func TestJailerRecoveryGateConfigCanonicalAndBounded(t *testing.T) {
	config := jailerRecoveryTestGateConfig(t)
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeJailerRecoveryGateConfig(payload)
	if err != nil || !reflect.DeepEqual(decoded, config) {
		t.Errorf("valid selected gate config rejected: %v", err)
	}
	for name, data := range map[string][]byte{
		"null": []byte("null"), "oversized": bytes.Repeat([]byte("x"), jailerRecoveryGateConfigLimit+1),
		"unknown":     bytes.Replace(payload, []byte(`"parentPid":`), []byte(`"unknown":1,"parentPid":`), 1),
		"duplicate":   bytes.Replace(payload, []byte(`"parentPid":`), []byte(`"parentPid":1,"parentPid":`), 1),
		"case alias":  bytes.Replace(payload, []byte(`"parentPid":`), []byte(`"ParentPid":`), 1),
		"trailing":    append(bytes.Clone(payload), '\n'),
		"null parent": bytes.Replace(payload, []byte(`"parentPid":123`), []byte(`"parentPid":null`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJailerRecoveryGateConfig(data); err == nil {
				t.Fatal("unsafe gate config accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*jailerRecoveryGateConfig){
		"version":    func(c *jailerRecoveryGateConfig) { c.Version = "child-gate" },
		"parent":     func(c *jailerRecoveryGateConfig) { c.ParentPID = 1 },
		"start":      func(c *jailerRecoveryGateConfig) { c.ParentStartTime = 0 },
		"alias":      func(c *jailerRecoveryGateConfig) { c.Firecracker.Inode = c.Jailer.Inode },
		"size":       func(c *jailerRecoveryGateConfig) { c.Jailer.Size = maxStrictJailerExecutableBytes + 1 },
		"hash":       func(c *jailerRecoveryGateConfig) { c.Jailer.SHA256 = strings.Repeat("A", 64) },
		"path":       func(c *jailerRecoveryGateConfig) { c.Jailer.Path = "jailer" },
		"wrong exec": func(c *jailerRecoveryGateConfig) { c.Args[3] = "/other/firecracker" },
		"extra args": func(c *jailerRecoveryGateConfig) { c.Args = append(c.Args, "--daemonize") },
	} {
		t.Run(name, func(t *testing.T) {
			c := config
			c.Args = slices.Clone(config.Args)
			mutate(&c)
			data, _ := json.Marshal(c)
			if _, err := decodeJailerRecoveryGateConfig(data); err == nil {
				t.Fatal("unsafe selected gate facts accepted")
			}
		})
	}
}

func TestJailerRecoveryGateVerifiesBothSidesOfReleaseAndClosesBeforeExec(t *testing.T) {
	want := []string{"parent", "jailer", "firecracker", "armed", "release", "parent", "jailer", "firecracker", "close", "exec"}
	for failAt := -1; failAt < len(want); failAt++ {
		t.Run(fmt.Sprintf("failure_at_%d", failAt), func(t *testing.T) {
			var events []string
			step := func(name string) error {
				events = append(events, name)
				if len(events)-1 == failAt {
					return errors.New("fixture gate step failure")
				}
				return nil
			}
			config := jailerRecoveryTestGateConfig(t)
			err := runJailerRecoveryGate(context.Background(), config, jailerRecoveryGateOps{
				verifyParent: func() error { return step("parent") },
				verifyMounted: func(executable jailerRecoveryMountedExecutable) error {
					if executable == config.Jailer {
						return step("jailer")
					}
					if executable == config.Firecracker {
						return step("firecracker")
					}
					t.Fatal("unrelated executable inspected")
					return nil
				},
				sendArmed:    func() error { return step("armed") },
				awaitRelease: func() error { return step("release") },
				closeFiles:   func() error { return step("close") },
				exec: func(path string, args []string) error {
					if path != config.Jailer.Path || !slices.Equal(args, append([]string{path}, config.Args...)) {
						t.Fatal("exec argument drift")
					}
					return step("exec")
				},
			})
			end := len(want)
			if failAt >= 0 {
				end = failAt + 1
			}
			if (err != nil) != (failAt >= 0) || !slices.Equal(events, want[:end]) {
				t.Fatalf("gate error=%v events=%v want=%v", err, events, want[:end])
			}
		})
	}
}

func TestJailerRecoveryGateCancellationNeverExecutes(t *testing.T) {
	for _, phase := range []string{"before", "armed", "release", "close"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []string
			step := func(name string) error {
				events = append(events, name)
				if phase == name {
					cancel()
				}
				return nil
			}
			if phase == "before" {
				cancel()
			}
			err := runJailerRecoveryGate(ctx, jailerRecoveryTestGateConfig(t), jailerRecoveryGateOps{
				verifyParent:  func() error { return step("parent") },
				verifyMounted: func(jailerRecoveryMountedExecutable) error { return step("mounted") },
				sendArmed:     func() error { return step("armed") },
				awaitRelease:  func() error { return step("release") },
				closeFiles:    func() error { return step("close") },
				exec:          func(string, []string) error { return step("exec") },
			})
			if err == nil || slices.Contains(events, "exec") || phase == "before" && len(events) != 0 || phase != "before" && !slices.Contains(events, phase) {
				t.Fatalf("cancel phase=%s error=%v events=%v", phase, err, events)
			}
		})
	}
}
