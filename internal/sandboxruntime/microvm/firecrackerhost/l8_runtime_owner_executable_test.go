package firecrackerhost

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestL8RuntimeOwnerLinuxLaunchSourceRetainsPdeathsigCreatingThread(t *testing.T) {
	source, err := os.ReadFile("l8_runtime_owner_executable_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	markers := []string{"runtime.LockOSThread", "SysProcAttr", "Pdeathsig:", "syscall.SIGKILL", ".Start()", ".Wait()", "runtime.UnlockOSThread"}
	previous := -1
	for _, marker := range markers {
		index := strings.Index(text, marker)
		if index < 0 {
			t.Fatalf("linux launch omits %q", marker)
		}
		if index <= previous {
			t.Fatalf("linux launch order for %q", marker)
		}
		previous = index
	}
}

func TestL8RuntimeOwnerLinuxExecutableWiresProductionModes(t *testing.T) {
	source, err := os.ReadFile("l8_runtime_owner_executable_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, marker := range []string{
		"RunSupervisor: runL8RuntimeOwnerSupervisorLinux",
		"RunChildGate:  runL8RuntimeOwnerChildGateLinux",
	} {
		if strings.Count(text, marker) != 1 {
			t.Fatalf("linux executable wiring count for %q = %d", marker, strings.Count(text, marker))
		}
	}
	for _, forbidden := range []string{
		"RunSupervisor: func([6]int) error",
		"RunChildGate: func([6]int) error",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("linux executable retains failure callback %q", forbidden)
		}
	}
}

func TestL8RuntimeOwnerExecutableModesAndDescriptorABI(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		argv    []string
		wantRun string
		wantFDs []uintptr
	}{
		{name: "supervise", argv: []string{"supervise"}, wantRun: "supervise", wantFDs: []uintptr{3, 4, 5, 6, 7, 8}},
		{name: "child gate", argv: []string{"child-gate"}, wantRun: "child-gate", wantFDs: []uintptr{3, 4, 5, 6, 7, 8}},
		{name: "missing mode"},
		{name: "extra argument", argv: []string{"supervise", "extra"}},
		{name: "unknown mode", argv: []string{"unknown"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var opened []uintptr
			var closed []int
			var run string
			ops := l8RuntimeOwnerExecutableOps{
				OpenFD: func(fd uintptr, role string) (int, error) {
					if strings.TrimSpace(role) == "" {
						t.Fatal("empty descriptor role")
					}
					opened = append(opened, fd)
					return int(fd), nil
				},
				CloseFD: func(fd int) error { closed = append(closed, fd); return nil },
				RunSupervisor: func(fds [6]int) error {
					run = "supervise"
					if fds != [6]int{3, 4, 5, 6, 7, 8} {
						t.Fatalf("supervisor fds = %v", fds)
					}
					return nil
				},
				RunChildGate: func(fds [6]int) error {
					run = "child-gate"
					if fds != [6]int{3, 4, 5, 6, 7, 8} {
						t.Fatalf("child fds = %v", fds)
					}
					return nil
				},
			}
			got := runPrivateL8RuntimeOwnerExecutableWithOps(scenario.argv, ops)
			if scenario.wantRun == "" {
				if got != 127 || len(opened) != 0 || run != "" {
					t.Fatalf("invalid mode = exit %d opened %v run %q", got, opened, run)
				}
				return
			}
			if got != 0 || run != scenario.wantRun || !reflect.DeepEqual(opened, scenario.wantFDs) || !reflect.DeepEqual(closed, []int{8, 7, 6, 5, 4, 3}) {
				t.Fatalf("mode result = exit %d opened %v closed %v run %q", got, opened, closed, run)
			}
		})
	}

	for failedAt := uintptr(3); failedAt <= 8; failedAt++ {
		t.Run("open failure", func(t *testing.T) {
			var closed []int
			got := runPrivateL8RuntimeOwnerExecutableWithOps([]string{"supervise"}, l8RuntimeOwnerExecutableOps{
				OpenFD: func(fd uintptr, _ string) (int, error) {
					if fd == failedAt {
						return -1, errors.New("private path")
					}
					return int(fd), nil
				},
				CloseFD:       func(fd int) error { closed = append(closed, fd); return nil },
				RunSupervisor: func([6]int) error { t.Fatal("ran after open failure"); return nil },
			})
			if got != 127 || len(closed) != int(failedAt-3) {
				t.Fatalf("failure cleanup = exit %d closed %v", got, closed)
			}
		})
	}
}

func TestL8RuntimeOwnerChildLaunchRetainsCreatingThreadThroughWait(t *testing.T) {
	var events []string
	ops := l8RuntimeOwnerChildLaunchOps{
		LockOSThread:   func() { events = append(events, "lock") },
		UnlockOSThread: func() { events = append(events, "unlock") },
		Start:          func() error { events = append(events, "start"); return nil },
		Wait:           func() error { events = append(events, "wait"); return nil },
	}
	if err := launchL8RuntimeOwnerChildOnRetainedThread(ops); err != nil || !reflect.DeepEqual(events, []string{"lock", "start", "wait", "unlock"}) {
		t.Fatalf("launch = %v, %v", events, err)
	}
	events = nil
	ops.Start = func() error { events = append(events, "start"); return errors.New("private start") }
	if err := launchL8RuntimeOwnerChildOnRetainedThread(ops); !errors.Is(err, errL8RuntimeOwnerInvalid) || !reflect.DeepEqual(events, []string{"lock", "start", "unlock"}) {
		t.Fatalf("start failure = %v, %v", events, err)
	}
}

func TestL8RuntimeOwnerChildGateRemapsCollisionFreeAndExecsNamespaceWrapper(t *testing.T) {
	config := l8RuntimeOwnerTestSupervisorConfig()
	var events []string
	next := 9
	ops := l8RuntimeOwnerFDRemapOps{
		DuplicateAtLeast: func(fd, minimum int) (int, error) {
			events = append(events, "dup-temp")
			if minimum != 9 {
				t.Fatalf("minimum = %d", minimum)
			}
			value := next
			next++
			return value, nil
		},
		Dup3: func(from, to, flags int) error {
			events = append(events, "dup3")
			if from < 9 || to < 3 || to > 6 || flags != 0 {
				t.Fatalf("dup3 = %d %d %d", from, to, flags)
			}
			return nil
		},
		Close: func(int) error { events = append(events, "close"); return nil },
		CloseFrom: func(first int) error {
			events = append(events, "closefrom")
			if first != 7 {
				t.Fatalf("closefrom = %d", first)
			}
			return nil
		},
		Exec: func(path string, argv, env []string) error {
			events = append(events, "exec")
			want := []string{config.NamespaceWrapperExecutable, "--preserve-credentials", "--keep-caps", "--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--", config.FirecrackerExecutable, "--api-sock", "/private/runtime/firecracker.sock"}
			if path != config.NamespaceWrapperExecutable || !reflect.DeepEqual(argv, want) || len(env) != 0 {
				t.Fatalf("exec = %q %#v %#v", path, argv, env)
			}
			return nil
		},
	}
	if err := remapAndExecL8RuntimeOwnerChild(config, [4]int{5, 6, 7, 8}, ops); err != nil {
		t.Fatal(err)
	}
	if countString(events, "dup-temp") != 4 || countString(events, "dup3") != 4 || events[len(events)-2] != "closefrom" || events[len(events)-1] != "exec" {
		t.Fatalf("remap events = %v", events)
	}
}

func TestL8RuntimeOwnerChildGateClosesEveryTemporaryOnFailure(t *testing.T) {
	config := l8RuntimeOwnerTestSupervisorConfig()
	for _, scenario := range []struct {
		name        string
		failDupAt   int
		failMapAt   int
		failCloseAt int
	}{
		{name: "duplicate", failDupAt: 2},
		{name: "map", failMapAt: 2},
		{name: "close", failCloseAt: 2},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			next := 9
			duplicateCalls := 0
			mapCalls := 0
			closeCalls := make(map[int]int)
			err := remapAndExecL8RuntimeOwnerChild(config, [4]int{5, 6, 7, 8}, l8RuntimeOwnerFDRemapOps{
				DuplicateAtLeast: func(int, int) (int, error) {
					duplicateCalls++
					if duplicateCalls == scenario.failDupAt {
						return -1, errors.New("private duplicate")
					}
					fd := next
					next++
					return fd, nil
				},
				Dup3: func(int, int, int) error {
					mapCalls++
					if mapCalls == scenario.failMapAt {
						return errors.New("private map")
					}
					return nil
				},
				Close: func(fd int) error {
					closeCalls[fd]++
					if fd == 10 && scenario.failCloseAt != 0 {
						return errors.New("private close")
					}
					return nil
				},
				CloseFrom: func(int) error { return nil },
				Exec:      func(string, []string, []string) error { return nil },
			})
			if !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("failure = %v", err)
			}
			for fd := 9; fd < next; fd++ {
				if closeCalls[fd] != 1 {
					t.Fatalf("temporary %d close count = %d", fd, closeCalls[fd])
				}
			}
		})
	}
}

func TestL8RuntimeOwnerChildGateArmsBeforeAcknowledgementAndRelease(t *testing.T) {
	for _, scenario := range []struct{ name, fail string }{
		{name: "success"}, {name: "arm", fail: "arm"}, {name: "armed ack", fail: "armed"}, {name: "gate eof", fail: "release"}, {name: "exec", fail: "exec"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var events []string
			step := func(name string) error {
				events = append(events, name)
				if scenario.fail == name {
					return errors.New("private child gate")
				}
				return nil
			}
			err := runL8RuntimeOwnerChildGate(l8RuntimeOwnerChildGateOps{
				ArmPdeathsigAndVerifyParent: func() error { return step("arm") },
				SendArmed:                   func() error { return step("armed") },
				AwaitRelease:                func() error { return step("release") },
				RemapAndExec:                func() error { return step("exec") },
			})
			want := []string{"arm", "armed", "release", "exec"}
			if scenario.fail != "" {
				for index, value := range want {
					if value == scenario.fail {
						want = want[:index+1]
						break
					}
				}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("gate events = %v want %v", events, want)
			}
			if scenario.fail == "" && err != nil {
				t.Fatal(err)
			}
			if scenario.fail != "" && (!errors.Is(err, errL8RuntimeOwnerInvalid) || err.Error() != errL8RuntimeOwnerInvalid.Error()) {
				t.Fatalf("failure = %v", err)
			}
		})
	}
}

func TestL8RuntimeOwnerStableKeyFDIsExactAndReplacementSafe(t *testing.T) {
	wantIdentity := l8RuntimeOwnerKeyIdentity{Regular: true, Mode: 0600, UID: 1000, Links: 1, Size: 32, Device: 7, Inode: 9}
	for _, scenario := range []struct {
		name              string
		first, second     l8RuntimeOwnerKeyIdentity
		read              int
		readErr, closeErr error
		ok                bool
	}{
		{name: "valid", first: wantIdentity, second: wantIdentity, read: 32, ok: true},
		{name: "short", first: wantIdentity, second: wantIdentity, read: 31},
		{name: "wrong mode", first: func() l8RuntimeOwnerKeyIdentity { v := wantIdentity; v.Mode = 0640; return v }(), second: wantIdentity, read: 32},
		{name: "wrong uid", first: func() l8RuntimeOwnerKeyIdentity { v := wantIdentity; v.UID = 1001; return v }(), second: wantIdentity, read: 32},
		{name: "hardlink", first: func() l8RuntimeOwnerKeyIdentity { v := wantIdentity; v.Links = 2; return v }(), second: wantIdentity, read: 32},
		{name: "replacement", first: wantIdentity, second: func() l8RuntimeOwnerKeyIdentity { v := wantIdentity; v.Inode++; return v }(), read: 32},
		{name: "read error", first: wantIdentity, second: wantIdentity, readErr: errors.New("private key path")},
		{name: "close uncertainty", first: wantIdentity, second: wantIdentity, read: 32, closeErr: errors.New("private close")},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			stats := 0
			closes := 0
			key, err := loadL8RuntimeOwnerStableKeyFD(8, 1000, l8RuntimeOwnerKeyFDOps{
				Stat: func(fd int) (l8RuntimeOwnerKeyIdentity, error) {
					if fd != 8 {
						t.Fatalf("fd = %d", fd)
					}
					stats++
					if stats == 1 {
						return scenario.first, nil
					}
					return scenario.second, nil
				},
				Pread: func(fd int, destination []byte, offset int64) (int, error) {
					if fd != 8 || len(destination) != 32 || offset != 0 {
						t.Fatalf("pread = %d %d %d", fd, len(destination), offset)
					}
					for i := range destination {
						destination[i] = byte(i)
					}
					return scenario.read, scenario.readErr
				},
				Close: func(fd int) error { closes++; return scenario.closeErr },
			})
			if closes != 1 {
				t.Fatalf("close count = %d", closes)
			}
			if scenario.ok {
				if err != nil || len(key) != 32 || stats != 2 {
					t.Fatalf("key = %d stats %d err %v", len(key), stats, err)
				}
			} else if len(key) != 0 || !errors.Is(err, errL8RuntimeOwnerInvalid) || err.Error() != errL8RuntimeOwnerInvalid.Error() {
				t.Fatalf("invalid key = %x, %v", key, err)
			}
		})
	}
}

func TestL8RuntimeOwnerSupervisorConfigIsStrictBoundedAndComplete(t *testing.T) {
	config := l8RuntimeOwnerTestSupervisorConfig()
	payload, err := encodeL8RuntimeOwnerSupervisorConfig(config)
	if err != nil || len(payload) == 0 || len(payload) > l8RuntimeOwnerSupervisorConfigLimit {
		t.Fatalf("encode config = %d bytes, %v", len(payload), err)
	}
	decoded, err := decodeL8RuntimeOwnerSupervisorConfig(payload)
	if err != nil || !l8RuntimeOwnerSupervisorConfigsEqual(decoded, config) {
		t.Fatalf("decode config = %#v, %v", decoded, err)
	}
	for name, candidate := range map[string][]byte{
		"null":           []byte("null\n"),
		"unknown":        bytes.Replace(payload, []byte("\"daemonUid\":"), []byte("\"unknown\":1,\"daemonUid\":"), 1),
		"duplicate":      bytes.Replace(payload, []byte("\"daemonUid\":"), []byte("\"daemonUid\":1,\"daemonUid\":"), 1),
		"case duplicate": bytes.Replace(payload, []byte("\"daemonUid\":"), []byte("\"DaemonUid\":1,\"daemonUid\":"), 1),
		"null uid":       bytes.Replace(payload, []byte("\"daemonUid\":1000"), []byte("\"daemonUid\":null"), 1),
		"trailing":       append(append([]byte(nil), payload...), 'x'),
		"oversize":       make([]byte, l8RuntimeOwnerSupervisorConfigLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeL8RuntimeOwnerSupervisorConfig(candidate); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("decode mutation = %v", err)
			}
		})
	}
	mutations := map[string]func(*l8RuntimeOwnerSupervisorConfigV1){
		"version":                func(value *l8RuntimeOwnerSupervisorConfigV1) { value.ContractVersion = "v2" },
		"invalid seed":           func(value *l8RuntimeOwnerSupervisorConfigV1) { value.Seed.RuntimeGeneration = "" },
		"relative wrapper":       func(value *l8RuntimeOwnerSupervisorConfigV1) { value.NamespaceWrapperExecutable = "nsenter" },
		"relative firecracker":   func(value *l8RuntimeOwnerSupervisorConfigV1) { value.FirecrackerExecutable = "firecracker" },
		"wrong descriptor count": func(value *l8RuntimeOwnerSupervisorConfigV1) { value.InheritedDescriptorCount = 3 },
		"asset alias":            func(value *l8RuntimeOwnerSupervisorConfigV1) { value.Rootfs = value.Kernel },
		"asset kind":             func(value *l8RuntimeOwnerSupervisorConfigV1) { value.Kernel.Kind = "rootfs" },
		"asset digest":           func(value *l8RuntimeOwnerSupervisorConfigV1) { value.Kernel.Digest = "private path" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := config
			candidate.FirecrackerArguments = append([]string(nil), config.FirecrackerArguments...)
			mutate(&candidate)
			if _, err := encodeL8RuntimeOwnerSupervisorConfig(candidate); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("encode mutation = %v", err)
			}
		})
	}
}

func l8RuntimeOwnerTestSupervisorConfig() l8RuntimeOwnerSupervisorConfigV1 {
	return l8RuntimeOwnerSupervisorConfigV1{
		ContractVersion:            l8RuntimeOwnerSupervisorConfigVersion,
		Seed:                       l8RuntimeOwnerTestSeed(),
		DaemonUID:                  1000,
		NamespaceWrapperExecutable: "/usr/bin/nsenter",
		FirecrackerExecutable:      "/usr/bin/firecracker",
		FirecrackerArguments:       []string{"--api-sock", "/private/runtime/firecracker.sock"},
		Kernel:                     l8RuntimeOwnerDescriptorIdentityV1{Kind: "kernel", Device: 1, Inode: 2, Digest: string(bytes.Repeat([]byte("a"), 64))},
		Rootfs:                     l8RuntimeOwnerDescriptorIdentityV1{Kind: "rootfs", Device: 1, Inode: 3, Digest: string(bytes.Repeat([]byte("b"), 64))},
		InheritedDescriptorCount:   2,
	}
}

func l8RuntimeOwnerSupervisorConfigsEqual(left, right l8RuntimeOwnerSupervisorConfigV1) bool {
	if left.ContractVersion != right.ContractVersion || left.DaemonUID != right.DaemonUID ||
		left.NamespaceWrapperExecutable != right.NamespaceWrapperExecutable || left.FirecrackerExecutable != right.FirecrackerExecutable ||
		left.Kernel != right.Kernel || left.Rootfs != right.Rootfs || left.InheritedDescriptorCount != right.InheritedDescriptorCount ||
		len(left.FirecrackerArguments) != len(right.FirecrackerArguments) {
		return false
	}
	for index := range left.FirecrackerArguments {
		if left.FirecrackerArguments[index] != right.FirecrackerArguments[index] {
			return false
		}
	}
	return reflect.DeepEqual(left.Seed, right.Seed)
}
