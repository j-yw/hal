package firecrackerhost

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

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
		"null":      []byte("null\n"),
		"unknown":   bytes.Replace(payload, []byte("\"daemonUid\":"), []byte("\"unknown\":1,\"daemonUid\":"), 1),
		"duplicate": bytes.Replace(payload, []byte("\"daemonUid\":"), []byte("\"daemonUid\":1,\"daemonUid\":"), 1),
		"trailing":  append(append([]byte(nil), payload...), 'x'),
		"oversize":  make([]byte, l8RuntimeOwnerSupervisorConfigLimit+1),
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
