//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func jailerRecoveryProducerFixture(t *testing.T) (jailerRecoveryProducerRequest, string, []byte, []byte) {
	t.Helper()
	distribution, root, kernel, rootfs := minimalJailerFixture(t)
	c := jailerRecoveryTestSupervisorConfig(t)
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	executable := []byte("synthetic independently pinned owner; never executed")
	// Ordinary borrowed descriptors replace host authority only at the explicit
	// fake start boundary; no real supervisor, namespace or VM is started.
	return jailerRecoveryProducerRequest{distribution: distribution, job: c.Job, policy: c.Policy, paths: c.Paths, config: []byte(validCoordinatorConfig()), enablePCI: true, ownerExecutable: bytes.NewReader(executable), ownerExecutableSHA256: sha256.Sum256(executable), ownerDirectory: directory, rootKey: directory, namespaces: [2]*os.File{directory, directory}}, root, kernel, rootfs
}

func TestJailerRecoveryProducerMeasuresSealsAndClosesActualInputs(t *testing.T) {
	request, _, kernel, rootfs := jailerRecoveryProducerFixture(t)
	var borrowed []*os.File
	client := &jailerRecoveryClient{}
	got, err := withJailerRecoveryProducerInputs(context.Background(), request, func(_ context.Context, c jailerRecoverySupervisorConfig, executable, configFile *os.File, inputs [5]*os.File, _ [2]*os.File) (*jailerRecoveryClient, error) {
		borrowed = []*os.File{executable, configFile, inputs[1], inputs[2], inputs[4]}
		if validateStrictJailerExecutableSnapshot(executable) != nil {
			t.Fatal("owner snapshot not sealed")
		}
		for i, file := range []*os.File{inputs[1], inputs[2], inputs[4]} {
			want := [][]byte{kernel, rootfs, request.config}[i]
			actual, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(want)+1)))
			if err != nil || !bytes.Equal(actual, want) {
				t.Fatal("wrong snapshot bytes")
			}
			if _, err := file.WriteAt([]byte("!"), 0); err == nil {
				t.Fatal("mutable snapshot")
			}
		}
		payload, err := io.ReadAll(io.NewSectionReader(configFile, 0, l8RuntimeOwnerSupervisorConfigLimit+1))
		decoded, decodeErr := decodeJailerRecoverySupervisorConfig(payload)
		if err != nil || decodeErr != nil || jailerRecoveryConfigDigest(decoded) != jailerRecoveryConfigDigest(c) {
			t.Fatal("config handoff mismatch")
		}
		return client, nil
	})
	if err != nil || got != client {
		t.Fatalf("producer: %v", err)
	}
	for _, file := range borrowed {
		if _, err := file.Stat(); err == nil {
			t.Fatal("producer snapshot descriptor leaked")
		}
	}
	if _, err := request.ownerDirectory.Stat(); err != nil {
		t.Fatal("producer closed borrowed caller directory")
	}
}

func TestJailerRecoveryProducerRejectsUnknownOrCanceledStartResult(t *testing.T) {
	for _, name := range []string{"nil_result", "canceled_result"} {
		t.Run(name, func(t *testing.T) {
			request, _, _, _ := jailerRecoveryProducerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			retained := &jailerRecoveryClient{}
			got, err := withJailerRecoveryProducerInputs(ctx, request, func(context.Context, jailerRecoverySupervisorConfig, *os.File, *os.File, [5]*os.File, [2]*os.File) (*jailerRecoveryClient, error) {
				if name == "nil_result" {
					return nil, nil
				}
				cancel()
				return retained, nil
			})
			if err == nil {
				t.Fatal("unknown/canceled owner start reported success")
			}
			if name == "canceled_result" && got != retained {
				t.Fatal("canceled post-start owner discarded")
			}
		})
	}
}

type jailerRecoveryMutationReader struct {
	source io.Reader
	mutate func()
}

func (r *jailerRecoveryMutationReader) Read(p []byte) (int, error) {
	if r.mutate != nil {
		r.mutate()
		r.mutate = nil
	}
	return r.source.Read(p)
}

func TestJailerRecoveryProducerRevalidatesSourcesBeforeStart(t *testing.T) {
	request, root, _, _ := jailerRecoveryProducerFixture(t)
	request.ownerExecutable = &jailerRecoveryMutationReader{source: request.ownerExecutable, mutate: func() {
		if err := os.WriteFile(filepath.Join(root, "rootfs.ext4"), []byte("replaced source after immutable copy"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	called := false
	client, err := withJailerRecoveryProducerInputs(context.Background(), request, func(context.Context, jailerRecoverySupervisorConfig, *os.File, *os.File, [5]*os.File, [2]*os.File) (*jailerRecoveryClient, error) {
		called = true
		return &jailerRecoveryClient{}, nil
	})
	if err == nil || client != nil || called {
		t.Fatal("changed source reached start")
	}
}
