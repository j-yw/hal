//go:build linux

package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestMinimalControlConfigRejectsCanonicalAndCorrelationDrift(t *testing.T) {
	for name, mutate := range map[string]func(*minimalControlSupervisorConfig){
		"six roles":                    func(c *minimalControlSupervisorConfig) { c.Roles = c.Roles[:6] },
		"seven roles":                  func(c *minimalControlSupervisorConfig) { c.Roles = c.Roles[:7] },
		"extra role":                   func(c *minimalControlSupervisorConfig) { c.Roles = append(c.Roles, "extra") },
		"swapped roles":                func(c *minimalControlSupervisorConfig) { c.Roles[6], c.Roles[7] = c.Roles[7], c.Roles[6] },
		"duplicate role":               func(c *minimalControlSupervisorConfig) { c.Roles[7] = c.Roles[6] },
		"old discriminator":            func(c *minimalControlSupervisorConfig) { c.Version = jailerRecoveryConfigVersion },
		"unknown discriminator":        func(c *minimalControlSupervisorConfig) { c.Version += "-extra" },
		"missing discriminator":        func(c *minimalControlSupervisorConfig) { c.Version = "" },
		"case discriminator":           func(c *minimalControlSupervisorConfig) { c.Version = strings.ToUpper(c.Version) },
		"nonroot daemon policy":        func(c *minimalControlSupervisorConfig) { c.DaemonUID = 42 },
		"root workload policy":         func(c *minimalControlSupervisorConfig) { c.Policy.UID = 0 },
		"changed runtime":              func(c *minimalControlSupervisorConfig) { c.Job.RuntimeID = "other-runtime" },
		"changed execution":            func(c *minimalControlSupervisorConfig) { c.Job.ExecutionID = "other-execution" },
		"changed asset digest":         func(c *minimalControlSupervisorConfig) { c.Rootfs.SHA256 = strings.Repeat("a", 64) },
		"changed asset identity":       func(c *minimalControlSupervisorConfig) { c.Kernel.Inode++ },
		"changed config digest":        func(c *minimalControlSupervisorConfig) { c.Config.SHA256 = strings.Repeat("a", 64) },
		"empty binding":                func(c *minimalControlSupervisorConfig) { c.Control.Prelaunch = nil },
		"late process":                 func(c *minimalControlSupervisorConfig) { c.Control.Prelaunch["processGeneration"] = "fabricated" },
		"late vsock":                   func(c *minimalControlSupervisorConfig) { c.Control.Prelaunch["vsockGeneration"] = "1" },
		"missing launch grant":         func(c *minimalControlSupervisorConfig) { c.Control.LaunchGrantID = "" },
		"noncanonical launch revision": func(c *minimalControlSupervisorConfig) { c.Control.LaunchPolicyRevision = "03" },
		"missing preparation bound":    func(c *minimalControlSupervisorConfig) { c.Control.PreparationDeadlineUnixNano = 0 },
		"missing nonce":                func(c *minimalControlSupervisorConfig) { c.Control.BootNonce = "" },
		"missing key generation":       func(c *minimalControlSupervisorConfig) { c.Control.ControllerKeyGeneration = "" },
		"missing namespace tuple":      func(c *minimalControlSupervisorConfig) { c.Control.Namespace = minimalControlNamespaces{} },
		"namespace alias": func(c *minimalControlSupervisorConfig) {
			c.Control.Namespace.NetworkInode = c.Control.Namespace.UserInode
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			mutate(&f.config)
			f.reseal(nil)
			f.reject(t)
		})
	}
}

func TestMinimalControlConfigRequiresEveryPublicPrelaunchPin(t *testing.T) {
	keys := []string{"sandboxId", "executionId", "workerId", "hostId", "runtimeDriver", "runtimeId", "runtimeGeneration", "bootGeneration", "imageGeneration", "imageDigest", "workerJobId", "submissionId", "planId", "jobGeneration", "admissionGrantId", "admissionRevision", "principalId", "templatePolicyId", "workspacePolicyId", "networkPlanId", "policySnapshotId", "proxySessionId", "proxyGenerationId", "topologyGenerationId", "ruleGenerationId"}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			delete(f.config.Control.Prelaunch, key)
			f.reseal(nil)
			f.reject(t)
		})
	}
}

func TestMinimalControlConfigExactJSONHasNoAliasOrTrailingAcceptance(t *testing.T) {
	for _, name := range []string{"unknown", "duplicate", "case alias", "nested duplicate", "nested alias", "nested unknown", "null false", "null numeric", "null control", "null roles", "trailing", "two documents", "too large"} {
		t.Run(name, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			payload := bytes.Clone(f.payload)
			switch name {
			case "unknown":
				payload = bytes.Replace(payload, []byte(`"daemonUid":0`), []byte(`"unknown":0,"daemonUid":0`), 1)
			case "duplicate":
				payload = bytes.Replace(payload, []byte(`"daemonUid":0`), []byte(`"daemonUid":0,"daemonUid":0`), 1)
			case "case alias":
				payload = bytes.Replace(payload, []byte(`"daemonUid"`), []byte(`"DaemonUid"`), 1)
			case "nested duplicate":
				payload = bytes.Replace(payload, []byte(`"admissionRevision":"7"`), []byte(`"admissionRevision":"7","admissionRevision":"7"`), 1)
			case "nested alias":
				payload = bytes.Replace(payload, []byte(`"controllerKeyGeneration"`), []byte(`"ControllerKeyGeneration"`), 1)
			case "nested unknown":
				payload = bytes.Replace(payload, []byte(`"controllerKeyGeneration"`), []byte(`"credentialProof":true,"controllerKeyGeneration"`), 1)
			case "null false":
				payload = bytes.Replace(payload, []byte(`"enablePci":false`), []byte(`"enablePci":null`), 1)
			case "null numeric":
				payload = bytes.Replace(payload, []byte(`"daemonUid":0`), []byte(`"daemonUid":null`), 1)
			case "null control":
				var object map[string]json.RawMessage
				_ = json.Unmarshal(payload, &object)
				object["minimalControl"] = json.RawMessage("null")
				payload, _ = json.Marshal(object)
			case "null roles":
				roles, _ := json.Marshal(f.config.Roles)
				payload = bytes.Replace(payload, roles, []byte("null"), 1)
			case "trailing":
				payload = append(payload, '\n')
			case "two documents":
				payload = append(payload, payload...)
			case "too large":
				payload = append(payload, bytes.Repeat([]byte(" "), l8RuntimeOwnerSupervisorConfigLimit)...)
			}
			if bytes.Equal(payload, f.payload) {
				t.Fatal("negative fixture did not mutate input")
			}
			f.reseal(payload)
			f.reject(t)
		})
	}
}

func (f *minimalControlAdmissionFixture) reject(t *testing.T) {
	t.Helper()
	code := f.run("supervise", func(*minimalControlSupervisorAdmission) error {
		t.Fatal("malformed selected config admitted")
		return nil
	})
	if code != 127 || f.legacy != 0 || f.admissions != 0 {
		t.Fatal("selected failure fell back or admitted")
	}
}

func TestMinimalControlConfigCannotEnterHistoricalDecoders(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	if _, err := decodeJailerRecoverySupervisorConfig(f.payload); err == nil {
		t.Fatal("eight-role config entered seven-role decoder")
	}
	if _, err := decodeL8RuntimeOwnerSupervisorConfig(f.payload); err == nil {
		t.Fatal("eight-role config entered six-role decoder")
	}
	if !slices.Equal(f.config.Roles[:7], jailerRecoverySupervisorRoles()) {
		t.Fatal("first seven role positions changed")
	}
}
