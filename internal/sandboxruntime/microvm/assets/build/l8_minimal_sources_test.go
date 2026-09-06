package build

import (
	"reflect"
	"strings"
	"testing"
)

func TestL8MinimalSourceLockValidation(t *testing.T) {
	_, _, legacy, _ := validL8BuildContracts(t)
	valid := L8MinimalSourceLock{SchemaVersion: L8MinimalSourceLockSchemaV1, ImageProfile: ImageProfileL8MinimalCredentials, SourceRevision: strings.Repeat("a", 40), ParentL7: legacy.ParentL7, Runtime: legacy.Runtime, Sources: legacy.Sources}
	for _, scenario := range []string{"valid", "schema", "profile", "revision", "missing_sources", "source_order", "source_digest", "source_size", "source_filename", "duplicate_source", "node_version", "runtime_digest", "dependency_correlation", "parent_correlation"} {
		t.Run(scenario, func(t *testing.T) {
			lock := cloneL8Contract(t, valid)
			switch scenario {
			case "schema":
				lock.SchemaVersion = L8SourceLockSchemaVersionV1
			case "profile":
				lock.ImageProfile = ImageProfileL8ProductionCredentials
			case "revision":
				lock.SourceRevision = "unknown"
			case "missing_sources":
				lock.Sources = nil
			case "source_order":
				lock.Sources[2], lock.Sources[3] = lock.Sources[3], lock.Sources[2]
			case "source_digest":
				lock.Sources[3].SHA256 = "invalid"
			case "source_size":
				lock.Sources[3].SizeBytes = 0
			case "source_filename":
				lock.Sources[3].Filename = "../archive.tgz"
			case "duplicate_source":
				lock.Sources = append(lock.Sources, lock.Sources[3])
			case "node_version":
				lock.Sources[0].Version = "20.0.0"
			case "runtime_digest":
				lock.Runtime.NodeSHA256 = ""
			case "dependency_correlation":
				lock.Sources[3].SHA256 = strings.Repeat("f", 64)
			case "parent_correlation":
				lock.ParentL7.KernelSHA256 = strings.Repeat("f", 64)
			}
			before := cloneL8Contract(t, lock)
			err := ValidateL8MinimalSourceLock(lock)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("scenario=%s error=%v", scenario, err)
			}
			if !reflect.DeepEqual(lock, before) {
				t.Fatal("source validation mutated caller-owned pins")
			}
		})
	}
}
