package sandboxexecution

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestL2ManifestDeclaresOptionalWorkerJobReference(t *testing.T) {
	t.Parallel()

	manifestType := reflect.TypeOf(Manifest{})
	field, ok := manifestType.FieldByName("WorkerJob")
	if !ok {
		t.Fatal("Manifest does not declare the L2 WorkerJob durable reference")
	}
	if got, want := field.Tag.Get("json"), "workerJob,omitempty"; got != want {
		t.Fatalf("Manifest.WorkerJob JSON tag = %q, want %q", got, want)
	}
	if field.Type.Kind() != reflect.Pointer {
		t.Fatalf("Manifest.WorkerJob kind = %s, want pointer", field.Type.Kind())
	}
}

func TestL2DefaultManifestOmitsWorkerJobReference(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(testManifest("exec-l2", time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if _, ok := raw["workerJob"]; ok {
		t.Fatalf("default manifest unexpectedly persisted workerJob: %s", payload)
	}
}
