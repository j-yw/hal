//go:build integration

package sandbox

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestIntegrationSnapshotCreateDelete(t *testing.T) {
	client := newIntegrationClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var snapshotID string
	t.Cleanup(func() {
		if snapshotID != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cleanupCancel()
			_ = DeleteSnapshot(cleanupCtx, client, snapshotID)
		}
	})

	// Create a snapshot from a lightweight public image
	snapshotName := integrationResourceName("inttest-snapshot-create-delete-snap")
	var out bytes.Buffer
	var err error
	snapshotID, err = CreateSnapshot(ctx, client, snapshotName, "ubuntu:22.04", &out)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	if snapshotID == "" {
		t.Fatal("CreateSnapshot returned empty snapshot ID")
	}
	t.Logf("Created snapshot: %s", snapshotID)

	// Delete the snapshot
	if err := DeleteSnapshot(ctx, client, snapshotID); err != nil {
		t.Fatalf("DeleteSnapshot failed: %v", err)
	}
	t.Logf("Deleted snapshot: %s", snapshotID)

	// Clear snapshotID so cleanup doesn't try to delete again
	snapshotID = ""
}
