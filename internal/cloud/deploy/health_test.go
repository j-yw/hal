package deploy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	handler := HealthHandler("0.1.0", "turso")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.OK {
		t.Error("expected ok=true")
	}
	if resp.Version != "0.1.0" {
		t.Errorf("expected version %q, got %q", "0.1.0", resp.Version)
	}
	if resp.Adapter != "turso" {
		t.Errorf("expected adapter %q, got %q", "turso", resp.Adapter)
	}
}
