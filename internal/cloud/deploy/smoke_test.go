package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunSmoke_AllHealthy(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer cpServer.Close()

	runnerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer runnerServer.Close()

	report := RunSmoke(context.Background(), cpServer.URL, runnerServer.URL, nil)

	if !report.AllOK {
		t.Error("expected AllOK=true")
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}
	for _, r := range report.Results {
		if !r.OK {
			t.Errorf("service %q not OK: %s", r.Service, r.Error)
		}
		if r.StatusCode != 200 {
			t.Errorf("service %q status %d, want 200", r.Service, r.StatusCode)
		}
	}
}

func TestRunSmoke_RunnerUnhealthy(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer cpServer.Close()

	runnerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer runnerServer.Close()

	report := RunSmoke(context.Background(), cpServer.URL, runnerServer.URL, nil)

	if report.AllOK {
		t.Error("expected AllOK=false when runner is unhealthy")
	}

	// Control plane should be OK.
	if !report.Results[0].OK {
		t.Error("expected control-plane OK")
	}
	// Runner should not be OK.
	if report.Results[1].OK {
		t.Error("expected runner not OK")
	}
}

func TestRunSmoke_ConnectionRefused(t *testing.T) {
	report := RunSmoke(context.Background(), "http://127.0.0.1:1", "http://127.0.0.1:2", nil)

	if report.AllOK {
		t.Error("expected AllOK=false when connections refused")
	}
	for _, r := range report.Results {
		if r.OK {
			t.Errorf("service %q should not be OK", r.Service)
		}
		if r.Error == "" {
			t.Errorf("service %q should have error message", r.Service)
		}
	}
}

func TestRunSmoke_EmptyRunnerURL_SyntheticHealth(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer cpServer.Close()

	report := RunSmoke(context.Background(), cpServer.URL, "", nil)

	if !report.AllOK {
		t.Error("expected AllOK=true when runner URL is empty (SDK-direct mode)")
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}

	// Control plane should be checked normally.
	cp := report.Results[0]
	if !cp.OK {
		t.Error("expected control-plane OK")
	}
	if cp.StatusCode != 200 {
		t.Errorf("expected control-plane status 200, got %d", cp.StatusCode)
	}

	// Runner should be synthetic healthy.
	runner := report.Results[1]
	if !runner.OK {
		t.Error("expected runner OK in SDK-direct mode")
	}
	if runner.URL != "sdk-direct" {
		t.Errorf("expected runner URL %q, got %q", "sdk-direct", runner.URL)
	}
	if runner.StatusCode != 0 {
		t.Errorf("expected runner status 0 (no HTTP call), got %d", runner.StatusCode)
	}
	if runner.Error != "" {
		t.Errorf("expected no error for synthetic runner, got %q", runner.Error)
	}
}

func TestRunSmoke_NonEmptyRunnerURL_HTTPCheck(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer cpServer.Close()

	runnerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer runnerServer.Close()

	report := RunSmoke(context.Background(), cpServer.URL, runnerServer.URL, nil)

	if !report.AllOK {
		t.Error("expected AllOK=true")
	}

	runner := report.Results[1]
	if !runner.OK {
		t.Error("expected runner OK")
	}
	if runner.StatusCode != 200 {
		t.Errorf("expected runner status 200, got %d", runner.StatusCode)
	}
	if runner.URL != runnerServer.URL+"/health" {
		t.Errorf("expected runner URL %q, got %q", runnerServer.URL+"/health", runner.URL)
	}
}

func TestWriteSmokeReport_HumanReadable(t *testing.T) {
	report := SmokeReport{
		Results: []SmokeResult{
			{Service: "control-plane", URL: "http://cp/health", StatusCode: 200, OK: true},
			{Service: "runner", URL: "http://runner/health", StatusCode: 503, OK: false, Error: "expected HTTP 200, got 503"},
		},
		AllOK: false,
	}

	var buf bytes.Buffer
	if err := WriteSmokeReport(&buf, report, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "control-plane") {
		t.Error("output should contain control-plane")
	}
	if !strings.Contains(output, "FAIL") {
		t.Error("output should contain FAIL")
	}
	if !strings.Contains(output, "Some services unhealthy") {
		t.Error("output should indicate unhealthy services")
	}
}

func TestWriteSmokeReport_JSON(t *testing.T) {
	report := SmokeReport{
		Results: []SmokeResult{
			{Service: "control-plane", URL: "http://cp/health", StatusCode: 200, OK: true},
			{Service: "runner", URL: "http://runner/health", StatusCode: 200, OK: true},
		},
		AllOK: true,
	}

	var buf bytes.Buffer
	if err := WriteSmokeReport(&buf, report, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed SmokeReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !parsed.AllOK {
		t.Error("expected AllOK=true in JSON output")
	}
	if len(parsed.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(parsed.Results))
	}
}
