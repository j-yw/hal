package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/deploy"
)

func TestRunCloudSmoke_AllHealthy(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer cpServer.Close()

	runnerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer runnerServer.Close()

	var buf bytes.Buffer
	err := runCloudSmoke(cpServer.URL, runnerServer.URL, false, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "All services healthy") {
		t.Errorf("expected healthy message in output, got: %s", output)
	}
}

func TestRunCloudSmoke_Unhealthy(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer cpServer.Close()

	runnerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer runnerServer.Close()

	var buf bytes.Buffer
	err := runCloudSmoke(cpServer.URL, runnerServer.URL, false, &buf)
	if err == nil {
		t.Fatal("expected error for unhealthy service")
	}
	if !strings.Contains(err.Error(), "smoke check failed") {
		t.Errorf("error %q does not contain %q", err.Error(), "smoke check failed")
	}
}

func TestRunCloudSmoke_JSON(t *testing.T) {
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer cpServer.Close()

	runnerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer runnerServer.Close()

	var buf bytes.Buffer
	err := runCloudSmoke(cpServer.URL, runnerServer.URL, true, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report deploy.SmokeReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if !report.AllOK {
		t.Error("expected AllOK=true")
	}
}

func TestRunCloudSmoke_EmptyURLs(t *testing.T) {
	var buf bytes.Buffer
	err := runCloudSmoke("", "http://runner:8090", false, &buf)
	if err == nil {
		t.Fatal("expected error for empty control-plane URL")
	}

	buf.Reset()
	err = runCloudSmoke("http://cp:8080", "", false, &buf)
	if err == nil {
		t.Fatal("expected error for empty runner URL")
	}
}

func TestRunCloudEnv_Valid(t *testing.T) {
	env := map[string]string{
		"HAL_CLOUD_DB_ADAPTER":           "turso",
		"HAL_CLOUD_TURSO_URL":            "libsql://db.example.com",
		"HAL_CLOUD_TURSO_AUTH_TOKEN":     "token123",
		"HAL_CLOUD_RUNNER_URL":           "http://runner:8090",
		"HAL_CLOUD_RUNNER_SERVICE_TOKEN": "svc-token",
	}

	var buf bytes.Buffer
	err := runCloudEnv(func(key string) string { return env[key] }, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Environment OK") {
		t.Errorf("expected 'Environment OK' in output, got: %s", output)
	}
	if !strings.Contains(output, "turso") {
		t.Errorf("expected 'turso' in output, got: %s", output)
	}
}

func TestRunCloudEnv_MissingTursoURL(t *testing.T) {
	env := map[string]string{
		"HAL_CLOUD_DB_ADAPTER":           "turso",
		"HAL_CLOUD_TURSO_AUTH_TOKEN":     "token123",
		"HAL_CLOUD_RUNNER_URL":           "http://runner:8090",
		"HAL_CLOUD_RUNNER_SERVICE_TOKEN": "svc-token",
	}

	var buf bytes.Buffer
	err := runCloudEnv(func(key string) string { return env[key] }, &buf)
	if err == nil {
		t.Fatal("expected error for missing Turso URL")
	}
	if !strings.Contains(buf.String(), "HAL_CLOUD_TURSO_URL") {
		t.Errorf("expected error about HAL_CLOUD_TURSO_URL, got: %s", buf.String())
	}
}

func TestRunCloudEnv_DefaultTurso(t *testing.T) {
	env := map[string]string{
		"HAL_CLOUD_TURSO_URL":            "libsql://db.example.com",
		"HAL_CLOUD_TURSO_AUTH_TOKEN":     "token123",
		"HAL_CLOUD_RUNNER_URL":           "http://runner:8090",
		"HAL_CLOUD_RUNNER_SERVICE_TOKEN": "svc-token",
	}

	var buf bytes.Buffer
	err := runCloudEnv(func(key string) string { return env[key] }, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "turso") {
		t.Errorf("expected default adapter 'turso' in output")
	}
}

func TestRunCloudEnv_PostgresAdapter(t *testing.T) {
	env := map[string]string{
		"HAL_CLOUD_DB_ADAPTER":           "postgres",
		"HAL_CLOUD_POSTGRES_DSN":         "postgres://localhost:5432/hal",
		"HAL_CLOUD_RUNNER_URL":           "http://runner:8090",
		"HAL_CLOUD_RUNNER_SERVICE_TOKEN": "svc-token",
	}

	var buf bytes.Buffer
	err := runCloudEnv(func(key string) string { return env[key] }, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "postgres_dsn") {
		t.Errorf("expected postgres_dsn in output")
	}
}
