package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ClientConfig
		wantErr string
	}{
		{
			name:    "empty base URL",
			cfg:     ClientConfig{ServiceToken: "tok"},
			wantErr: "base_url must not be empty",
		},
		{
			name:    "empty service token",
			cfg:     ClientConfig{BaseURL: "http://localhost"},
			wantErr: "service_token must not be empty",
		},
		{
			name: "valid config",
			cfg:  ClientConfig{BaseURL: "http://localhost", ServiceToken: "tok"},
		},
		{
			name: "custom HTTP client",
			cfg: ClientConfig{
				BaseURL:      "http://localhost",
				ServiceToken: "tok",
				HTTPClient:   &http.Client{Timeout: 5 * time.Second},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c == nil {
				t.Fatal("expected non-nil client")
			}
		})
	}
}

func TestServiceTokenHeader(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Service-Token")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(HealthStatus{OK: true})
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, ServiceToken: "my-secret-token"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "my-secret-token" {
		t.Errorf("X-Service-Token = %q, want %q", gotToken, "my-secret-token")
	}
}

func TestContentTypeHeader(t *testing.T) {
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(Sandbox{ID: "sb-1", Status: "running"})
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, ServiceToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.CreateSandbox(context.Background(), &CreateSandboxRequest{Image: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/json")
	}
}

func TestCreateSandbox(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var gotReq CreateSandboxRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/sandboxes" {
				t.Errorf("path = %s, want /sandboxes", r.URL.Path)
			}
			json.NewDecoder(r.Body).Decode(&gotReq)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(Sandbox{
				ID:        "sb-123",
				Status:    "running",
				CreatedAt: time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC),
			})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		sb, err := c.CreateSandbox(context.Background(), &CreateSandboxRequest{
			Image:   "ubuntu:22.04",
			Repo:    "https://github.com/org/repo",
			Branch:  "main",
			EnvVars: map[string]string{"FOO": "bar"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if sb.ID != "sb-123" {
			t.Errorf("ID = %q, want %q", sb.ID, "sb-123")
		}
		if sb.Status != "running" {
			t.Errorf("Status = %q, want %q", sb.Status, "running")
		}
		if gotReq.Image != "ubuntu:22.04" {
			t.Errorf("request image = %q, want %q", gotReq.Image, "ubuntu:22.04")
		}
		if gotReq.Repo != "https://github.com/org/repo" {
			t.Errorf("request repo = %q, want %q", gotReq.Repo, "https://github.com/org/repo")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		c := mustClient(t, "http://localhost")
		_, err := c.CreateSandbox(context.Background(), nil)
		if err == nil || !strings.Contains(err.Error(), "must not be nil") {
			t.Errorf("expected nil request error, got: %v", err)
		}
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(apiError{Error: "sandbox pool exhausted"})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		_, err := c.CreateSandbox(context.Background(), &CreateSandboxRequest{Image: "ubuntu"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "sandbox pool exhausted") {
			t.Errorf("error %q should contain API error message", err.Error())
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error %q should contain status code", err.Error())
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(apiError{Error: "invalid service token", ErrorCode: "unauthorized"})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		_, err := c.CreateSandbox(context.Background(), &CreateSandboxRequest{Image: "ubuntu"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("error %q should contain 401", err.Error())
		}
	})
}

func TestExec(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var gotReq ExecRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/sandboxes/sb-1/exec" {
				t.Errorf("path = %s, want /sandboxes/sb-1/exec", r.URL.Path)
			}
			json.NewDecoder(r.Body).Decode(&gotReq)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(ExecResult{
				ExitCode: 0,
				Stdout:   "hello world",
				Stderr:   "",
			})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		result, err := c.Exec(context.Background(), "sb-1", &ExecRequest{
			Command: "echo hello world",
			WorkDir: "/workspace",
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.ExitCode != 0 {
			t.Errorf("ExitCode = %d, want 0", result.ExitCode)
		}
		if result.Stdout != "hello world" {
			t.Errorf("Stdout = %q, want %q", result.Stdout, "hello world")
		}
		if gotReq.Command != "echo hello world" {
			t.Errorf("request command = %q, want %q", gotReq.Command, "echo hello world")
		}
	})

	t.Run("empty sandbox ID", func(t *testing.T) {
		c := mustClient(t, "http://localhost")
		_, err := c.Exec(context.Background(), "", &ExecRequest{Command: "ls"})
		if err == nil || !strings.Contains(err.Error(), "sandbox_id must not be empty") {
			t.Errorf("expected empty sandbox_id error, got: %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		c := mustClient(t, "http://localhost")
		_, err := c.Exec(context.Background(), "sb-1", nil)
		if err == nil || !strings.Contains(err.Error(), "must not be nil") {
			t.Errorf("expected nil request error, got: %v", err)
		}
	})

	t.Run("non-zero exit code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(ExecResult{
				ExitCode: 1,
				Stdout:   "",
				Stderr:   "command not found",
			})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		result, err := c.Exec(context.Background(), "sb-1", &ExecRequest{Command: "bad-cmd"})
		if err != nil {
			t.Fatalf("non-zero exit is not an HTTP error: %v", err)
		}
		if result.ExitCode != 1 {
			t.Errorf("ExitCode = %d, want 1", result.ExitCode)
		}
		if result.Stderr != "command not found" {
			t.Errorf("Stderr = %q, want %q", result.Stderr, "command not found")
		}
	})
}

func TestStreamLogs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("method = %s, want GET", r.Method)
			}
			if r.URL.Path != "/sandboxes/sb-1/logs" {
				t.Errorf("path = %s, want /sandboxes/sb-1/logs", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("line1\nline2\nline3\n"))
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		rc, err := c.StreamLogs(context.Background(), "sb-1")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()

		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "line1\nline2\nline3\n" {
			t.Errorf("logs = %q, want %q", string(data), "line1\nline2\nline3\n")
		}
	})

	t.Run("empty sandbox ID", func(t *testing.T) {
		c := mustClient(t, "http://localhost")
		_, err := c.StreamLogs(context.Background(), "")
		if err == nil || !strings.Contains(err.Error(), "sandbox_id must not be empty") {
			t.Errorf("expected empty sandbox_id error, got: %v", err)
		}
	})

	t.Run("server error closes body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(apiError{Error: "sandbox not found"})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		rc, err := c.StreamLogs(context.Background(), "sb-missing")
		if err == nil {
			rc.Close()
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("error %q should contain 404", err.Error())
		}
	})
}

func TestDestroySandbox(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("method = %s, want DELETE", r.Method)
			}
			if r.URL.Path != "/sandboxes/sb-1" {
				t.Errorf("path = %s, want /sandboxes/sb-1", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		err := c.DestroySandbox(context.Background(), "sb-1")
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("empty sandbox ID", func(t *testing.T) {
		c := mustClient(t, "http://localhost")
		err := c.DestroySandbox(context.Background(), "")
		if err == nil || !strings.Contains(err.Error(), "sandbox_id must not be empty") {
			t.Errorf("expected empty sandbox_id error, got: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(apiError{Error: "sandbox not found"})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		err := c.DestroySandbox(context.Background(), "sb-missing")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "sandbox not found") {
			t.Errorf("error %q should contain API message", err.Error())
		}
	})
}

func TestHealth(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("method = %s, want GET", r.Method)
			}
			if r.URL.Path != "/health" {
				t.Errorf("path = %s, want /health", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(HealthStatus{OK: true, Version: "1.2.3"})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		status, err := c.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !status.OK {
			t.Error("OK should be true")
		}
		if status.Version != "1.2.3" {
			t.Errorf("Version = %q, want %q", status.Version, "1.2.3")
		}
	})

	t.Run("unhealthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(apiError{Error: "database unavailable"})
		}))
		defer srv.Close()

		c := mustClient(t, srv.URL)
		_, err := c.Health(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "503") {
			t.Errorf("error %q should contain 503", err.Error())
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		c := mustClient(t, "http://127.0.0.1:1")
		_, err := c.Health(context.Background())
		if err == nil {
			t.Fatal("expected error for unreachable server")
		}
	})
}

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := c.Health(ctx)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestInterfaceCompliance(t *testing.T) {
	// Verify Client implements Runner at compile time.
	var _ Runner = (*Client)(nil)
}

// mustClient creates a test client with a default service token.
func mustClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		BaseURL:      baseURL,
		ServiceToken: "test-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
