package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ClientConfig holds configuration for the HTTP runner client.
type ClientConfig struct {
	// BaseURL is the runner service base URL (e.g., "http://localhost:8080").
	BaseURL string
	// ServiceToken is the authentication token sent as X-Service-Token header.
	ServiceToken string
	// HTTPClient is an optional custom HTTP client. If nil, a default client
	// with a 30-second timeout is used.
	HTTPClient *http.Client
}

// Client is an HTTP implementation of the Runner interface that communicates
// with a Daytona runner service.
type Client struct {
	baseURL      string
	serviceToken string
	http         *http.Client
}

// NewClient creates a new HTTP runner client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("runner client: base_url must not be empty")
	}
	if cfg.ServiceToken == "" {
		return nil, fmt.Errorf("runner client: service_token must not be empty")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:      cfg.BaseURL,
		serviceToken: cfg.ServiceToken,
		http:         httpClient,
	}, nil
}

// CreateSandbox provisions a new Daytona sandbox via POST /sandboxes.
func (c *Client) CreateSandbox(ctx context.Context, req *CreateSandboxRequest) (*Sandbox, error) {
	if req == nil {
		return nil, fmt.Errorf("runner client: create request must not be nil")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("runner client: marshal create request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/sandboxes", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("runner client: build create request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("runner client: create sandbox: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}

	var sandbox Sandbox
	if err := json.NewDecoder(resp.Body).Decode(&sandbox); err != nil {
		return nil, fmt.Errorf("runner client: decode create response: %w", err)
	}
	return &sandbox, nil
}

// Exec executes a command in a sandbox via POST /sandboxes/{id}/exec.
func (c *Client) Exec(ctx context.Context, sandboxID string, req *ExecRequest) (*ExecResult, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("runner client: sandbox_id must not be empty")
	}
	if req == nil {
		return nil, fmt.Errorf("runner client: exec request must not be nil")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("runner client: marshal exec request: %w", err)
	}
	url := fmt.Sprintf("%s/sandboxes/%s/exec", c.baseURL, sandboxID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("runner client: build exec request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("runner client: exec: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}

	var result ExecResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("runner client: decode exec response: %w", err)
	}
	return &result, nil
}

// StreamLogs opens a streaming reader for sandbox logs via GET /sandboxes/{id}/logs.
// The caller must close the returned ReadCloser when done.
func (c *Client) StreamLogs(ctx context.Context, sandboxID string) (io.ReadCloser, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("runner client: sandbox_id must not be empty")
	}
	url := fmt.Sprintf("%s/sandboxes/%s/logs", c.baseURL, sandboxID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("runner client: build logs request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("runner client: stream logs: %w", err)
	}

	if err := checkStatusNoClose(resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp.Body, nil
}

// DestroySandbox tears down a sandbox via DELETE /sandboxes/{id}.
func (c *Client) DestroySandbox(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return fmt.Errorf("runner client: sandbox_id must not be empty")
	}
	url := fmt.Sprintf("%s/sandboxes/%s", c.baseURL, sandboxID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("runner client: build destroy request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("runner client: destroy sandbox: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusNoContent); err != nil {
		return err
	}
	return nil
}

// Health checks runner service health via GET /health.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return nil, fmt.Errorf("runner client: build health request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("runner client: health check: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}

	var status HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("runner client: decode health response: %w", err)
	}
	return &status, nil
}

// setHeaders sets the required headers on every runner API request.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Token", c.serviceToken)
}

// apiError represents an error response from the runner API.
type apiError struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code,omitempty"`
}

// checkStatus validates the HTTP response status code and reads the error body.
func checkStatus(resp *http.Response, expected int) error {
	if resp.StatusCode == expected {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var apiErr apiError
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
		return fmt.Errorf("runner client: HTTP %d: %s", resp.StatusCode, apiErr.Error)
	}
	return fmt.Errorf("runner client: unexpected status %d (expected %d)", resp.StatusCode, expected)
}

// checkStatusNoClose validates the HTTP response status without closing the body.
func checkStatusNoClose(resp *http.Response, expected int) error {
	if resp.StatusCode == expected {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var apiErr apiError
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
		return fmt.Errorf("runner client: HTTP %d: %s", resp.StatusCode, apiErr.Error)
	}
	return fmt.Errorf("runner client: unexpected status %d (expected %d)", resp.StatusCode, expected)
}

// Compile-time check that Client implements Runner.
var _ Runner = (*Client)(nil)
