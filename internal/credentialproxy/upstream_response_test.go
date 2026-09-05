package credentialproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestL8D3AzureResponsesRejectsMalformedJSONEncodingAndEventStreamFraming(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		extra       string
		body        []byte
		chunked     bool
	}{
		{name: "invalid JSON syntax", contentType: "application/json", body: []byte("not-json")},
		{name: "content encoding", contentType: "application/json", extra: "Content-Encoding: gzip\r\n", body: []byte(`{"ok":true}`)},
		{name: "invalid event stream UTF-8", contentType: "text/event-stream", body: []byte{0xff, '\n', '\n'}},
		{name: "unterminated event stream event", contentType: "text/event-stream", body: []byte("data: {}\n")},
		{name: "invalid retry value", contentType: "text/event-stream", body: []byte("retry: soon\n\n")},
		{name: "NUL event id", contentType: "text/event-stream", body: []byte("id: bad\x00id\ndata: {}\n\n")},
	}
	definition := l8D3AzureResponsesDefinition(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := l8D3RawUpstreamResponse(httpResponseSpec{
				contentType: tt.contentType,
				extra:       tt.extra,
				body:        tt.body,
				chunked:     tt.chunked,
			})
			connection := l8D3RawResponseConnection(t, wire)
			response, err := readAzureResponsesResponse(connection, definition)
			if response.Body != nil {
				_ = response.Body.Close()
			}
			if err == nil {
				t.Fatal("readAzureResponsesResponse() accepted malformed upstream response")
			}
		})
	}
}

func TestL8D3AzureResponsesAcceptsExactJSONAndEventStreamWithoutChangingBody(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		extra       string
		body        []byte
		chunked     bool
		streaming   bool
	}{
		{name: "JSON", contentType: "application/json", body: []byte("{\n  \"ok\": true\n}")},
		{name: "chunked JSON", contentType: "application/json", body: []byte(`{"ok":true}`), chunked: true},
		{name: "identity encoded JSON", contentType: "application/json", extra: "Content-Encoding: identity\r\n", body: []byte(`{"ok":true}`)},
		{
			name: "event stream", contentType: "text/event-stream", streaming: true, chunked: true,
			body: []byte(": heartbeat\rignored: value\r\nignored\nevent: response.output_text.delta\rid: event-1\nretry: 1000\r\ndata: {\"delta\":\"hello\"}\ndata: [DONE]\r\n\r\n"),
		},
	}
	definition := l8D3AzureResponsesDefinition(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connection := l8D3RawResponseConnection(t, l8D3RawUpstreamResponse(httpResponseSpec{
				contentType: tt.contentType,
				extra:       tt.extra,
				body:        tt.body,
				chunked:     tt.chunked,
			}))
			response, err := readAzureResponsesResponse(connection, definition)
			if err != nil {
				t.Fatalf("readAzureResponsesResponse() error: %v", err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.body) {
				t.Fatalf("response body changed: got %q want exact %q", got, tt.body)
			}
			if response.Metadata.Streaming != tt.streaming || response.Metadata.ContentLength != int64(len(tt.body)) {
				t.Fatalf("response metadata = %#v", response.Metadata)
			}
		})
	}
}

func TestL8D3AzureResponsesOverlimitResponseClosesWithoutBodyDrain(t *testing.T) {
	definition := l8D3AzureResponsesDefinition(t)
	definition.limits.MaxResponseBodyBytes = 8
	tests := []struct {
		name          string
		wire          []byte
		wantBodyReads int
	}{
		{
			name: "declared fixed length",
			wire: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n"),
		},
		{
			name:          "chunked max plus one",
			wire:          []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\na\r\n123456789"),
			wantBodyReads: 12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connection := newL8D3BlockingResponseConn(tt.wire)
			done := make(chan error, 1)
			go func() {
				response, err := readAzureResponsesResponse(connection, definition)
				if response.Body != nil {
					_ = response.Body.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("overlimit response was accepted")
				}
			case <-time.After(200 * time.Millisecond):
				_ = connection.Close()
				<-done
				t.Fatal("overlimit response blocked while draining beyond bound")
			}
			if !connection.Closed() {
				t.Fatal("rejected response did not close owned connection")
			}
			headerEnd := bytes.Index(tt.wire, []byte("\r\n\r\n")) + 4
			bodyReads := connection.ReadCount() - headerEnd
			if bodyReads != tt.wantBodyReads {
				t.Fatalf("body wire bytes read = %d, want %d", bodyReads, tt.wantBodyReads)
			}
		})
	}
}

type httpResponseSpec struct {
	contentType string
	extra       string
	body        []byte
	chunked     bool
}

func l8D3RawUpstreamResponse(spec httpResponseSpec) []byte {
	header := "HTTP/1.1 200 OK\r\nContent-Type: " + spec.contentType + "\r\n" + spec.extra
	if spec.chunked {
		header += "Transfer-Encoding: chunked\r\n\r\n"
		wire := []byte(header + fmt.Sprintf("%x\r\n", len(spec.body)))
		wire = append(wire, spec.body...)
		return append(wire, []byte("\r\n0\r\n\r\n")...)
	}
	header += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(spec.body))
	return append([]byte(header), spec.body...)
}

func l8D3RawResponseConnection(t *testing.T, wire []byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() {
		defer server.Close()
		_, _ = server.Write(wire)
	}()
	return client
}

func l8D3AzureResponsesDefinition(t *testing.T) ServiceDefinition {
	t.Helper()
	definition, err := NewAzureOpenAIResponsesV1Definition(
		"example.com", 443, "example.com", TLSRootPolicySystem, "deployment-one", "2026-06-01",
	)
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

type l8D3BlockingResponseConn struct {
	mu        sync.Mutex
	wire      []byte
	offset    int
	closed    chan struct{}
	closeOnce sync.Once
}

func newL8D3BlockingResponseConn(wire []byte) *l8D3BlockingResponseConn {
	return &l8D3BlockingResponseConn{wire: append([]byte(nil), wire...), closed: make(chan struct{})}
}

func (connection *l8D3BlockingResponseConn) Read(destination []byte) (int, error) {
	connection.mu.Lock()
	if connection.offset < len(connection.wire) {
		count := copy(destination, connection.wire[connection.offset:])
		connection.offset += count
		connection.mu.Unlock()
		return count, nil
	}
	connection.mu.Unlock()
	<-connection.closed
	return 0, io.EOF
}

func (*l8D3BlockingResponseConn) Write(body []byte) (int, error) { return len(body), nil }
func (connection *l8D3BlockingResponseConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}
func (*l8D3BlockingResponseConn) LocalAddr() net.Addr              { return l8D3ResponseAddr("local") }
func (*l8D3BlockingResponseConn) RemoteAddr() net.Addr             { return l8D3ResponseAddr("remote") }
func (*l8D3BlockingResponseConn) SetDeadline(time.Time) error      { return nil }
func (*l8D3BlockingResponseConn) SetReadDeadline(time.Time) error  { return nil }
func (*l8D3BlockingResponseConn) SetWriteDeadline(time.Time) error { return nil }
func (connection *l8D3BlockingResponseConn) ReadCount() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.offset
}
func (connection *l8D3BlockingResponseConn) Closed() bool {
	select {
	case <-connection.closed:
		return true
	default:
		return false
	}
}

type l8D3ResponseAddr string

func (address l8D3ResponseAddr) Network() string { return "tcp" }
func (address l8D3ResponseAddr) String() string  { return string(address) }
