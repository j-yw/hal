package credentialproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
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
