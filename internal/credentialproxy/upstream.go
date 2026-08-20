package credentialproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute"
)

func writeAzureResponsesRequest(ctx context.Context, connection net.Conn, lease *TicketRequestLease, correlation TicketCorrelation, definition ServiceDefinition, body []byte) error {
	if connection == nil || lease == nil || ctx == nil {
		return ErrRouteUpstreamUnavailable
	}
	secret, err := credentialmemory.NewLockedMapping(maxUpstreamCredentialBytes)
	if err != nil {
		return ErrRouteUpstreamUnavailable
	}
	defer secret.Destroy()
	if err := lease.FillSecret(ctx, correlation, &lockedMappingCredentialSink{mapping: secret}); err != nil {
		return ErrRouteUpstreamUnavailable
	}

	var authentication *credentialmemory.LockedMapping
	var constructionErr error
	borrowErr := secret.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		authentication, constructionErr = buildAuthenticationLine(ctx, definition.UpstreamAuthenticationHeader(), view)
		return nil
	})
	if borrowErr != nil || constructionErr != nil || authentication == nil {
		if authentication != nil {
			_ = authentication.Destroy()
		}
		return ErrRouteUpstreamUnavailable
	}
	defer authentication.Destroy()

	prefix := []byte("POST " + definition.UpstreamPathTemplate() + " HTTP/1.1\r\n" +
		"Host: " + definition.SealedAuthority() + "\r\n" +
		"Accept: application/json\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n")
	if err := writeAll(connection, prefix); err != nil {
		wipeBytes(prefix)
		return ErrRouteUpstreamUnavailable
	}
	wipeBytes(prefix)
	if err := authentication.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		return view.WriteTo(ctx, &connectionCredentialSink{connection: connection, maximum: view.Len()})
	}); err != nil {
		return ErrRouteUpstreamUnavailable
	}
	if err := writeAll(connection, []byte("\r\n")); err != nil {
		return ErrRouteUpstreamUnavailable
	}
	if err := writeAll(connection, body); err != nil {
		return ErrRouteUpstreamUnavailable
	}
	return nil
}

func buildAuthenticationLine(ctx context.Context, name string, secret credentialmemory.BorrowedView) (*credentialmemory.LockedMapping, error) {
	if ctx == nil || secret == nil || secret.Len() <= 0 || secret.Len() > maxUpstreamCredentialBytes {
		return nil, ErrRouteUpstreamUnavailable
	}
	prefix := []byte(name + ": ")
	capacity := len(prefix) + secret.Len() + 2
	mapping, err := credentialmemory.NewLockedMapping(capacity)
	if err != nil {
		wipeBytes(prefix)
		return nil, ErrRouteUpstreamUnavailable
	}
	err = mapping.Load(ctx, func(destination []byte) (int, error) {
		copy(destination, prefix)
		sink := &sliceCredentialSink{destination: destination[len(prefix) : len(prefix)+secret.Len()]}
		if err := secret.WriteTo(ctx, sink); err != nil {
			wipeBytes(destination)
			return 0, ErrRouteUpstreamUnavailable
		}
		copy(destination[len(prefix)+secret.Len():], []byte("\r\n"))
		return capacity, nil
	})
	wipeBytes(prefix)
	if err != nil {
		_ = mapping.Destroy()
		return nil, ErrRouteUpstreamUnavailable
	}
	return mapping, nil
}

func readAzureResponsesResponse(connection net.Conn, definition ServiceDefinition) (applicationroute.Response, error) {
	limits := definition.Limits()
	header, err := readHTTPResponseHeader(connection, limits.MaxResponseHeaderBytes)
	if err != nil {
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	defer wipeBytes(header)
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(header), connection))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	defer response.Body.Close()
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.StatusCode < 200 ||
		response.Header.Get("Upgrade") != "" || len(response.Trailer) != 0 ||
		!validAzureResponsesContentEncoding(response) || response.Uncompressed {
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	contentType := response.Header.Get("Content-Type")
	streaming := contentType == "text/event-stream"
	if contentType != "application/json" && !streaming {
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	if !validAzureResponsesTransferFraming(response) {
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limits.MaxResponseBodyBytes+1))
	if err != nil || int64(len(body)) > limits.MaxResponseBodyBytes || response.ContentLength > limits.MaxResponseBodyBytes ||
		(response.ContentLength >= 0 && response.ContentLength != int64(len(body))) {
		wipeBytes(body)
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	maxEvent := int64(0)
	if streaming {
		maxEvent, err = validateSSEEvents(body, limits.MaxSSEEventBytes)
		if err != nil {
			wipeBytes(body)
			return applicationroute.Response{}, ErrRouteResponseRejected
		}
	} else if !json.Valid(body) {
		wipeBytes(body)
		return applicationroute.Response{}, ErrRouteResponseRejected
	}
	return applicationroute.Response{
		Metadata: applicationroute.ResponseMetadata{
			StatusCode: response.StatusCode, ContentType: contentType, HeaderBytes: int64(len(header)),
			ContentLength: int64(len(body)), MaxEventBytes: maxEvent, Streaming: streaming,
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func validAzureResponsesTransferFraming(response *http.Response) bool {
	if response == nil {
		return false
	}
	if len(response.TransferEncoding) == 0 {
		return response.ContentLength >= -1
	}
	return len(response.TransferEncoding) == 1 && response.TransferEncoding[0] == "chunked" && response.ContentLength == -1
}

func validAzureResponsesContentEncoding(response *http.Response) bool {
	if response == nil {
		return false
	}
	values := response.Header.Values("Content-Encoding")
	return len(values) == 0 || (len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "identity"))
}

func readHTTPResponseHeader(reader io.Reader, maximum int64) ([]byte, error) {
	if reader == nil || maximum <= 0 {
		return nil, ErrRouteResponseRejected
	}
	header := make([]byte, 0, minInt64(maximum, 4096))
	var one [1]byte
	for int64(len(header)) < maximum {
		count, err := reader.Read(one[:])
		if count == 1 {
			header = append(header, one[0])
			if len(header) >= 4 && bytes.Equal(header[len(header)-4:], []byte("\r\n\r\n")) {
				return header, nil
			}
		}
		if err != nil {
			wipeBytes(header)
			return nil, ErrRouteResponseRejected
		}
	}
	wipeBytes(header)
	return nil, ErrRouteResponseRejected
}

func validateSSEEvents(body []byte, maximum int64) (int64, error) {
	if len(body) == 0 || maximum <= 0 || !utf8.Valid(body) {
		return 0, ErrRouteResponseRejected
	}
	current := int64(0)
	observed := int64(0)
	lineStart := 0
	terminatedEvent := false
	for lineStart < len(body) {
		lineEnd, nextLine, ok := nextSSELine(body, lineStart)
		if !ok {
			return 0, ErrRouteResponseRejected
		}
		line := body[lineStart:lineEnd]
		if len(line) == 0 {
			if current > observed {
				observed = current
			}
			current = 0
			terminatedEvent = true
		} else {
			if !validSSELine(line) {
				return 0, ErrRouteResponseRejected
			}
			terminatedEvent = false
			current += int64(nextLine - lineStart)
			if current > maximum {
				return 0, ErrRouteResponseRejected
			}
		}
		lineStart = nextLine
	}
	if !terminatedEvent || current != 0 || observed > maximum {
		return 0, ErrRouteResponseRejected
	}
	return observed, nil
}

func nextSSELine(body []byte, start int) (lineEnd, next int, ok bool) {
	if start < 0 || start >= len(body) {
		return 0, 0, false
	}
	for index := start; index < len(body); index++ {
		switch body[index] {
		case '\n':
			return index, index + 1, true
		case '\r':
			if index+1 < len(body) && body[index+1] == '\n' {
				return index, index + 2, true
			}
			return index, index + 1, true
		}
	}
	return 0, 0, false
}

func validSSELine(line []byte) bool {
	if len(line) == 0 {
		return true
	}
	if line[0] == ':' {
		return true
	}
	field := line
	value := []byte(nil)
	if separator := bytes.IndexByte(line, ':'); separator >= 0 {
		field = line[:separator]
		value = line[separator+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
	}
	if len(field) == 0 {
		return false
	}
	switch string(field) {
	case "id":
		return bytes.IndexByte(value, 0) < 0
	case "data", "event":
		return true
	case "retry":
		if len(value) == 0 {
			return false
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		return true
	default:
		return true
	}
}

type lockedMappingCredentialSink struct {
	mapping *credentialmemory.LockedMapping
}

func (*lockedMappingCredentialSink) MaxCredentialBytes() int { return maxUpstreamCredentialBytes }
func (sink *lockedMappingCredentialSink) WriteCredential(value []byte) error {
	if sink.mapping == nil || len(value) <= 0 || len(value) > maxUpstreamCredentialBytes {
		return ErrRouteUpstreamUnavailable
	}
	return sink.mapping.Load(context.Background(), func(destination []byte) (int, error) {
		copy(destination, value)
		return len(value), nil
	})
}

type sliceCredentialSink struct {
	destination []byte
}

func (sink *sliceCredentialSink) MaxCredentialBytes() int { return len(sink.destination) }
func (sink *sliceCredentialSink) WriteCredential(value []byte) error {
	if len(value) != len(sink.destination) {
		wipeBytes(sink.destination)
		return ErrRouteUpstreamUnavailable
	}
	copy(sink.destination, value)
	return nil
}

type connectionCredentialSink struct {
	connection net.Conn
	maximum    int
}

func (sink *connectionCredentialSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *connectionCredentialSink) WriteCredential(value []byte) error {
	if sink.connection == nil || len(value) != sink.maximum {
		return ErrRouteUpstreamUnavailable
	}
	return writeAll(sink.connection, value)
}

func writeAll(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		count, err := writer.Write(body)
		if err != nil || count <= 0 || count > len(body) {
			return ErrRouteUpstreamUnavailable
		}
		body = body[count:]
	}
	return nil
}

func minInt64(left, right int64) int {
	if left < right {
		return int(left)
	}
	return int(right)
}

var _ sandboxruntime.JobCredentialSecretSink = (*lockedMappingCredentialSink)(nil)
