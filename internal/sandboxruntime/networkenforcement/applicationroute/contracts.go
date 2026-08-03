// Package applicationroute defines neutral bounded application-route
// contracts shared by network-enforcement implementations.
package applicationroute

import (
	"errors"
	"io"
	"strings"
)

type RouteID string

const (
	RouteCredentialHTTPV1  RouteID = "credential-http-v1"
	CredentialHTTPV1Prefix         = "/.well-known/hal/credential-http/v1/"
)

type StreamLimits struct {
	MaxRequestHeaderBytes  int64
	MaxRequestBodyBytes    int64
	MaxResponseHeaderBytes int64
	MaxResponseBodyBytes   int64
	MaxEventBytes          int64
}

type Definition struct {
	ID     RouteID
	Prefix string
	Limits StreamLimits
}

type RequestMetadata struct {
	Method        string
	ContentType   string
	HeaderBytes   int64
	ContentLength int64
}

type ResponseMetadata struct {
	StatusCode    int
	ContentType   string
	HeaderBytes   int64
	ContentLength int64
	MaxEventBytes int64
	Streaming     bool
}

type Request struct {
	Metadata RequestMetadata
	Body     io.Reader
}

type Response struct {
	Metadata ResponseMetadata
	Body     io.ReadCloser
}

var (
	ErrHandlerRequired               = errors.New("application route handler is required")
	ErrInvalidRoute                  = errors.New("application route invalid")
	ErrRouteCollision                = errors.New("application route collision")
	ErrHandlerStart                  = errors.New("application route handler start failed")
	ErrHandlerClose                  = errors.New("application route handler close failed")
	ErrHandlerDispatch               = errors.New("application route handler dispatch failed")
	ErrStreamBounds                  = errors.New("application route stream bounds exceeded")
	ErrRegistryNotStarted            = errors.New("application route registry not started")
	ErrRegistryStarted               = errors.New("application route registry already started")
	ErrRegistryClosed                = errors.New("application route registry closed")
	ErrUnknownRoute                  = errors.New("application route unknown")
	ErrLiveRouteStateNotSerializable = errors.New("application route live state is not serializable")
)

func ValidateDefinition(definition Definition) error {
	if !validRouteID(definition.ID) || !validRoutePrefix(definition.Prefix) ||
		definition.Limits.MaxRequestHeaderBytes <= 0 ||
		definition.Limits.MaxRequestBodyBytes <= 0 ||
		definition.Limits.MaxResponseHeaderBytes <= 0 ||
		definition.Limits.MaxResponseBodyBytes <= 0 ||
		definition.Limits.MaxEventBytes <= 0 {
		return ErrInvalidRoute
	}
	return nil
}

func ValidateRequestBounds(limits StreamLimits, request Request) error {
	if limits.MaxRequestHeaderBytes <= 0 || limits.MaxRequestBodyBytes <= 0 ||
		request.Metadata.HeaderBytes < 0 || request.Metadata.ContentLength < 0 ||
		request.Metadata.HeaderBytes > limits.MaxRequestHeaderBytes ||
		request.Metadata.ContentLength > limits.MaxRequestBodyBytes {
		return ErrStreamBounds
	}
	return nil
}

func ValidateResponseBounds(limits StreamLimits, response Response) error {
	if limits.MaxResponseHeaderBytes <= 0 || limits.MaxResponseBodyBytes <= 0 || limits.MaxEventBytes <= 0 ||
		response.Metadata.HeaderBytes < 0 || response.Metadata.ContentLength < 0 || response.Metadata.MaxEventBytes < 0 ||
		response.Metadata.HeaderBytes > limits.MaxResponseHeaderBytes ||
		response.Metadata.ContentLength > limits.MaxResponseBodyBytes ||
		response.Metadata.MaxEventBytes > limits.MaxEventBytes {
		return ErrStreamBounds
	}
	return nil
}

func validRouteID(id RouteID) bool {
	value := string(id)
	if len(value) == 0 || len(value) > 128 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	previousHyphen := false
	for _, character := range value {
		if character == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		previousHyphen = false
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validRoutePrefix(prefix string) bool {
	if len(prefix) > 512 ||
		!strings.HasPrefix(prefix, "/.well-known/hal/") ||
		!strings.HasSuffix(prefix, "/") ||
		strings.Contains(prefix, "//") ||
		strings.Contains(prefix, "..") {
		return false
	}
	for _, character := range prefix {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '/' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func (Request) MarshalJSON() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (Request) MarshalText() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (Request) String() string               { return "applicationroute.Request{live}" }
func (Request) GoString() string             { return "applicationroute.Request{live}" }

func (Response) MarshalJSON() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (Response) MarshalText() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (Response) String() string               { return "applicationroute.Response{live}" }
func (Response) GoString() string             { return "applicationroute.Response{live}" }
