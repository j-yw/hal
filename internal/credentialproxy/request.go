package credentialproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute"
)

func validateAzureResponsesRequest(request applicationroute.Request, localAuthority string, definition ServiceDefinition) ([]byte, error) {
	limits := definition.Limits()
	if request.Metadata.Method != "POST" || request.Metadata.ContentType != "application/json" ||
		request.Metadata.HeaderBytes < 0 || request.Metadata.HeaderBytes > limits.MaxRequestHeaderBytes ||
		request.Metadata.ContentLength <= 0 || request.Metadata.ContentLength > limits.MaxRequestBodyBytes ||
		request.Target.Authority != localAuthority || request.Target.Path != localAzureResponsesPath(definition) ||
		request.Target.RawQuery != definition.QueryKey()+"="+definition.SealedAPIVersion() ||
		request.Headers == nil || typedNil(request.Headers) || request.Body == nil {
		return nil, ErrRouteRequestRejected
	}
	if err := validateAzureResponsesHeaders(request.Headers, definition); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, limits.MaxRequestBodyBytes+1))
	if err != nil || int64(len(body)) != request.Metadata.ContentLength || int64(len(body)) > limits.MaxRequestBodyBytes {
		wipeBytes(body)
		return nil, ErrRouteRequestRejected
	}
	if err := validateAzureResponsesJSONModel(body, definition.SealedDeployment()); err != nil {
		wipeBytes(body)
		return nil, ErrRouteRequestRejected
	}
	return body, nil
}

func validateAzureResponsesHeaders(headers applicationroute.RequestHeaderValues, definition ServiceDefinition) (result error) {
	defer func() {
		if recover() != nil {
			result = ErrRouteRequestRejected
		}
	}()
	names, ok := requestHeaderNames(headers)
	if !ok || len(names) == 0 || len(names) > 128 {
		return ErrRouteRequestRejected
	}
	seenTicket := false
	seenContentType := false
	previous := ""
	for _, name := range names {
		count, countOK := requestHeaderValueCount(headers, name)
		if name <= previous || !countOK || count != 1 {
			return ErrRouteRequestRejected
		}
		previous = name
		switch name {
		case definition.TicketHeader():
			seenTicket = true
		case "content-type":
			value, err := copySafeHeaderValue(headers, name, 64)
			if err != nil || !bytes.Equal(value, []byte("application/json")) {
				wipeBytes(value)
				return ErrRouteRequestRejected
			}
			wipeBytes(value)
			seenContentType = true
		case "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "cookie", "set-cookie",
			"connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "host", "expect":
			return ErrRouteRequestRejected
		default:
			if !allowedAzureResponsesMetadataHeader(name) {
				return ErrRouteRequestRejected
			}
		}
	}
	if !seenTicket || !seenContentType {
		return ErrRouteRequestRejected
	}
	return nil
}

func allowedAzureResponsesMetadataHeader(name string) bool {
	return name == "accept" || name == "user-agent" || strings.HasPrefix(name, "x-stainless-")
}

func localAzureResponsesPath(definition ServiceDefinition) string {
	return applicationroute.CredentialHTTPV1Prefix + string(definition.ServiceID()) +
		"/deployments/" + definition.SealedDeployment() + "/responses"
}

func validateAzureResponsesJSONModel(body []byte, expected string) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrRouteRequestRejected
	}
	seen := make(map[string]bool)
	modelFound := false
	for decoder.More() {
		nameToken, err := decoder.Token()
		name, ok := nameToken.(string)
		if err != nil || !ok || seen[name] {
			return ErrRouteRequestRejected
		}
		seen[name] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return ErrRouteRequestRejected
		}
		if name == "model" {
			var model string
			if json.Unmarshal(raw, &model) != nil || model != expected {
				return ErrRouteRequestRejected
			}
			modelFound = true
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || !modelFound {
		return ErrRouteRequestRejected
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrRouteRequestRejected
	}
	return nil
}
