package applicationroute

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestL8D2ApplicationRouteRequestTargetAndHeaderContractShape(t *testing.T) {
	targetType := reflect.TypeOf(RequestTarget{})
	if got, want := targetType.NumField(), 3; got != want {
		t.Fatalf("RequestTarget field count = %d, want %d", got, want)
	}
	for index, want := range []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "Authority", typeOf: reflect.TypeOf("")},
		{name: "Path", typeOf: reflect.TypeOf("")},
		{name: "RawQuery", typeOf: reflect.TypeOf("")},
	} {
		field := targetType.Field(index)
		if field.Name != want.name || field.Type != want.typeOf || field.PkgPath != "" {
			t.Errorf("RequestTarget field %d = %s %v exported=%v, want %s string exported", index, field.Name, field.Type, field.PkgPath == "", want.name)
		}
	}

	requestType := reflect.TypeOf(Request{})
	if got, want := requestType.NumField(), 4; got != want {
		t.Fatalf("Request field count = %d, want %d", got, want)
	}
	for index, want := range []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "Metadata", typeOf: reflect.TypeOf(RequestMetadata{})},
		{name: "Target", typeOf: reflect.TypeOf(RequestTarget{})},
		{name: "Headers", typeOf: reflect.TypeOf((*RequestHeaderValues)(nil)).Elem()},
		{name: "Body", typeOf: reflect.TypeOf((*io.Reader)(nil)).Elem()},
	} {
		field := requestType.Field(index)
		if field.Name != want.name || field.Type != want.typeOf {
			t.Errorf("Request field %d = %s %v, want %s %v", index, field.Name, field.Type, want.name, want.typeOf)
		}
	}

	interfaceType := reflect.TypeOf((*RequestHeaderValues)(nil)).Elem()
	for index, want := range []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "CopyValue", typeOf: reflect.TypeOf(func(string, int, []byte) (int, error) { return 0, nil })},
		{name: "Names", typeOf: reflect.TypeOf(func() []string { return nil })},
		{name: "ValueCount", typeOf: reflect.TypeOf(func(string) int { return 0 })},
	} {
		method := interfaceType.Method(index)
		if method.Name != want.name || method.Type != want.typeOf {
			t.Errorf("RequestHeaderValues method %d = %s %v, want %s %v", index, method.Name, method.Type, want.name, want.typeOf)
		}
	}
}

func TestL8D2ApplicationRouteRequestTargetDeniesFormattingAndSerialization(t *testing.T) {
	const rawAuthority = "user:raw-ticket@private.example.test"
	const rawPath = "/.well-known/hal/credential-http/v1/raw-secret"
	target := RequestTarget{Authority: rawAuthority, Path: rawPath, RawQuery: "api-key=raw-ticket"}

	if _, ok := any(target).(json.Marshaler); !ok {
		t.Fatal("RequestTarget does not implement json.Marshaler")
	}
	if _, ok := any(target).(encoding.TextMarshaler); !ok {
		t.Fatal("RequestTarget does not implement encoding.TextMarshaler")
	}
	if _, ok := any(target).(encoding.BinaryMarshaler); !ok {
		t.Fatal("RequestTarget does not implement encoding.BinaryMarshaler")
	}
	if _, ok := any(target).(fmt.Stringer); !ok {
		t.Fatal("RequestTarget does not implement fmt.Stringer")
	}
	if _, ok := any(target).(fmt.GoStringer); !ok {
		t.Fatal("RequestTarget does not implement fmt.GoStringer")
	}
	if _, ok := any(target).(fmt.Formatter); !ok {
		t.Fatal("RequestTarget does not implement fmt.Formatter")
	}
	if _, ok := any(&target).(json.Unmarshaler); !ok {
		t.Fatal("*RequestTarget does not implement json.Unmarshaler")
	}
	if _, ok := any(&target).(encoding.TextUnmarshaler); !ok {
		t.Fatal("*RequestTarget does not implement encoding.TextUnmarshaler")
	}
	if _, ok := any(&target).(encoding.BinaryUnmarshaler); !ok {
		t.Fatal("*RequestTarget does not implement encoding.BinaryUnmarshaler")
	}

	for label, marshal := range map[string]func() ([]byte, error){
		"json":   func() ([]byte, error) { return json.Marshal(target) },
		"text":   target.MarshalText,
		"binary": target.MarshalBinary,
	} {
		payload, err := marshal()
		if len(payload) != 0 || !errors.Is(err, ErrLiveRouteStateNotSerializable) {
			t.Errorf("%s marshal = %q, %v, want empty stable denial", label, payload, err)
		}
	}

	wantTarget := target
	for label, unmarshal := range map[string]func() error{
		"json":   func() error { return target.UnmarshalJSON([]byte(`{"Authority":"changed"}`)) },
		"text":   func() error { return target.UnmarshalText([]byte("changed")) },
		"binary": func() error { return target.UnmarshalBinary([]byte("changed")) },
	} {
		if err := unmarshal(); err != ErrLiveRouteStateNotSerializable {
			t.Errorf("%s unmarshal error = %v, want stable denial", label, err)
		}
		if target != wantTarget {
			t.Fatalf("%s unmarshal changed target", label)
		}
	}

	for _, format := range applicationRoutePoisonFormats() {
		rendered := fmt.Sprintf(format, target)
		if got, want := rendered, "applicationroute.RequestTarget{live}"; got != want {
			t.Errorf("fmt.Sprintf(%q, RequestTarget) = %q, want %q", format, got, want)
		}
		for _, unsafe := range []string{rawAuthority, rawPath, "raw-ticket", "raw-secret", "private.example.test"} {
			if strings.Contains(rendered, unsafe) {
				t.Fatalf("fmt.Sprintf(%q, RequestTarget) exposed live target", format)
			}
		}
	}

	var nilTarget *RequestTarget
	for _, format := range applicationRoutePoisonFormats() {
		if got := fmt.Sprintf(format, nilTarget); got != "<nil>" {
			t.Errorf("fmt.Sprintf(%q, nil *RequestTarget) = %q, want safe nil rendering", format, got)
		}
	}
}

func TestL8D2ApplicationRouteRegistryValidatesTargetBeforeDispatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RequestTarget)
	}{
		{name: "missing authority", mutate: func(target *RequestTarget) { target.Authority = "" }},
		{name: "authority too long", mutate: func(target *RequestTarget) { target.Authority = strings.Repeat("a", 513) }},
		{name: "authority control", mutate: func(target *RequestTarget) { target.Authority = "private.example.test\n" }},
		{name: "authority space", mutate: func(target *RequestTarget) { target.Authority = "private example.test" }},
		{name: "authority userinfo", mutate: func(target *RequestTarget) { target.Authority = "user@private.example.test" }},
		{name: "authority slash", mutate: func(target *RequestTarget) { target.Authority = "private.example.test/path" }},
		{name: "authority backslash", mutate: func(target *RequestTarget) { target.Authority = `private.example.test\\path` }},
		{name: "authority query", mutate: func(target *RequestTarget) { target.Authority = "private.example.test?query" }},
		{name: "authority fragment", mutate: func(target *RequestTarget) { target.Authority = "private.example.test#fragment" }},
		{name: "authority non ascii", mutate: func(target *RequestTarget) { target.Authority = "priváte.example.test" }},
		{name: "missing path", mutate: func(target *RequestTarget) { target.Path = "" }},
		{name: "non origin path", mutate: func(target *RequestTarget) { target.Path = "relative/path" }},
		{name: "path too long", mutate: func(target *RequestTarget) { target.Path = "/" + strings.Repeat("a", 4096) }},
		{name: "path control", mutate: func(target *RequestTarget) { target.Path += "\t" }},
		{name: "path space", mutate: func(target *RequestTarget) { target.Path += " value" }},
		{name: "path backslash", mutate: func(target *RequestTarget) { target.Path += `\\value` }},
		{name: "path query", mutate: func(target *RequestTarget) { target.Path += "?query" }},
		{name: "path fragment", mutate: func(target *RequestTarget) { target.Path += "#fragment" }},
		{name: "path non ascii", mutate: func(target *RequestTarget) { target.Path += "é" }},
		{name: "path malformed percent short", mutate: func(target *RequestTarget) { target.Path += "%A" }},
		{name: "path malformed percent digit", mutate: func(target *RequestTarget) { target.Path += "%G0" }},
		{name: "path lowercase percent", mutate: func(target *RequestTarget) { target.Path += "%a0" }},
		{name: "path lowercase percent second", mutate: func(target *RequestTarget) { target.Path += "%0a" }},
		{name: "query too long", mutate: func(target *RequestTarget) { target.RawQuery = strings.Repeat("a", 4097) }},
		{name: "query leading marker", mutate: func(target *RequestTarget) { target.RawQuery = "?value=1" }},
		{name: "query control", mutate: func(target *RequestTarget) { target.RawQuery = "value=1\r" }},
		{name: "query space", mutate: func(target *RequestTarget) { target.RawQuery = "value=1 2" }},
		{name: "query backslash", mutate: func(target *RequestTarget) { target.RawQuery = `value=1\\2` }},
		{name: "query fragment", mutate: func(target *RequestTarget) { target.RawQuery = "value=1#fragment" }},
		{name: "query non ascii", mutate: func(target *RequestTarget) { target.RawQuery = "value=é" }},
		{name: "query malformed percent", mutate: func(target *RequestTarget) { target.RawQuery = "value=%0" }},
		{name: "query lowercase percent", mutate: func(target *RequestTarget) { target.RawQuery = "value=%0a" }},
		{name: "query lowercase percent first", mutate: func(target *RequestTarget) { target.RawQuery = "value=%a0" }},
		{name: "route prefix mismatch", mutate: func(target *RequestTarget) { target.Path = "/.well-known/hal/other/v1/" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, registry := newStartedL8D2ApplicationRouteRegistry(t)
			request := validL8D2ApplicationRouteRequest()
			tt.mutate(&request.Target)
			response, err := registry.Handle(context.Background(), RouteCredentialHTTPV1, request)
			if response.Body != nil || err != ErrHandlerDispatch {
				t.Fatalf("Handle() = body:%T error:%v, want empty response and exact ErrHandlerDispatch", response.Body, err)
			}
			if got := handler.handleCalls(); got != 0 {
				t.Fatalf("handler calls = %d, want zero", got)
			}
			assertApplicationRouteErrorSafe(t, err)
		})
	}
}

func TestL8D2ApplicationRouteInvalidLegacyRequestReturnsBeforeBlockingHandler(t *testing.T) {
	handler := newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	handler.handleEntered = make(chan struct{})
	handler.handleRelease = make(chan struct{})
	registry, err := NewRegistry(handler)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		close(handler.handleRelease)
		if err := registry.Close(context.Background()); err != nil {
			t.Errorf("Registry.Close() error = %v", err)
		}
	})

	response, err := registry.Handle(context.Background(), RouteCredentialHTTPV1, Request{
		Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", ContentLength: 2},
		Body:     strings.NewReader("{}"),
	})
	if response.Body != nil || err != ErrHandlerDispatch {
		t.Fatalf("Handle(legacy request) = body:%T error:%v, want empty response and exact ErrHandlerDispatch", response.Body, err)
	}
	select {
	case <-handler.handleEntered:
		t.Fatal("invalid legacy request entered the blocking handler")
	default:
	}
}

func TestL8D2ApplicationRouteRegistryValidatesHeaderSnapshotBeforeDispatch(t *testing.T) {
	typedNil := (*l8D2RouteHeaderValues)(nil)
	tests := []struct {
		name    string
		headers RequestHeaderValues
	}{
		{name: "nil", headers: nil},
		{name: "typed nil", headers: typedNil},
		{name: "too many names", headers: newL8D2RouteHeaderValues(append([]string{"a"}, makeL8D2HeaderNames(128)...))},
		{name: "unsorted", headers: newL8D2RouteHeaderValues([]string{"z", "a"})},
		{name: "duplicate", headers: newL8D2RouteHeaderValues([]string{"a", "a"})},
		{name: "empty name", headers: newL8D2RouteHeaderValues([]string{""})},
		{name: "long name", headers: newL8D2RouteHeaderValues([]string{strings.Repeat("a", 257)})},
		{name: "uppercase name", headers: newL8D2RouteHeaderValues([]string{"Api-Key"})},
		{name: "invalid name punctuation", headers: newL8D2RouteHeaderValues([]string{"api:key"})},
		{name: "zero count", headers: &l8D2RouteHeaderValues{names: []string{"api-key"}, counts: map[string]int{"api-key": 0}}},
		{name: "negative count", headers: &l8D2RouteHeaderValues{names: []string{"api-key"}, counts: map[string]int{"api-key": -1}}},
		{name: "changed names", headers: &l8D2RouteHeaderValues{names: []string{"api-key"}, counts: map[string]int{"api-key": 1}, changeNames: true}},
		{name: "aliased names", headers: &l8D2RouteHeaderValues{names: []string{"api-key"}, counts: map[string]int{"api-key": 1}, aliasNames: true}},
		{name: "changed count", headers: &l8D2RouteHeaderValues{names: []string{"api-key"}, counts: map[string]int{"api-key": 1}, changeCount: true}},
		{name: "names panic", headers: &l8D2RouteHeaderValues{panicNames: true}},
		{name: "count panic", headers: &l8D2RouteHeaderValues{names: []string{"api-key"}, counts: map[string]int{"api-key": 1}, panicCount: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, registry := newStartedL8D2ApplicationRouteRegistry(t)
			request := validL8D2ApplicationRouteRequest()
			request.Headers = tt.headers
			response, err := registry.Handle(context.Background(), RouteCredentialHTTPV1, request)
			if response.Body != nil || err != ErrHandlerDispatch {
				t.Fatalf("Handle() = body:%T error:%v, want empty response and exact ErrHandlerDispatch", response.Body, err)
			}
			if got := handler.handleCalls(); got != 0 {
				t.Fatalf("handler calls = %d, want zero", got)
			}
			assertApplicationRouteErrorSafe(t, err)
		})
	}
}

func TestL8D2ApplicationRouteRegistryAcceptsExactBoundaryAndDoesNotCopyHeaderValues(t *testing.T) {
	handler, registry := newStartedL8D2ApplicationRouteRegistry(t)
	headers := newL8D2RouteHeaderValues([]string{"api-key", "x`trace", strings.Repeat("z", 256)})
	request := validL8D2ApplicationRouteRequest()
	request.Target.Authority = strings.Repeat("a", 512)
	request.Target.Path = CredentialHTTPV1Prefix + strings.Repeat("a", 4096-len(CredentialHTTPV1Prefix)-3) + "%AF"
	request.Target.RawQuery = strings.Repeat("b", 4093) + "%0F"
	request.Headers = headers

	response, err := registry.Handle(context.Background(), RouteCredentialHTTPV1, request)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("response Body.Close() error = %v", closeErr)
		}
	}
	if got := handler.handleCalls(); got != 1 {
		t.Fatalf("handler calls = %d, want one", got)
	}
	if headers.namesCalls != 2 {
		t.Errorf("Names calls = %d, want two", headers.namesCalls)
	}
	for _, name := range headers.names {
		if got := headers.countCalls[name]; got != 2 {
			t.Errorf("ValueCount(%q) calls = %d, want two", name, got)
		}
	}
	if headers.copyCalls != 0 {
		t.Errorf("CopyValue calls = %d, want zero", headers.copyCalls)
	}
}

func TestL8D2ApplicationRouteRequestFormattingDoesNotInspectTargetHeadersOrBody(t *testing.T) {
	headers := &l8D2RouteHeaderValues{panicNames: true}
	body := &poisonApplicationRouteBody{raw: "raw-body private.example.test"}
	request := Request{
		Metadata: RequestMetadata{Method: "POST"},
		Target: RequestTarget{
			Authority: "raw-authority.private.example.test",
			Path:      "/raw-secret",
			RawQuery:  "api-key=raw-ticket",
		},
		Headers: headers,
		Body:    body,
	}
	for _, format := range applicationRoutePoisonFormats() {
		if got, want := fmt.Sprintf(format, request), "applicationroute.Request{live}"; got != want {
			t.Errorf("fmt.Sprintf(%q, Request) = %q, want %q", format, got, want)
		}
	}
	if headers.namesCalls != 0 || body.invoked {
		t.Fatal("Request formatting inspected a live target, header accessor, or body")
	}
}

func newStartedL8D2ApplicationRouteRegistry(t *testing.T) (*fakeApplicationRouteHandler, *Registry) {
	t.Helper()
	handler := newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	registry, err := NewRegistry(handler)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := registry.Close(context.Background()); err != nil {
			t.Errorf("Registry.Close() error = %v", err)
		}
	})
	return handler, registry
}

func validL8D2ApplicationRouteRequest() Request {
	return Request{
		Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", HeaderBytes: 64, ContentLength: 2},
		Target: RequestTarget{
			Authority: "runtime.invalid:443",
			Path:      CredentialHTTPV1Prefix + "resource",
			RawQuery:  "version=1",
		},
		Headers: newL8D2RouteHeaderValues([]string{"api-key"}),
		Body:    strings.NewReader("{}"),
	}
}

func makeL8D2HeaderNames(count int) []string {
	names := make([]string, count)
	for index := range names {
		names[index] = fmt.Sprintf("x-%03d", index)
	}
	return names
}

type l8D2RouteHeaderValues struct {
	names       []string
	counts      map[string]int
	namesCalls  int
	countCalls  map[string]int
	copyCalls   int
	aliasNames  bool
	changeNames bool
	changeCount bool
	panicNames  bool
	panicCount  bool
}

var _ RequestHeaderValues = (*l8D2RouteHeaderValues)(nil)

func newL8D2RouteHeaderValues(names []string) *l8D2RouteHeaderValues {
	counts := make(map[string]int, len(names))
	for _, name := range names {
		counts[name] = 1
	}
	return &l8D2RouteHeaderValues{names: append([]string(nil), names...), counts: counts}
}

func (headers *l8D2RouteHeaderValues) Names() []string {
	if headers == nil || headers.panicNames {
		panic("raw header names must not cross the application-route boundary")
	}
	headers.namesCalls++
	if headers.changeNames && headers.namesCalls > 1 {
		return []string{"changed"}
	}
	if headers.aliasNames {
		return headers.names
	}
	return append([]string(nil), headers.names...)
}

func (headers *l8D2RouteHeaderValues) ValueCount(name string) int {
	if headers == nil || headers.panicCount {
		panic("raw header count must not cross the application-route boundary")
	}
	if headers.countCalls == nil {
		headers.countCalls = make(map[string]int)
	}
	headers.countCalls[name]++
	count := headers.counts[name]
	if headers.changeCount && headers.countCalls[name] > 1 {
		return count + 1
	}
	return count
}

func (headers *l8D2RouteHeaderValues) CopyValue(string, int, []byte) (int, error) {
	headers.copyCalls++
	panic("Registry must not copy a header value")
}

func TestL8D2ApplicationRouteHeaderFakeCopyValueIsAllOrErrorAndWipesFailure(t *testing.T) {
	// D2 has no concrete header implementation: L6/D3 owns it. This fixture
	// documents the exact interface behavior later implementations must satisfy.
	headers := &l8D2ConformingCopyHeader{value: []byte("ticket")}
	destination := make([]byte, len(headers.value))
	count, err := headers.CopyValue("api-key", 0, destination)
	if err != nil || count != len(destination) || string(destination) != "ticket" {
		t.Fatalf("CopyValue(success) = %d, %v, %q", count, err, destination)
	}
	destination = []byte("seeded")
	count, err = headers.CopyValue("api-key", 1, destination)
	if count != 0 || !errors.Is(err, errL8D2HeaderCopy) {
		t.Fatalf("CopyValue(failure) = %d, %v, want zero and fixture error", count, err)
	}
	if string(destination) != strings.Repeat("\x00", len(destination)) {
		t.Fatalf("CopyValue(failure) destination = %v, want full wipe", destination)
	}
}

var errL8D2HeaderCopy = errors.New("header copy rejected")

type l8D2ConformingCopyHeader struct{ value []byte }

func (*l8D2ConformingCopyHeader) Names() []string { return []string{"api-key"} }
func (*l8D2ConformingCopyHeader) ValueCount(name string) int {
	if name == "api-key" {
		return 1
	}
	return 0
}
func (headers *l8D2ConformingCopyHeader) CopyValue(name string, index int, destination []byte) (int, error) {
	if name != "api-key" || index != 0 || len(destination) < len(headers.value) {
		clear(destination)
		return 0, errL8D2HeaderCopy
	}
	copy(destination, headers.value)
	return len(headers.value), nil
}
