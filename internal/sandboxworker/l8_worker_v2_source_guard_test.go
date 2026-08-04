package sandboxworker

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestL8WorkerV2SourceGuardsKeepV1JobPayloadsCredentialFree(t *testing.T) {
	jobSource := l8ReadWorkerSource(t, "job_types.go")
	for _, marker := range []string{
		"JobContractVersionV2",
		"JobStartRequestV2",
		"JobCredentialIntentV2",
		"productionCredentialsRequested",
		"admissionGrantId",
		"sourceReferenceIds",
	} {
		if strings.Contains(jobSource, marker) {
			t.Fatalf("v1 job_types.go contains v2 marker %q", marker)
		}
	}

	envelopeSource := l8ReadWorkerSource(t, "types.go")
	for _, marker := range []string{
		"productionCredentialsRequested",
		"admissionGrantId",
		"admissionGrantRevision",
		"sourceReferenceIds",
		"authenticatedPrincipal",
	} {
		if strings.Contains(envelopeSource, marker) {
			t.Fatalf("outer envelope source contains inline credential field %q; v2 payloads must remain distinct", marker)
		}
	}
}

func TestL8WorkerV2SourceGuardsRejectSecretAndLiveAuthoritySurfaces(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		matched, matchErr := build.Default.MatchFile(".", path)
		if matchErr != nil {
			t.Fatalf("match production file %s: %v", path, matchErr)
		}
		if !matched {
			continue
		}
		sources[path] = l8ReadWorkerSource(t, path)
	}
	if err := l8AuditWorkerV2Sources(sources, l8WorkerV2ProductionGuardPolicy()); err != nil {
		t.Fatal(err)
	}
}

func TestL8WorkerV2GuardAddingD1CDeclarationsPreservesRealV1Production(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		matched, matchErr := build.Default.MatchFile(".", path)
		if matchErr != nil {
			t.Fatalf("match production file %s: %v", path, matchErr)
		}
		if matched {
			sources[path] = l8ReadWorkerSource(t, path)
		}
	}
	l8WorkerV2AddD1CDeclarationFixture(sources)

	if err := l8AuditWorkerV2Sources(sources, l8WorkerV2ProductionGuardPolicy()); err != nil {
		t.Fatalf("guard rejected unchanged real V1 production after adding an allowed D1C declaration: %v", err)
	}
}

func TestL8WorkerV2GuardDeclarationFixturePreservesExistingV2Types(t *testing.T) {
	sources := map[string]string{
		"job_v2_types.go": `package sandboxworker
type JobStartRequestV2 struct{}
type JobV2 struct{ ID string }`,
	}
	l8WorkerV2AddD1CDeclarationFixture(sources)
	if !strings.Contains(sources["job_v2_types.go"], "type JobV2 struct") {
		t.Fatal("D1C declaration fixture replaced existing V2 production declarations")
	}
}

func l8WorkerV2AddD1CDeclarationFixture(sources map[string]string) {
	if _, exists := sources["job_v2_types.go"]; exists {
		return
	}
	sources["job_v2_types.go"] = `package sandboxworker
type JobStartRequestV2 struct{}`
}

func TestL8WorkerV2GuardAllowsExactExistingClientTransportSeam(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		matched, matchErr := build.Default.MatchFile(".", path)
		if matchErr != nil {
			t.Fatalf("match production file %s: %v", path, matchErr)
		}
		if matched {
			sources[path] = l8ReadWorkerSource(t, path)
		}
	}
	l8WorkerV2AddExactClientTransportSeamFixture(t, sources)
	l8AssertWorkerV2GuardAllows(t, sources, l8WorkerV2ProductionGuardPolicy())

	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import "context"
type Request struct{}
type Response struct{}
type arbitraryTransport interface {
	RoundTrip(context.Context, Request) (Response, error)
}
func JobStartV2Fixture(ctx context.Context, transport arbitraryTransport, request Request) {
	_, _ = transport.RoundTrip(ctx, request)
}`,
	}, policy, "interface dispatch")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobResolveV2Fixture(callback func()) { callback() }`,
	}, policy, "function-value dispatch")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"types.go": `package sandboxworker
import processapi "os"
type JobStartRequestV2 struct{}
type Request struct{}
func (Request) Validate() error {
	forbiddenCompatibilityHelper()
	return nil
}
func forbiddenCompatibilityHelper() { processapi.Exit(1) }
func JobStartV2Fixture(request Request) { _ = request.Validate() }`,
	}, l8WorkerV2GuardPolicy{mixed: map[string]bool{"types.go": true}}, "os.Exit")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"types.go": `package sandboxworker
import processapi "os"
type JobStartRequestV2 struct{}
type Request struct{ JobStartV2 *JobStartRequestV2 }
func (request Request) Validate() error {
	if request.JobStartV2 != nil {
		processapi.Exit(1)
	}
	return nil
}`,
	}, l8WorkerV2GuardPolicy{mixed: map[string]bool{"types.go": true}}, "os.Exit")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_types.go": `package sandboxworker
type JobStartRequestV2 struct{ Exec ExecRequest }
func (request JobStartRequestV2) Validate() error { return request.Exec.Validate() }`,
		"exec.go": `package sandboxworker
import processapi "os"
type ExecRequest struct{}
func (ExecRequest) Validate() error {
	processapi.Exit(1)
	return nil
}`,
	}, l8WorkerV2ProductionGuardPolicy(), "outside the exact allowlist")
}

func TestL8WorkerV2GuardClientTransportFixturePreservesExistingV2Production(t *testing.T) {
	sources := map[string]string{
		"types.go": `package sandboxworker
type Request struct {
	JobStartV2   *JobStartRequestV2   ` + "`json:\"jobStartV2,omitempty\"`" + `
	JobResolveV2 *JobResolveRequestV2 ` + "`json:\"jobResolveV2,omitempty\"`" + `
	JobStatusV2  *JobStatusRequestV2  ` + "`json:\"jobStatusV2,omitempty\"`" + `
	JobLogsV2    *JobLogsRequestV2    ` + "`json:\"jobLogsV2,omitempty\"`" + `
	JobCancelV2  *JobCancelRequestV2  ` + "`json:\"jobCancelV2,omitempty\"`" + `
}
type Response struct {
	JobV2     *JobV2             ` + "`json:\"jobV2,omitempty\"`" + `
	JobLogsV2 *JobLogsResponseV2 ` + "`json:\"jobLogsV2,omitempty\"`" + `
}`,
		"job_v2_types.go":  "package sandboxworker\ntype JobStartRequestV2 struct{}\ntype JobV2 struct{}",
		"job_v2_client.go": "package sandboxworker\nconst existingV2Client = true",
	}
	wantTypes, wantClient := sources["job_v2_types.go"], sources["job_v2_client.go"]
	l8WorkerV2AddExactClientTransportSeamFixture(t, sources)
	if sources["job_v2_types.go"] != wantTypes || sources["job_v2_client.go"] != wantClient {
		t.Fatal("client transport fixture replaced existing V2 production files")
	}
}

func TestL8WorkerV2GuardClientTransportFixtureIgnoresMarkerSpoofing(t *testing.T) {
	sources := map[string]string{
		"types.go": `package sandboxworker
// *JobStartRequestV2 *JobResolveRequestV2 *JobStatusRequestV2
// *JobLogsRequestV2 *JobCancelRequestV2 *JobV2 *JobLogsResponseV2
type Request struct {
	JobCancel       *JobCancelRequest  ` + "`json:\"jobCancel,omitempty\"`" + `
}
type Response struct {
	Error           *Error           ` + "`json:\"error,omitempty\"`" + `
}`,
	}
	l8WorkerV2AddExactClientTransportSeamFixture(t, sources)
	_, complete, err := l8WorkerV2OuterEnvelopeFixtureState(sources["types.go"])
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("comment markers suppressed the exact V2 envelope fixture")
	}
}

func TestL8WorkerV2GuardOuterEnvelopeFixtureStateRejectsWrongFields(t *testing.T) {
	source := `package sandboxworker
const markerSpoof = "*JobResolveRequestV2 *JobStatusRequestV2 *JobLogsRequestV2 *JobCancelRequestV2 *JobV2 *JobLogsResponseV2"
type Request struct {
	WrongName *JobStartRequestV2 ` + "`json:\"jobStartV2,omitempty\"`" + `
}
type Response struct{}`
	hasV2, complete, err := l8WorkerV2OuterEnvelopeFixtureState(source)
	if err != nil {
		t.Fatal(err)
	}
	if !hasV2 || complete {
		t.Fatalf("wrong V2 envelope field state = hasV2 %t complete %t, want partial", hasV2, complete)
	}
}

func l8WorkerV2OuterEnvelopeFixtureState(source string) (bool, bool, error) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "types.go", source, 0)
	if err != nil {
		return false, false, err
	}
	required := map[string]bool{
		`Request|JobStartV2|*JobStartRequestV2|json:"jobStartV2,omitempty"`:       false,
		`Request|JobResolveV2|*JobResolveRequestV2|json:"jobResolveV2,omitempty"`: false,
		`Request|JobStatusV2|*JobStatusRequestV2|json:"jobStatusV2,omitempty"`:    false,
		`Request|JobLogsV2|*JobLogsRequestV2|json:"jobLogsV2,omitempty"`:          false,
		`Request|JobCancelV2|*JobCancelRequestV2|json:"jobCancelV2,omitempty"`:    false,
		`Response|JobV2|*JobV2|json:"jobV2,omitempty"`:                            false,
		`Response|JobLogsV2|*JobLogsResponseV2|json:"jobLogsV2,omitempty"`:        false,
	}
	hasV2 := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || (typeSpec.Name.Name != "Request" && typeSpec.Name.Name != "Response") {
			return true
		}
		structure, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structure.Fields.List {
			if len(field.Names) != 1 {
				continue
			}
			var typeSource bytes.Buffer
			if renderErr := format.Node(&typeSource, fileSet, field.Type); renderErr != nil {
				err = renderErr
				return false
			}
			tag := ""
			if field.Tag != nil {
				tag, err = strconv.Unquote(field.Tag.Value)
				if err != nil {
					return false
				}
			}
			name, typ := field.Names[0].Name, typeSource.String()
			if strings.HasSuffix(name, "V2") || strings.HasSuffix(typ, "V2") || strings.Contains(tag, "V2") {
				hasV2 = true
			}
			key := typeSpec.Name.Name + "|" + name + "|" + typ + "|" + tag
			if _, expected := required[key]; expected {
				required[key] = true
			}
		}
		return false
	})
	if err != nil {
		return false, false, err
	}
	for _, found := range required {
		if !found {
			return hasV2, false, nil
		}
	}
	return true, true, nil
}

func l8WorkerV2AddExactClientTransportSeamFixture(t *testing.T, sources map[string]string) {
	t.Helper()
	hasV2Fields, completeV2Fields, err := l8WorkerV2OuterEnvelopeFixtureState(sources["types.go"])
	if err != nil {
		t.Fatalf("inspect real outer envelope fixture: %v", err)
	}
	if !completeV2Fields {
		_, hasV2Types := sources["job_v2_types.go"]
		_, hasV2Client := sources["job_v2_client.go"]
		if hasV2Fields || hasV2Types || hasV2Client {
			t.Fatal("real V2 outer envelope is partial")
		}
		requestTail := "\tJobCancel       *JobCancelRequest  `json:\"jobCancel,omitempty\"`\n}"
		if !strings.Contains(sources["types.go"], requestTail) {
			t.Fatal("real Request envelope shape changed; update the exact V2 field fixture")
		}
		sources["types.go"] = strings.Replace(sources["types.go"], requestTail, "\tJobCancel       *JobCancelRequest    `json:\"jobCancel,omitempty\"`\n\tJobStartV2      *JobStartRequestV2   `json:\"jobStartV2,omitempty\"`\n\tJobResolveV2    *JobResolveRequestV2 `json:\"jobResolveV2,omitempty\"`\n\tJobStatusV2     *JobStatusRequestV2  `json:\"jobStatusV2,omitempty\"`\n\tJobLogsV2       *JobLogsRequestV2    `json:\"jobLogsV2,omitempty\"`\n\tJobCancelV2     *JobCancelRequestV2  `json:\"jobCancelV2,omitempty\"`\n}", 1)
		responseTail := "\tError           *Error           `json:\"error,omitempty\"`\n}"
		if !strings.Contains(sources["types.go"], responseTail) {
			t.Fatal("real Response envelope shape changed; update the exact V2 field fixture")
		}
		sources["types.go"] = strings.Replace(sources["types.go"], responseTail, "\tError           *Error              `json:\"error,omitempty\"`\n\tJobV2           *JobV2              `json:\"jobV2,omitempty\"`\n\tJobLogsV2       *JobLogsResponseV2  `json:\"jobLogsV2,omitempty\"`\n}", 1)
		_, completeV2Fields, err = l8WorkerV2OuterEnvelopeFixtureState(sources["types.go"])
		if err != nil || !completeV2Fields {
			t.Fatalf("synthesize exact V2 outer envelope fixture: complete=%t err=%v", completeV2Fields, err)
		}
	}
	if _, exists := sources["job_v2_types.go"]; !exists {
		sources["job_v2_types.go"] = `package sandboxworker
type JobStartRequestV2 struct{ Exec ExecRequest }
func (request JobStartRequestV2) Validate() error { return request.Exec.Validate() }
type JobResolveRequestV2 struct{}
type JobStatusRequestV2 struct{}
type JobLogsRequestV2 struct{}
type JobCancelRequestV2 struct{}
type JobLogsResponseV2 struct{}
type JobV2 struct{ ID string }`
	}
	if _, exists := sources["job_v2_client.go"]; !exists {
		sources["job_v2_client.go"] = `package sandboxworker
import "context"
func (client *Client) roundTripV2(ctx context.Context, request Request) (Response, error) {
	return client.roundTrip(ctx, request)
}`
	}
}

func TestL8WorkerV2GuardAllowsExactBoundedStrictDecoderSeam(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"protocol_decode.go": true}}
	requestDecoderSource := `package sandboxworker
	import (
		"bytes"
		"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Value string }
type Request struct { JobStartV2 *JobStartRequestV2 }
func (Request) Validate() error { return nil }
func validateWorkerJSONPreflightV2(raw string) error {
	if len(raw) == 0 { return errors.New("worker request is empty") }
	return nil
}
func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 { return nil, errors.New("worker JSON limit is invalid") }
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil { return nil, err }
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 { return nil, errors.New("worker JSON exceeds limit") }
		if n == 0 && probeErr == io.EOF { return raw, nil }
		if probeErr != nil { return nil, probeErr }
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil { return err }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("worker request contains trailing JSON")
	}
	return nil
}
`
	l8AssertWorkerV2GuardAllows(t, map[string]string{"protocol_decode.go": requestDecoderSource}, policy)
	methodBoundedReader := strings.Replace(requestDecoderSource,
		"func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {\n\traw, err := readWorkerJSONBoundedV2(reader, maxBytes)",
		"type boundedReaderV2 struct{}\nfunc (boundedReaderV2) readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) { return nil, nil }\nfunc decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {\n\traw, err := (boundedReaderV2{}).readWorkerJSONBoundedV2(reader, maxBytes)", 1)
	if methodBoundedReader == requestDecoderSource {
		t.Fatal("method-shaped bounded reader mutation did not change the positive fixture")
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{"protocol_decode.go": methodBoundedReader}, policy, "implicit interface callback")
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"protocol_decode.go": `package sandboxworker
	import (
		"bytes"
		"encoding/json"
	"errors"
	"io"
	"time"
)
type JobV2 struct { ID string }
type Response struct {
	JobV2      *JobV2
	SubmittedAt time.Time
}
func (Response) Validate() error { return nil }
func validateWorkerJSONPreflightV2(raw string) error {
	if len(raw) == 0 { return errors.New("worker response is empty") }
	return nil
}
func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 { return nil, errors.New("worker JSON limit is invalid") }
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil { return nil, err }
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 { return nil, errors.New("worker JSON exceeds limit") }
		if n == 0 && probeErr == io.EOF { return raw, nil }
		if probeErr != nil { return nil, probeErr }
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}
func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil { return err }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("worker response contains trailing JSON")
	}
	return nil
}
const defaultMaxResponseBytes int64 = 1<<20
func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output); err != nil { return Response{}, err }
	return output, nil
}`,
	}, policy)

	for name, source := range map[string]string{
		"decode_before_strictness": `package sandboxworker
import (
	"encoding/json"
	"io"
)
type JobStartRequestV2 struct { Value string }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	if err := decoder.Decode(output); err != nil { return err }
	decoder.DisallowUnknownFields()
	return nil
}`,
		"unreachable_strictness": `package sandboxworker
import (
	"encoding/json"
	"io"
)
type JobStartRequestV2 struct { Value string }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	if err := decoder.Decode(output); err != nil { return err }
	return nil
	decoder.DisallowUnknownFields()
	return nil
}`,
		"extra_decode": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Value string }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	_ = decoder.Decode(&trailing)
	return nil
}`,
		"extra_decode_in_error_return": `package sandboxworker
import (
	"encoding/json"
	"io"
)
type JobStartRequestV2 struct { Value string }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return decoder.Decode(output) }
	return nil
}`,
		"different_output_parameter": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Value string }
func decodeJobStartRequestV2(reader io.Reader, output, replacement *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(replacement); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
		"constructor_reassigns_output": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Value string }
func replaceJobStartV2Output(reader io.Reader, output **JobStartRequestV2) io.Reader {
	*output = &JobStartRequestV2{Value: "replacement"}
	return reader
}
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(replaceJobStartV2Output(reader, &output), 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
		"custom_unmarshal_callback": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Value string }
func (*JobStartRequestV2) UnmarshalJSON([]byte) error { return nil }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
		"nested_custom_unmarshal_callback": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type nestedJobStartV2Value struct { Value string }
func (*nestedJobStartV2Value) UnmarshalJSON([]byte) error { return nil }
type JobStartRequestV2 struct { Nested nestedJobStartV2Value }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
		"nested_text_unmarshal_callback": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type nestedJobStartV2Label string
func (*nestedJobStartV2Label) UnmarshalText([]byte) error { return nil }
type JobStartRequestV2 struct { Labels []nestedJobStartV2Label }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
		"nested_interface_callback": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Dynamic any }
func decodeJobStartRequestV2(reader io.Reader, output *JobStartRequestV2) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
	} {
		t.Run(name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{"protocol_decode.go": source}, policy, "implicit interface callback")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"protocol_decode.go": `package sandboxworker
import formatting "fmt"
type callbackRenderer struct{}
func (callbackRenderer) String() string { return "" }
func decodeJobResolveV2() { _ = formatting.Sprint(callbackRenderer{}) }`,
	}, policy, "implicit interface callback")
}

func TestL8WorkerV2GuardLocksExactDecoderCallerComposition(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{
			"job_store_v2.go":    true,
			"protocol_decode.go": true,
		},
		mixed: map[string]bool{
			"client.go": true,
			"server.go": true,
			"types.go":  true,
		},
	}
	sources := map[string]string{
		"types.go": `package sandboxworker
type JobStartRequestV2 struct{}
type JobV2 struct{}
type callerNestedValue struct { Value string }
type Request struct { Operation string; JobStartV2 *JobStartRequestV2; Nested *callerNestedValue }
type Response struct { JobV2 *JobV2; Nested *callerNestedValue }
type storedJobStateV2 struct { JobV2 JobV2; Nested *callerNestedValue }
func (request Request) WithDefaults() Request { return request }`,
		"protocol_decode.go": `package sandboxworker
import "io"
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error { return nil }
func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error { return nil }
func decodeStoredJobStateV2Into(reader io.Reader, maxBytes int64, output *storedJobStateV2) error { return nil }
func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output); err != nil { return Response{}, err }
	return output, nil
}`,
		"server.go": `package sandboxworker
import "io"
const configuredMaxRequestBytesV2 int64 = 8 << 20
type Server struct { maxRequestBytes int64 }
func configuredServerV2() *Server { return &Server{maxRequestBytes: configuredMaxRequestBytesV2} }
func (server *Server) readRequest(reader io.Reader) (Request, *Response) {
	var request Request
	if err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }
	return request, nil
}`,
		"client.go": `package sandboxworker
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)
const defaultMaxResponseBytes int64 = 1 << 20
type unixSocketClientTransport struct { maxResponseBytes int64 }
type workerResponseConnection interface { io.Reader; io.Writer; Close() error; SetDeadline(time.Time) error }
func openResponseReader() (workerResponseConnection, error) { return nil, nil }
func (transport unixSocketClientTransport) RoundTrip(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	connection, err := openResponseReader()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("open worker connection failed")
	}
	defer connection.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	defer close(done)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request failed")
	}
	halfCloser, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
	if err := halfCloser.CloseWrite(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
	maxResponseBytes := transport.maxResponseBytes
	if maxResponseBytes <= 0 { maxResponseBytes = defaultMaxResponseBytes }
	var response Response
	if err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("read worker response failed")
	}
	return response, nil
}`,
		"job_store_v2.go": `package sandboxworker
import (
	"errors"
	"io"
	"os"
	"path/filepath"
)
const maxStoredJobStateV2Bytes int64 = 64 << 10
type jobStoreV2 struct { root string }
type storedJobReaderV2 interface { io.Reader; Close() error }
func validJobSafeID(value string) bool { return value != "" }
func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	if store == nil || !validJobSafeID(jobID) {
		return nil, errors.New("stored job state is unavailable")
	}
	path := filepath.Join(store.root, jobID+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxStoredJobStateV2Bytes {
		return nil, errors.New("stored job state is unavailable")
	}
	return os.Open(path)
}
func (store *jobStoreV2) load(jobID string) (storedJobStateV2, error) {
	reader, err := store.openStoredJobStateV2(jobID)
	if err != nil { return storedJobStateV2{}, errors.New("stored job state could not be opened") }
	defer reader.Close()
	var state storedJobStateV2
	if err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil { return storedJobStateV2{}, errors.New("stored job state is malformed") }
	return state, nil
}`,
	}
	l8AssertWorkerV2GuardAllows(t, sources, policy)

	validatedServerSources := l8CloneWorkerV2GuardSources(sources)
	validatedServerSources["types.go"] = strings.Replace(validatedServerSources["types.go"],
		"type Request struct { Operation string; JobStartV2 *JobStartRequestV2; Nested *callerNestedValue }",
		"type Request struct { RequestID string; Operation string; JobStartV2 *JobStartRequestV2; Nested *callerNestedValue }", 1)
	validatedServerSources["types.go"] += "\nfunc (request Request) Validate() error { return nil }\n"
	validatedServerSources["server.go"] = `package sandboxworker
import (
	"fmt"
	"io"
)
const configuredMaxRequestBytesV2 int64 = 8 << 20
const OperationProtocolError = "protocol_error"
const ErrorCodeMalformedRequest = "malformed_request"
type Server struct { maxRequestBytes int64 }
func configuredServerV2() *Server { return &Server{maxRequestBytes: configuredMaxRequestBytesV2} }
func protocolErrorResponse(requestID, operation, code, message string) Response { return Response{} }
func (server *Server) readRequest(reader io.Reader) (Request, *Response) {
	var request Request
	if err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil {
		response := protocolErrorResponse("", OperationProtocolError, ErrorCodeMalformedRequest, "malformed worker request")
		return Request{}, &response
	}
	request = request.WithDefaults()
	if err := request.Validate(); err != nil {
		response := protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker request: %v", err))
		return request, &response
	}
	return request, nil
}`
	l8AssertWorkerV2GuardAllows(t, validatedServerSources, policy)

	for _, tt := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{
			name: "validated server substitutes decoder limit",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "decodeWorkerRequestInto(reader, server.maxRequestBytes, &request)", "decodeWorkerRequestInto(reader, configuredMaxRequestBytesV2, &request)", 1)
			},
		},
		{
			name: "validated server skips defaults",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "\trequest = request.WithDefaults()\n", "", 1)
			},
		},
		{
			name: "validated server validates pointer alias",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "request.Validate()", "(&request).Validate()", 1)
			},
		},
		{
			name: "validated server changes validation error format",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "malformed worker request: %v", "worker request validation failed: %v", 1)
			},
		},
		{
			name: "validated server changes validation error code",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "request.Operation, ErrorCodeMalformedRequest, fmt.Sprintf", "request.Operation, OperationProtocolError, fmt.Sprintf", 1)
			},
		},
		{
			name: "validated server uses decoded request ID on decode failure",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "protocolErrorResponse(\"\", OperationProtocolError", "protocolErrorResponse(request.RequestID, OperationProtocolError", 1)
			},
		},
		{
			name: "validated server smuggles decoded request",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] += "\nvar leakedValidatedRequest Request\n"
				mutated["server.go"] = strings.Replace(mutated["server.go"], "\trequest = request.WithDefaults()", "\tleakedValidatedRequest = request\n\trequest = request.WithDefaults()", 1)
			},
		},
		{
			name: "validated server returns before validation",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "\tif err := request.Validate()", "\tif request.RequestID == \"early\" { return request, nil }\n\tif err := request.Validate()", 1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(validatedServerSources)
			tt.mutate(mutated)
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	possiblyReturningHelper := l8CloneWorkerV2GuardSources(sources)
	possiblyReturningHelper["client.go"] = strings.Replace(possiblyReturningHelper["client.go"], "\tvar response Response", `	_ = false && reviewSkippedForeverBool()
	_ = true || reviewSkippedForeverBool()
	defer reviewDeferredForever()
	go reviewDeferredForever()
	_ = reviewReturnsNormally()
	reviewMayReturn(true)
	reviewLoopMayReturn()
	reviewCountdown(1)
	reviewConditionalRecursive(false)
	reviewMutualMayReturnA(false)
	reviewRecoveringRecursiveDecoy(false)
	reviewReturnBeforeRecursion(true)
	reviewConditionalReturnBeforeTerminal(true)
	reviewReachableDeferRecover()
	reviewDeferredRecoverThenPanic()
	_ = func() int { return 1 }()
	_ = (reviewReturningReceiver{}).value()
	reviewReassignedLocal := func() { select {} }
	reviewReassignedLocal = func() {}
	reviewReassignedLocal()
	reviewAddressedLocal := func() { select {} }
	reviewAddressedAlias := &reviewAddressedLocal
	*reviewAddressedAlias = func() {}
	reviewAddressedLocal()
	var reviewCycleA, reviewCycleB func()
	reviewCycleA = reviewCycleB
	reviewCycleB = reviewCycleA
	if reviewCycleA != nil { reviewCycleA() }
	switch true { case true: case reviewSkippedForeverBool(): }
	switch true { case true, reviewSkippedForeverBool(): }
	switch true { case reviewUnknownBool(): case reviewSkippedForeverBool(): }
	reviewNormalAssignment := 0
	reviewNormalAssignment = 1
	_ = reviewNormalAssignment
	var response Response`, 1)
	possiblyReturningHelper["client.go"] += `
func reviewSkippedForeverBool() bool { select {} }
func reviewDeferredForever() { select {} }
func reviewReturnsNormally() int { return 1 }
func reviewMayReturn(shouldReturn bool) { if shouldReturn { return }; select {} }
func reviewLoopMayReturn() { for { break } }
func reviewCountdown(value int) { if value == 0 { return }; reviewCountdown(value-1) }
func reviewConditionalRecursive(recurse bool) { if recurse { reviewConditionalRecursive(false) } }
func reviewMutualMayReturnA(recurse bool) { if recurse { reviewMutualMayReturnB(false) } }
func reviewMutualMayReturnB(recurse bool) { if recurse { reviewMutualMayReturnA(false) } }
func reviewRecoveringRecursiveDecoy(recurse bool) { defer func() { _ = recover() }(); if recurse { reviewRecoveringRecursiveDecoy(false) } }
func reviewReturnBeforeRecursion(stop bool) { if stop { return }; reviewReturnBeforeRecursion(stop) }
func reviewConditionalReturnBeforeTerminal(stop bool) { if stop { return }; select {} }
func reviewReachableDeferRecover() { defer func() { _ = recover() }() }
func reviewDeferredRecoverThenPanic() { defer func() { _ = recover() }(); panic("recovered") }
func reviewUnknownBool() bool { return false }
type reviewReturningReceiver struct{}
func (reviewReturningReceiver) value() int { return 1 }
`
	l8AssertWorkerV2GuardAllows(t, possiblyReturningHelper, policy)
	clientHalfCloseBlock := `	halfCloser, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
	if err := halfCloser.CloseWrite(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
`
	clientEncodeBlock := `	if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request failed")
	}
`
	clientDecodeBlock := `	var response Response
	if err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("read worker response failed")
	}
`
	clientResponseLimitBlock := `	maxResponseBytes := transport.maxResponseBytes
	if maxResponseBytes <= 0 { maxResponseBytes = defaultMaxResponseBytes }
`
	clientHelperEncodeBlock := `	if err := encodeWorkerRequest(connection, request); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request failed")
	}
`
	clientUnsupportedHalfCloseBlock := `	if !ok {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
`
	clientConnectionLifecycleBlock := `	defer connection.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	defer close(done)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
`
	clientContextNormalizationBlock := `	if ctx == nil {
		ctx = context.Background()
	}
`
	clientAcquisitionErrorBlock := `	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("open worker connection failed")
	}
`
	storeAcquisitionErrorBlock := "\tif err != nil { return storedJobStateV2{}, errors.New(\"stored job state could not be opened\") }\n"
	existingJSONWriterSources := l8CloneWorkerV2GuardSources(sources)
	l8AssertWorkerV2GuardAllows(t, existingJSONWriterSources, policy)

	tests := []struct {
		name    string
		path    string
		old     string
		replace string
	}{
		{name: "server hardcoded limit", path: "server.go", old: "server.maxRequestBytes, &request", replace: "int64(1 << 20), &request"},
		{name: "server transformed limit", path: "server.go", old: "server.maxRequestBytes, &request", replace: "server.maxRequestBytes-1, &request"},
		{name: "client pretruncated reader", path: "client.go", old: "decodeWorkerResponseInto(connection, maxResponseBytes, &response)", replace: "decodeWorkerResponseInto(io.LimitReader(connection, maxResponseBytes), maxResponseBytes, &response)"},
		{name: "client hardcoded limit", path: "client.go", old: "connection, maxResponseBytes, &response", replace: "connection, int64(1 << 20), &response"},
		{name: "client transformed limit", path: "client.go", old: "connection, maxResponseBytes, &response", replace: "connection, maxResponseBytes-1, &response"},
		{name: "response wrapper hardcoded limit", path: "protocol_decode.go", old: "reader, defaultMaxResponseBytes, &output", replace: "reader, int64(1 << 20), &output"},
		{name: "response wrapper outer limit", path: "protocol_decode.go", old: "decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output)", replace: "decodeWorkerResponseInto(io.LimitReader(reader, defaultMaxResponseBytes), defaultMaxResponseBytes, &output)"},
		{name: "store hardcoded limit", path: "job_store_v2.go", old: "reader, maxStoredJobStateV2Bytes, &state", replace: "reader, int64(64 << 10), &state"},
		{name: "store transformed limit", path: "job_store_v2.go", old: "reader, maxStoredJobStateV2Bytes, &state", replace: "reader, maxStoredJobStateV2Bytes-1, &state"},
		{name: "store outer limit", path: "job_store_v2.go", old: "decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state)", replace: "decodeStoredJobStateV2Into(io.LimitReader(reader, maxStoredJobStateV2Bytes), maxStoredJobStateV2Bytes, &state)"},
		{name: "wrong store load signature", path: "job_store_v2.go", old: "load(jobID string) (storedJobStateV2, error) {", replace: "load(jobID string, unused bool) (storedJobStateV2, error) {\n\t_ = unused"},
		{name: "response wrapper returns zero", path: "protocol_decode.go", old: "return output, nil", replace: "return Response{}, nil"},
		{name: "response wrapper swallows error", path: "protocol_decode.go", old: "return Response{}, err", replace: "return Response{}, nil"},
		{name: "server outer limit", path: "server.go", old: "decodeWorkerRequestInto(reader, server.maxRequestBytes, &request)", replace: "decodeWorkerRequestInto(io.LimitReader(reader, server.maxRequestBytes), server.maxRequestBytes, &request)"},
		{name: "wrong server signature", path: "server.go", old: "readRequest(reader io.Reader)", replace: "readRequest(reader io.Reader, unused bool)"},
		{name: "wrong server receiver", path: "server.go", old: "func (server *Server) readRequest", replace: "func (server Server) readRequest"},
		{name: "wrong client receiver", path: "client.go", old: "func (transport unixSocketClientTransport) RoundTrip", replace: "func (transport *unixSocketClientTransport) RoundTrip"},
		{name: "wrong client signature", path: "client.go", old: "RoundTrip(ctx context.Context, request Request)", replace: "RoundTrip(ctx context.Context, request Request, unused bool)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	t.Run("store defers cleanup between no-op and duplicate safe acquisition error branches", func(t *testing.T) {
		mutated := l8CloneWorkerV2GuardSources(sources)
		mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], storeAcquisitionErrorBlock, "\tif err != nil { _ = len(\"\") }\n", 1)
		mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()\n", "\tdefer reader.Close()\n"+storeAcquisitionErrorBlock, 1)
		if mutated["job_store_v2.go"] == sources["job_store_v2.go"] {
			t.Fatal("store acquisition error branch mutation did not change the positive fixture")
		}
		l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
	})

	for _, tt := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "client uses alternate acquisition while decoy open is audited",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tconnection, err := openResponseReader()\n", `	alternateConnection, alternateErr := openAlternateResponseReader()
	if alternateErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("open alternate worker connection failed")
	}
	_, err := openResponseReader()
`, 1)
				source = strings.NewReplacer(
					"connection.Close()", "alternateConnection.Close()",
					"connection.SetDeadline", "alternateConnection.SetDeadline",
					"json.NewEncoder(connection)", "json.NewEncoder(alternateConnection)",
					"connection.(interface", "alternateConnection.(interface",
					"decodeWorkerResponseInto(connection", "decodeWorkerResponseInto(alternateConnection",
				).Replace(source)
				return source + "\nfunc openAlternateResponseReader() (workerResponseConnection, error) { return nil, nil }\n"
			},
		},
		{
			name: "client decodes before half-close with later response sentinel",
			mutate: func(source string) string {
				source = strings.Replace(source, clientDecodeBlock, "", 1)
				source = strings.Replace(source, clientResponseLimitBlock, "", 1)
				source = strings.Replace(source, clientHalfCloseBlock, clientResponseLimitBlock+clientDecodeBlock+clientHalfCloseBlock+"\tvar sentinel Response\n\tobserveResponseSentinel(nil, 0, &sentinel)\n", 1)
				return source + "\nfunc observeResponseSentinel(io.Reader, int64, *Response) {}\n"
			},
		},
		{
			name: "client acquisition is unreachable after unconditional error return",
			mutate: func(source string) string {
				return strings.Replace(source, "\tconnection, err := openResponseReader()", "\tif true { return Response{}, errors.New(\"client protocol disabled\") }\n\tconnection, err := openResponseReader()", 1)
			},
		},
		{
			name: "client acquisition is unreachable after terminal with trailing statement",
			mutate: func(source string) string {
				return strings.Replace(source, "\tconnection, err := openResponseReader()", "\tif true {\n\t\treturn Response{}, errors.New(\"client protocol disabled\")\n\t\t_ = request.Operation\n\t}\n\tconnection, err := openResponseReader()", 1)
			},
		},
		{
			name: "client acquisition is unreachable through constant false terminal else",
			mutate: func(source string) string {
				return strings.Replace(source, "\tconnection, err := openResponseReader()", "\tif false {\n\t\t_ = request.Operation\n\t} else {\n\t\treturn Response{}, errors.New(\"client protocol disabled\")\n\t}\n\tconnection, err := openResponseReader()", 1)
			},
		},
		{
			name: "client response decode is unreachable after unconditional error return",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\tif true { return Response{}, errors.New(\"client response decoding disabled\") }\n\tvar response Response", 1)
			},
		},
		{
			name: "client defers cleanup between no-op and duplicate safe acquisition error branches",
			mutate: func(source string) string {
				source = strings.Replace(source, clientAcquisitionErrorBlock, "\tif err != nil {\n\t\t_ = request.Operation\n\t}\n", 1)
				return strings.Replace(source, "\tdefer connection.Close()\n", "\tdefer connection.Close()\n"+clientAcquisitionErrorBlock, 1)
			},
		},
		{
			name: "client response decode is unreachable after default-only switch",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\tswitch {\n\tdefault:\n\t\treturn Response{}, errors.New(\"client response decoding disabled\")\n\t}\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after unconditional loop",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\tfor {}\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after labeled unconditional loop",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "blocked:\n\tfor { continue blocked }\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after builtin panic",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\tpanic(\"client response decoding disabled\")\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after direct nonreturning helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewBlockForever()\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockForever() { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after assigned nonreturning helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tblocked := reviewBlockForeverValue()\n\t_ = blocked\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockForeverValue() int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after if initializer helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tif blocked := reviewBlockForeverIfValue(); blocked > 0 {}\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockForeverIfValue() int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after range operand helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tfor range reviewBlockForeverValues() {}\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockForeverValues() []int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after true and helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\t_ = true && reviewBlockForeverBool()\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockForeverBool() bool { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after false or helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\t_ = false || reviewBlockForeverBool()\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockForeverBool() bool { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after direct recursion",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewRecursiveForever()\n\tvar response Response", 1)
				return source + "\nfunc reviewRecursiveForever() { reviewRecursiveForever() }\n"
			},
		},
		{
			name: "client response decode is unreachable after mutual recursion",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewMutualForeverA()\n\tvar response Response", 1)
				return source + "\nfunc reviewMutualForeverA() { reviewMutualForeverB() }\nfunc reviewMutualForeverB() { reviewMutualForeverA() }\n"
			},
		},
		{
			name: "client response decode is unreachable after defer argument helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tdefer reviewSinkValue(reviewBlockForeverValue())\n\tvar response Response", 1)
				return source + "\nfunc reviewSinkValue(int) {}\nfunc reviewBlockForeverValue() int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after go argument helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tgo reviewSinkValue(reviewBlockForeverValue())\n\tvar response Response", 1)
				return source + "\nfunc reviewSinkValue(int) {}\nfunc reviewBlockForeverValue() int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after return operand helper",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\t_ = reviewReturnBlocks()\n\tvar response Response", 1)
				return source + "\nfunc reviewReturnBlocks() int { return reviewBlockForeverValue() }\nfunc reviewBlockForeverValue() int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after recursion before return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewRecursiveThenReturn()\n\tvar response Response", 1)
				return source + "\nfunc reviewRecursiveThenReturn() { reviewRecursiveThenReturn(); return }\n"
			},
		},
		{
			name: "client response decode is unreachable after mutual recursion before return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewMutualThenReturnA()\n\tvar response Response", 1)
				return source + "\nfunc reviewMutualThenReturnA() { reviewMutualThenReturnB(); return }\nfunc reviewMutualThenReturnB() { reviewMutualThenReturnA(); return }\n"
			},
		},
		{
			name: "client response decode is unreachable after select before return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewSelectThenReturn()\n\tvar response Response", 1)
				return source + "\nfunc reviewSelectThenReturn() { select {}; return }\n"
			},
		},
		{
			name: "client response decode is unreachable after panic before return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewPanicThenReturn()\n\tvar response Response", 1)
				return source + "\nfunc reviewPanicThenReturn() { panic(\"blocked\"); return }\n"
			},
		},
		{
			name: "client response decode is unreachable before defer recover",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewSelectThenDeferRecover()\n\tvar response Response", 1)
				return source + "\nfunc reviewSelectThenDeferRecover() { select {}; defer func() { _ = recover() }() }\n"
			},
		},
		{
			name: "client response decode is unreachable after benign defer before select",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewBenignDeferThenSelect()\n\tvar response Response", 1)
				return source + "\nfunc reviewBenignDeferThenSelect() { defer func() {}(); select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after benign defer before recursion",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewBenignDeferThenRecurse()\n\tvar response Response", 1)
				return source + "\nfunc reviewKnownNoRecover() {}\nfunc reviewBenignDeferThenRecurse() { defer reviewKnownNoRecover(); reviewBenignDeferThenRecurse() }\n"
			},
		},
		{
			name: "client response decode is unreachable after recover defer before select",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewRecoverDeferThenSelect()\n\tvar response Response", 1)
				return source + "\nfunc reviewRecoverDeferThenSelect() { defer func() { _ = recover() }(); select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after recover defer before recursion",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewRecoverDeferThenRecurse()\n\tvar response Response", 1)
				return source + "\nfunc reviewRecoverDeferThenRecurse() { defer func() { _ = recover() }(); reviewRecoverDeferThenRecurse() }\n"
			},
		},
		{
			name: "client response decode is unreachable after ordinary recover before select",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewOrdinaryRecoverThenSelect()\n\tvar response Response", 1)
				return source + "\nfunc reviewOrdinaryRecoverThenSelect() { _ = recover(); select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after goroutine recover before select",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewGoroutineRecoverThenSelect()\n\tvar response Response", 1)
				return source + "\nfunc reviewGoroutineRecoverThenSelect() { go recover(); select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after concrete receiver method",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\t(reviewConcreteBlocker{}).block()\n\tvar response Response", 1)
				return source + "\ntype reviewConcreteBlocker struct{}\nfunc (reviewConcreteBlocker) block() { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after direct iife",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\tfunc() { select {} }()\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after immutable local function",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\treviewLocalBlock := func() { select {} }\n\treviewLocalBlock()\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable when immutable local address is taken before call",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\treviewLocalBlock := func() { select {} }\n\t_ = &reviewLocalBlock\n\treviewLocalBlock()\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable when immutable local address is taken after call",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\treviewLocalBlock := func() { select {} }\n\treviewLocalBlock()\n\t_ = &reviewLocalBlock\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after immutable local function alias chain",
			mutate: func(source string) string {
				return strings.Replace(source, "\tvar response Response", "\treviewLocalBlock := func() { select {} }\n\treviewLocalAlias := reviewLocalBlock\n\treviewLocalAlias2 := reviewLocalAlias\n\treviewLocalAlias2()\n\tvar response Response", 1)
			},
		},
		{
			name: "client response decode is unreachable after immutable package function alias chain",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewPackageBlockAlias2()\n\tvar response Response", 1)
				return source + "\nvar reviewPackageBlock = func() { select {} }\nvar reviewPackageBlockAlias = reviewPackageBlock\nvar reviewPackageBlockAlias2 = reviewPackageBlockAlias\n"
			},
		},
		{
			name: "client response decode is unreachable after first switch case expression",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tswitch true { case reviewSwitchBlocks(): }\n\tvar response Response", 1)
				return source + "\nfunc reviewSwitchBlocks() bool { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after provably nonmatching switch case",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tswitch true { case false: case reviewSwitchBlocks(): }\n\tvar response Response", 1)
				return source + "\nfunc reviewSwitchBlocks() bool { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after provably nonmatching switch list expression",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\tswitch true { case false, reviewSwitchBlocks(): }\n\tvar response Response", 1)
				return source + "\nfunc reviewSwitchBlocks() bool { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after panic with defer recover then select",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewRecoverThenSelectPanic()\n\tvar response Response", 1)
				return source + "\nfunc reviewRecoverThenSelectPanic() { defer func() { _ = recover(); select {} }(); panic(\"blocked\") }\n"
			},
		},
		{
			name: "client response decode is unreachable after panic with defer recover then recurse",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewRecoverThenRecursePanic()\n\tvar response Response", 1)
				return source + "\nfunc reviewRecoverThenRecursePanic() { defer func() { _ = recover(); reviewRecoverThenRecursePanic() }(); panic(\"blocked\") }\n"
			},
		},
		{
			name: "client response decode is unreachable when deferred recovery branch cannot return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewConditionalRecoverThenBlockPanic(false)\n\tvar response Response", 1)
				return source + "\nfunc reviewConditionalRecoverThenBlockPanic(condition bool) { defer func() { if condition { _ = recover(); select {} } }(); panic(\"blocked\") }\n"
			},
		},
		{
			name: "client response decode is unreachable when selected switch branch cannot return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewSelectedSwitchRecoveryDecoyPanic()\n\tvar response Response", 1)
				return source + "\nfunc reviewSelectedSwitchRecoveryDecoyPanic() { defer func() { switch true { case true: select {}; case false: _ = recover() } }(); panic(\"blocked\") }\n"
			},
		},
		{
			name: "client response decode is unreachable when recovering loop path cannot return",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewConditionalLoopRecoveryDecoyPanic(false)\n\tvar response Response", 1)
				return source + "\nfunc reviewConditionalLoopRecoveryDecoyPanic(condition bool) { defer func() { for condition { _ = recover(); select {} } }(); panic(\"blocked\") }\n"
			},
		},
		{
			name: "client response decode is unreachable after panic with deferred goroutine recover",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewDeferredGoRecoverPanic()\n\tvar response Response", 1)
				return source + "\nfunc reviewDeferredGoRecoverPanic() { defer func() { go recover() }(); panic(\"blocked\") }\n"
			},
		},
		{
			name: "client response decode is unreachable after helper switch case expression",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewSwitchThenReturn()\n\tvar response Response", 1)
				return source + "\nfunc reviewSwitchThenReturn() { switch true { case reviewSwitchBlocks(): }; return }\nfunc reviewSwitchBlocks() bool { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after assignment lhs operand",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewBlockingSlice()[0] = 1\n\tvar response Response", 1)
				return source + "\nfunc reviewBlockingSlice() []int { select {} }\n"
			},
		},
		{
			name: "client response decode is unreachable after helper assignment lhs operand",
			mutate: func(source string) string {
				source = strings.Replace(source, "\tvar response Response", "\treviewAssignThenReturn()\n\tvar response Response", 1)
				return source + "\nfunc reviewAssignThenReturn() { reviewBlockingSlice()[0] = 1; return }\nfunc reviewBlockingSlice() []int { select {} }\n"
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["client.go"] = tt.mutate(mutated["client.go"])
			if mutated["client.go"] == sources["client.go"] {
				t.Fatal("client acquisition, framing, or reachability mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		path    string
		old     string
		replace string
	}{
		{
			name:    "server request decode is unreachable after unconditional return",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tif true { return Request{}, &Response{} }\n\tvar request Request",
		},
		{
			name:    "server request decode is unreachable after default-only switch",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tswitch {\n\tdefault:\n\t\treturn Request{}, &Response{}\n\t}\n\tvar request Request",
		},
		{
			name:    "server request decode is unreachable after default-only type switch",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tswitch any(\"\").(type) {\n\tdefault:\n\t\treturn Request{}, &Response{}\n\t}\n\tvar request Request",
		},
		{
			name:    "server request decode is unreachable after nested loop break then terminal switch clause",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tswitch any(\"\").(type) {\n\tdefault:\n\t\tfor { break }\n\t\treturn Request{}, &Response{}\n\t}\n\tvar request Request",
		},
		{
			name:    "store acquisition is unreachable after unconditional error return",
			path:    "job_store_v2.go",
			old:     "\treader, err := store.openStoredJobStateV2(jobID)",
			replace: "\tif true { return storedJobStateV2{}, errors.New(\"stored job loading disabled\") }\n\treader, err := store.openStoredJobStateV2(jobID)",
		},
		{
			name:    "store decode is unreachable after unconditional error return",
			path:    "job_store_v2.go",
			old:     "\tvar state storedJobStateV2",
			replace: "\tif true { return storedJobStateV2{}, errors.New(\"stored job decoding disabled\") }\n\tvar state storedJobStateV2",
		},
		{
			name:    "store decode is unreachable after default-only switch",
			path:    "job_store_v2.go",
			old:     "\tvar state storedJobStateV2",
			replace: "\tswitch {\n\tdefault:\n\t\treturn storedJobStateV2{}, errors.New(\"stored job decoding disabled\")\n\t}\n\tvar state storedJobStateV2",
		},
		{
			name:    "store decode is unreachable after all-terminal select",
			path:    "job_store_v2.go",
			old:     "\tvar state storedJobStateV2",
			replace: "\tselect {\n\tdefault:\n\t\treturn storedJobStateV2{}, errors.New(\"stored job decoding disabled\")\n\t}\n\tvar state storedJobStateV2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if mutated[tt.path] == sources[tt.path] {
				t.Fatalf("%s reachability mutation did not change the positive fixture", tt.path)
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	t.Run("store uses package-level root-blind acquisition with matching name", func(t *testing.T) {
		mutated := l8CloneWorkerV2GuardSources(sources)
		mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "func (store *jobStoreV2) openStoredJobStateV2(jobID string)", "func openStoredJobStateV2(jobID string)", 1)
		mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "store == nil || ", "", 1)
		mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "store.root", "globalJobStoreV2Root", 1)
		mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "store.openStoredJobStateV2(jobID)", "openStoredJobStateV2(jobID)", 1)
		mutated["job_store_v2.go"] += "\nvar globalJobStoreV2Root string\n"
		if mutated["job_store_v2.go"] == sources["job_store_v2.go"] {
			t.Fatal("package-level store acquisition mutation did not change the positive fixture")
		}
		l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
	})

	for _, tt := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "store opens through a different receiver object",
			mutate: func(source string) string {
				return strings.Replace(source, "\treader, err := store.openStoredJobStateV2(jobID)", "\totherStore := store\n\treader, err := otherStore.openStoredJobStateV2(jobID)", 1)
			},
		},
		{
			name: "store opener accepts an extra parameter",
			mutate: func(source string) string {
				source = strings.Replace(source, "openStoredJobStateV2(jobID string)", "openStoredJobStateV2(jobID string, rootOverride string)", 1)
				return strings.Replace(source, "store.openStoredJobStateV2(jobID)", "store.openStoredJobStateV2(jobID, \"\")", 1)
			},
		},
		{
			name: "store opener belongs to a generic receiver",
			mutate: func(source string) string {
				source = strings.Replace(source, "type jobStoreV2 struct { root string }", "type jobStoreV2[T any] struct { root string }", 1)
				source = strings.Replace(source, "func (store *jobStoreV2) openStoredJobStateV2", "func (store *jobStoreV2[T]) openStoredJobStateV2", 1)
				return strings.Replace(source, "func (store *jobStoreV2) load", "func (store *jobStoreV2[T]) load", 1)
			},
		},
		{
			name: "store opener method value escapes before acquisition",
			mutate: func(source string) string {
				source += "\ntype storedJobOpenerV2 func(string) (storedJobReaderV2, error)\nvar escapedStoredJobOpenerV2 storedJobOpenerV2\n"
				return strings.Replace(source, "\treader, err := store.openStoredJobStateV2(jobID)", "\tescapedStoredJobOpenerV2 = store.openStoredJobStateV2\n\treader, err := store.openStoredJobStateV2(jobID)", 1)
			},
		},
		{
			name: "store opener substitutes private worker v2 id vocabulary",
			mutate: func(source string) string {
				source = strings.Replace(source, "validJobSafeID(jobID)", "validWorkerV2SafeID(jobID)", 1)
				return source + "\nfunc validWorkerV2SafeID(value string) bool { return value != \"\" }\n"
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["job_store_v2.go"] = tt.mutate(mutated["job_store_v2.go"])
			if mutated["job_store_v2.go"] == sources["job_store_v2.go"] {
				t.Fatal("store opener mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name        string
		replacement string
		helper      string
	}{
		{
			name: "store opener references receiver but delegates to package global root helper",
			replacement: `func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	_ = store.root
	return openGlobalStoredJobStateV2(jobID)
}`,
			helper: `
var globalJobStoreV2Root string
func openGlobalStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	return os.Open(filepath.Join(globalJobStoreV2Root, jobID+".json"))
}
`,
		},
		{
			name: "store opener delegates receiver root and job identity through package helper",
			replacement: `func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	return openStoredJobStateV2FromRoot(store.root, jobID)
}`,
			helper: `
func openStoredJobStateV2FromRoot(root, jobID string) (storedJobReaderV2, error) {
	return os.Open(filepath.Join(root, jobID+".json"))
}
`,
		},
		{
			name: "store opener replaces receiver root through a package global",
			replacement: `func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	root := store.root
	root = globalJobStoreV2Root
	path := filepath.Join(root, jobID+".json")
	return os.Open(path)
}`,
			helper: "\nvar globalJobStoreV2Root string\n",
		},
		{
			name: "store opener replaces exact job identity",
			replacement: `func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	jobID = "job-neighbor"
	path := filepath.Join(store.root, jobID+".json")
	return os.Open(path)
}`,
		},
		{
			name: "store opener escapes derived path before open",
			replacement: `func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	path := filepath.Join(store.root, jobID+".json")
	escapedStoredJobPathV2 = path
	return os.Open(path)
}`,
			helper: "\nvar escapedStoredJobPathV2 string\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			const safeOpener = `func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	if store == nil || !validJobSafeID(jobID) {
		return nil, errors.New("stored job state is unavailable")
	}
	path := filepath.Join(store.root, jobID+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxStoredJobStateV2Bytes {
		return nil, errors.New("stored job state is unavailable")
	}
	return os.Open(path)
}`
			mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], safeOpener, tt.replacement, 1) + tt.helper
			if mutated["job_store_v2.go"] == sources["job_store_v2.go"] {
				t.Fatal("store opener implementation mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "client normalizes nil context after acquisition",
			mutate: func(source string) string {
				source = strings.Replace(source, clientContextNormalizationBlock, "", 1)
				return strings.Replace(source, "\tconnection, err := openResponseReader()\n", "\tconnection, err := openResponseReader()\n"+clientContextNormalizationBlock, 1)
			},
		},
		{
			name: "client replaces normalized context later",
			mutate: func(source string) string {
				return strings.Replace(source, "\tdefer close(done)\n", "\tdefer close(done)\n\tctx = context.Background()\n", 1)
			},
		},
		{
			name: "client omits nil context normalization",
			mutate: func(source string) string {
				return strings.Replace(source, clientContextNormalizationBlock, "", 1)
			},
		},
		{
			name: "client substitutes non-Background context",
			mutate: func(source string) string {
				return strings.Replace(source, "ctx = context.Background()", "ctx = context.TODO()", 1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["client.go"] = tt.mutate(mutated["client.go"])
			if mutated["client.go"] == sources["client.go"] {
				t.Fatal("client context normalization mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name   string
		mutate func(string) string
	}{
		{name: "missing mandatory half-close", mutate: func(source string) string {
			return strings.Replace(source, clientHalfCloseBlock, "", 1)
		}},
		{name: "half-close before request encode", mutate: func(source string) string {
			source = strings.Replace(source, clientHalfCloseBlock, "", 1)
			return strings.Replace(source, clientEncodeBlock, clientHalfCloseBlock+clientEncodeBlock, 1)
		}},
		{name: "response decode before half-close", mutate: func(source string) string {
			source = strings.Replace(source, clientHalfCloseBlock, "", 1)
			return strings.Replace(source, "\treturn response, nil\n}", clientHalfCloseBlock+"\treturn response, nil\n}", 1)
		}},
		{name: "unsupported half-close check after close", mutate: func(source string) string {
			source = strings.Replace(source, clientUnsupportedHalfCloseBlock, "", 1)
			return strings.Replace(source, "\tmaxResponseBytes := transport.maxResponseBytes", clientUnsupportedHalfCloseBlock+"\tmaxResponseBytes := transport.maxResponseBytes", 1)
		}},
		{name: "unsupported half-close panics", mutate: func(source string) string {
			return strings.Replace(source, "halfCloser, ok := connection.(interface{ CloseWrite() error })\n\tif !ok {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"write worker request framing failed\")\n\t}", "halfCloser := connection.(interface{ CloseWrite() error })", 1)
		}},
		{name: "ignored half-close error", mutate: func(source string) string {
			return strings.Replace(source, "\tif err := halfCloser.CloseWrite(); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"write worker request framing failed\")\n\t}\n", "\t_ = halfCloser.CloseWrite()\n", 1)
		}},
		{name: "half-close twice", mutate: func(source string) string {
			return strings.Replace(source, "\tmaxResponseBytes := transport.maxResponseBytes", "\t_ = halfCloser.CloseWrite()\n\tmaxResponseBytes := transport.maxResponseBytes", 1)
		}},
		{name: "half-close on different acquired object", mutate: func(source string) string {
			return strings.Replace(source, "halfCloser, ok := connection.(interface{ CloseWrite() error })", "otherConnection := connection\n\thalfCloser, ok := otherConnection.(interface{ CloseWrite() error })", 1)
		}},
		{name: "unsupported half-close omits context precedence", mutate: func(source string) string {
			return strings.Replace(source, "\tif !ok {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }", "\tif !ok {", 1)
		}},
		{name: "failed half-close omits context precedence", mutate: func(source string) string {
			return strings.Replace(source, "\tif err := halfCloser.CloseWrite(); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }", "\tif err := halfCloser.CloseWrite(); err != nil {", 1)
		}},
		{name: "failed half-close exposes raw error", mutate: func(source string) string {
			return strings.Replace(source, "\t\treturn Response{}, errors.New(\"write worker request framing failed\")\n\t}\n\tmaxResponseBytes", "\t\treturn Response{}, err\n\t}\n\tmaxResponseBytes", 1)
		}},
		{name: "failed half-close uses variable error text", mutate: func(source string) string {
			return strings.Replace(source, "errors.New(\"write worker request framing failed\")", "errors.New(\"write worker request framing failed: \" + request.Operation)", 2)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["client.go"] = tt.mutate(mutated["client.go"])
			if mutated["client.go"] == sources["client.go"] {
				t.Fatal("client half-close mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "client half-close composition")
		})
	}

	for _, tt := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{
			name: "client omits deferred connection close",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdefer connection.Close()\n", "", 1)
			},
		},
		{
			name: "client cancellation closure omits connection close",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\t\t\t_ = connection.Close()", "\t\t\treturn", 1)
			},
		},
		{
			name: "client cancellation closure consumes connection",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\t\t\t_ = connection.Close()", "\t\t\t_, _ = io.ReadAll(io.LimitReader(connection, 1))", 1)
			},
		},
		{
			name: "client omits deadline propagation",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], clientConnectionLifecycleBlock, strings.Replace(clientConnectionLifecycleBlock, "\tif deadline, ok := ctx.Deadline(); ok {\n\t\t_ = connection.SetDeadline(deadline)\n\t}\n", "", 1), 1)
			},
		},
		{
			name: "store omits deferred reader close",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()\n", "", 1)
			},
		},
		{
			name: "store eagerly closes reader before decode",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()", "\t_ = reader.Close()", 1)
			},
		},
		{
			name: "store defers close on replacement reader",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()", "\treplacementReader, _ := store.openStoredJobStateV2(jobID)\n\tdefer replacementReader.Close()", 1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			tt.mutate(mutated)
			if mutated["client.go"] == sources["client.go"] && mutated["job_store_v2.go"] == sources["job_store_v2.go"] {
				t.Fatal("connection or reader lifecycle mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		path    string
		old     string
		replace string
	}{
		{name: "server decodes throwaway request", path: "server.go", old: "var request Request\n\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request)", replace: "var decoded Request\n\tvar request Request\n\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &decoded)"},
		{name: "client decodes throwaway response", path: "client.go", old: "var response Response\n\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &response)", replace: "var decoded Response\n\tvar response Response\n\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &decoded)"},
		{name: "client uses different acquired reader", path: "client.go", old: "maxResponseBytes := transport.maxResponseBytes", replace: "otherConnection := connection\n\tmaxResponseBytes := transport.maxResponseBytes"},
		{name: "store decodes throwaway state", path: "job_store_v2.go", old: "var state storedJobStateV2\n\tif err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state)", replace: "var decoded storedJobStateV2\n\tvar state storedJobStateV2\n\tif err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &decoded)"},
		{name: "store uses different acquired reader", path: "job_store_v2.go", old: "var state storedJobStateV2", replace: "otherReader := reader\n\tvar state storedJobStateV2"},
		{name: "store opens neighbor identity", path: "job_store_v2.go", old: "store.openStoredJobStateV2(jobID)", replace: "store.openStoredJobStateV2(\"job-neighbor\")"},
		{name: "client reassigns acquired connection", path: "client.go", old: "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {", replace: "\tconnection = rewrapResponseConnection(connection)\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {"},
		{name: "store reassigns acquired reader", path: "job_store_v2.go", old: "\tvar state storedJobStateV2", replace: "\treader = reader\n\tvar state storedJobStateV2"},
		{name: "server resets decoded request", path: "server.go", old: "\treturn request, nil", replace: "\trequest = Request{}\n\treturn request, nil"},
		{name: "client resets decoded response", path: "client.go", old: "\treturn response, nil", replace: "\tresponse = Response{}\n\treturn response, nil"},
		{name: "store resets decoded state", path: "job_store_v2.go", old: "\treturn state, nil", replace: "\tstate = storedJobStateV2{}\n\treturn state, nil"},
		{name: "server adds second nil-error success", path: "server.go", old: "\treturn request, nil", replace: "\tif false { return Request{}, nil }\n\treturn request, nil"},
		{name: "client adds second nil-error success", path: "client.go", old: "\treturn response, nil", replace: "\tif false { return Response{}, nil }\n\treturn response, nil"},
		{name: "store adds second nil-error success", path: "job_store_v2.go", old: "\treturn state, nil", replace: "\tif false { return storedJobStateV2{}, nil }\n\treturn state, nil"},
		{name: "response wrapper resets decoded output", path: "protocol_decode.go", old: "\treturn output, nil", replace: "\toutput = Response{}\n\treturn output, nil"},
		{name: "client exposes raw codec error", path: "client.go", old: "return Response{}, errors.New(\"read worker response failed\")", replace: "return Response{}, err"},
		{name: "client exposes raw connection error", path: "client.go", old: "return Response{}, errors.New(\"open worker connection failed\")", replace: "return Response{}, err"},
		{name: "client exposes raw request encoder error", path: "client.go", old: "return Response{}, errors.New(\"write worker request failed\")", replace: "return Response{}, err"},
		{name: "client connection error omits context precedence", path: "client.go", old: "if err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"open worker connection failed\")", replace: "if err != nil {\n\t\treturn Response{}, errors.New(\"open worker connection failed\")"},
		{name: "client request encoder error omits context precedence", path: "client.go", old: "if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }", replace: "if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {"},
		{name: "client response decoder error omits context precedence", path: "client.go", old: "if err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }", replace: "if err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {"},
		{name: "store exposes raw codec error", path: "job_store_v2.go", old: "return storedJobStateV2{}, errors.New(\"stored job state is malformed\")", replace: "return storedJobStateV2{}, err"},
		{name: "store exposes raw opener error", path: "job_store_v2.go", old: "return storedJobStateV2{}, errors.New(\"stored job state could not be opened\")", replace: "return storedJobStateV2{}, err"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			switch tt.name {
			case "client uses different acquired reader":
				mutated[tt.path] = strings.Replace(mutated[tt.path], "decodeWorkerResponseInto(connection,", "decodeWorkerResponseInto(otherConnection,", 1)
			case "store uses different acquired reader":
				mutated[tt.path] = strings.Replace(mutated[tt.path], "decodeStoredJobStateV2Into(reader,", "decodeStoredJobStateV2Into(otherReader,", 1)
			case "client reassigns acquired connection":
				mutated[tt.path] += "\nfunc rewrapResponseConnection(connection workerResponseConnection) workerResponseConnection { return connection }\n"
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		old     string
		replace string
	}{
		{
			name:    "client resets decoded response through ValueSpec pointer aliases",
			old:     "\treturn response, nil",
			replace: "\tvar responseAlias = &response\n\tvar responseAlias2 = responseAlias\n\t*responseAlias2 = Response{}\n\treturn response, nil",
		},
		{
			name:    "client replaces acquired connection through ValueSpec pointer aliases",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\treplacementConnection, _ := openResponseReader()\n\tvar connectionAlias = &connection\n\tvar connectionAlias2 = connectionAlias\n\t*connectionAlias2 = replacementConnection\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
		{
			name:    "client passes decoded response address to local mutator",
			old:     "\treturn response, nil",
			replace: "\tmutateDecodedResponse(&response)\n\treturn response, nil",
		},
		{
			name:    "client passes acquired connection address to local mutator",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\tmutateAcquiredConnection(&connection)\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["client.go"] = strings.Replace(mutated["client.go"], tt.old, tt.replace, 1)
			switch tt.name {
			case "client passes decoded response address to local mutator":
				mutated["client.go"] += "\nfunc mutateDecodedResponse(response *Response) { *response = Response{} }\n"
			case "client passes acquired connection address to local mutator":
				mutated["client.go"] += "\nfunc mutateAcquiredConnection(connection *workerResponseConnection) { *connection = nil }\n"
			}
			if mutated["client.go"] == sources["client.go"] {
				t.Fatal("extended pointer-alias mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		path    string
		old     string
		replace string
	}{
		{
			name:    "server resets decoded request through pointer aliases",
			path:    "server.go",
			old:     "\treturn request, nil",
			replace: "\trequestAlias := &request\n\trequestAlias2 := requestAlias\n\t*requestAlias2 = Request{}\n\treturn request, nil",
		},
		{
			name:    "client resets decoded response through pointer aliases",
			path:    "client.go",
			old:     "\treturn response, nil",
			replace: "\tresponseAlias := &response\n\tresponseAlias2 := responseAlias\n\t*responseAlias2 = Response{}\n\treturn response, nil",
		},
		{
			name:    "store resets decoded state through pointer aliases",
			path:    "job_store_v2.go",
			old:     "\treturn state, nil",
			replace: "\tstateAlias := &state\n\tstateAlias2 := stateAlias\n\t*stateAlias2 = storedJobStateV2{}\n\treturn state, nil",
		},
		{
			name:    "server replaces configured limit through pointer aliases",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tmaxRequestBytesAlias := &server.maxRequestBytes\n\tmaxRequestBytesAlias2 := maxRequestBytesAlias\n\t*maxRequestBytesAlias2 = 1\n\tvar request Request",
		},
		{
			name:    "client replaces post-default limit through pointer aliases",
			path:    "client.go",
			old:     "\tvar response Response",
			replace: "\tmaxResponseBytesAlias := &maxResponseBytes\n\tmaxResponseBytesAlias2 := maxResponseBytesAlias\n\t*maxResponseBytesAlias2 = 1\n\tvar response Response",
		},
		{
			name:    "client replaces acquired connection through pointer aliases",
			path:    "client.go",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\treplacementConnection, _ := openResponseReader()\n\tconnectionAlias := &connection\n\tconnectionAlias2 := connectionAlias\n\t*connectionAlias2 = replacementConnection\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
		{
			name:    "store replaces acquired reader through pointer aliases",
			path:    "job_store_v2.go",
			old:     "\tvar state storedJobStateV2",
			replace: "\treaderAlias := &reader\n\treaderAlias2 := readerAlias\n\t*readerAlias2 = rewrapStoredJobReader(reader)\n\tvar state storedJobStateV2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if tt.name == "store replaces acquired reader through pointer aliases" {
				mutated[tt.path] += "\nfunc rewrapStoredJobReader(reader storedJobReaderV2) storedJobReaderV2 { return reader }\n"
			}
			if mutated[tt.path] == sources[tt.path] {
				t.Fatal("pointer-alias mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		old     string
		replace string
	}{
		{
			name:    "direct JSON request encoder exposes raw error",
			old:     "return Response{}, errors.New(\"write worker request failed\")",
			replace: "return Response{}, err",
		},
		{
			name:    "direct JSON request encoder omits context precedence",
			old:     "if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }",
			replace: "if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
		{
			name:    "direct JSON request encoder uses variable error text",
			old:     "errors.New(\"write worker request failed\")",
			replace: "errors.New(\"write worker request failed: \" + request.Operation)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(existingJSONWriterSources)
			mutated["client.go"] = strings.Replace(mutated["client.go"], tt.old, tt.replace, 1)
			if mutated["client.go"] == existingJSONWriterSources["client.go"] {
				t.Fatal("direct JSON encoder mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		path    string
		old     string
		replace string
	}{
		{
			name:    "server returns success before unreachable decoder",
			path:    "server.go",
			old:     "\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }\n\treturn request, nil",
			replace: "\treturn request, nil\n\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }\n\treturn Request{}, &Response{}",
		},
		{
			name:    "client returns success before unreachable decoder",
			path:    "client.go",
			old:     "\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"read worker response failed\")\n\t}\n\treturn response, nil",
			replace: "\treturn response, nil\n\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"read worker response failed\")\n\t}\n\treturn Response{}, errors.New(\"unreachable worker response\")",
		},
		{
			name:    "store returns success before unreachable decoder",
			path:    "job_store_v2.go",
			old:     "\tif err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil { return storedJobStateV2{}, errors.New(\"stored job state is malformed\") }\n\treturn state, nil",
			replace: "\treturn state, nil\n\tif err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil { return storedJobStateV2{}, errors.New(\"stored job state is malformed\") }\n\treturn storedJobStateV2{}, errors.New(\"unreachable stored job state\")",
		},
		{
			name:    "server decoder is unreachable under false branch",
			path:    "server.go",
			old:     "\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }",
			replace: "\tif false {\n\t\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }\n\t}",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if mutated[tt.path] == sources[tt.path] {
				t.Fatal("decoder dominance mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name   string
		before string
		alias  string
	}{
		{
			name:   "client clears context through pointer aliases before acquisition branch",
			before: "\tconnection, err := openResponseReader()",
			alias:  "\tctxAlias := &ctx\n\tctxAlias2 := ctxAlias\n\t*ctxAlias2 = nil\n",
		},
		{
			name:   "client clears context through pointer aliases before encode branch",
			before: "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			alias:  "\tctxAlias := &ctx\n\tctxAlias2 := ctxAlias\n\t*ctxAlias2 = nil\n",
		},
		{
			name:   "client clears context through pointer aliases before unsupported half-close branch",
			before: "\thalfCloser, ok := connection.(interface{ CloseWrite() error })",
			alias:  "\tctxAlias := &ctx\n\tctxAlias2 := ctxAlias\n\t*ctxAlias2 = nil\n",
		},
		{
			name:   "client clears context through pointer aliases before failed half-close branch",
			before: "\tif err := halfCloser.CloseWrite(); err != nil {",
			alias:  "\tctxAlias := &ctx\n\tctxAlias2 := ctxAlias\n\t*ctxAlias2 = nil\n",
		},
		{
			name:   "client clears context through pointer aliases before decode branch",
			before: "\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {",
			alias:  "\tctxAlias := &ctx\n\tctxAlias2 := ctxAlias\n\t*ctxAlias2 = nil\n",
		},
		{
			name:   "client clears acquisition error through pointer aliases before branch",
			before: "\tif err != nil {",
			alias:  "\terrAlias := &err\n\terrAlias2 := errAlias\n\t*errAlias2 = nil\n",
		},
		{
			name:   "client forces successful half-close assertion through pointer aliases",
			before: "\tif !ok {",
			alias:  "\tokAlias := &ok\n\tokAlias2 := okAlias\n\t*okAlias2 = true\n",
		},
		{
			name:   "client clears half-closer through pointer aliases before close",
			before: "\tif err := halfCloser.CloseWrite(); err != nil {",
			alias:  "\thalfCloserAlias := &halfCloser\n\thalfCloserAlias2 := halfCloserAlias\n\t*halfCloserAlias2 = nil\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["client.go"] = strings.Replace(mutated["client.go"], tt.before, tt.alias+tt.before, 1)
			if mutated["client.go"] == sources["client.go"] {
				t.Fatal("client safe-branch alias mutation did not change the positive fixture")
			}
			want := "decoder caller composition"
			if tt.name == "client forces successful half-close assertion through pointer aliases" || tt.name == "client clears half-closer through pointer aliases before close" {
				want = "client half-close composition"
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, want)
		})
	}

	t.Run("client returns success before unreachable encode half-close and decode", func(t *testing.T) {
		mutated := l8CloneWorkerV2GuardSources(sources)
		mutated["client.go"] = strings.Replace(mutated["client.go"], "\tvar response Response\n", "", 1)
		mutated["client.go"] = strings.Replace(mutated["client.go"], "\treturn response, nil\n}", "\treturn Response{}, errors.New(\"unreachable worker response\")\n}", 1)
		mutated["client.go"] = strings.Replace(mutated["client.go"], "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {", "\tvar response Response\n\treturn response, nil\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {", 1)
		if mutated["client.go"] == sources["client.go"] {
			t.Fatal("client early-success mutation did not change the positive fixture")
		}
		l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
	})

	t.Run("no-op named request encoder helper", func(t *testing.T) {
		mutated := l8CloneWorkerV2GuardSources(existingJSONWriterSources)
		mutated["client.go"] = strings.Replace(mutated["client.go"], "\t\"encoding/json\"\n", "", 1)
		mutated["client.go"] = strings.Replace(mutated["client.go"], `	if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request failed")
	}
`, clientHelperEncodeBlock, 1)
		mutated["client.go"] += "\nfunc encodeWorkerRequest(writer io.Writer, request Request) error { return nil }\n"
		if mutated["client.go"] == existingJSONWriterSources["client.go"] {
			t.Fatal("no-op request encoder mutation did not change the direct encoder fixture")
		}
		l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
	})

	for _, tt := range []struct {
		name    string
		path    string
		old     string
		replace string
		want    string
	}{
		{
			name:    "client IIFE resets decoded response through capture",
			path:    "client.go",
			old:     "\treturn response, nil",
			replace: "\tfunc() { response = Response{} }()\n\treturn response, nil",
			want:    "decoder caller composition",
		},
		{
			name:    "client IIFE clears acquired connection through capture",
			path:    "client.go",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\tfunc() { connection = nil }()\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			want:    "decoder caller composition",
		},
		{
			name:    "client IIFE clears context through capture",
			path:    "client.go",
			old:     "\tconnection, err := openResponseReader()",
			replace: "\tfunc() { ctx = nil }()\n\tconnection, err := openResponseReader()",
			want:    "decoder caller composition",
		},
		{
			name:    "client IIFE clears acquisition error through capture",
			path:    "client.go",
			old:     "\tif err != nil {",
			replace: "\tfunc() { err = nil }()\n\tif err != nil {",
			want:    "decoder caller composition",
		},
		{
			name:    "client IIFE forces successful half-close assertion through capture",
			path:    "client.go",
			old:     "\tif !ok {",
			replace: "\tfunc() { ok = true }()\n\tif !ok {",
			want:    "client half-close composition",
		},
		{
			name:    "client IIFE clears half-closer through capture",
			path:    "client.go",
			old:     "\tif err := halfCloser.CloseWrite(); err != nil {",
			replace: "\tfunc() { halfCloser = nil }()\n\tif err := halfCloser.CloseWrite(); err != nil {",
			want:    "client half-close composition",
		},
		{
			name:    "server IIFE replaces configured limit through capture",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tfunc() { server.maxRequestBytes = 1 }()\n\tvar request Request",
			want:    "decoder caller composition",
		},
		{
			name:    "server clears reader before decode",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\treader = nil\n\tvar request Request",
			want:    "decoder caller composition",
		},
		{
			name:    "store replaces job identity before open",
			path:    "job_store_v2.go",
			old:     "\treader, err := store.openStoredJobStateV2(jobID)",
			replace: "\tjobID = \"job-neighbor\"\n\treader, err := store.openStoredJobStateV2(jobID)",
			want:    "decoder caller composition",
		},
		{
			name:    "client resets request before direct JSON encode",
			path:    "client.go",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\trequest = Request{}\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			want:    "decoder caller composition",
		},
		{
			name:    "client replaces receiver response limit before initialization",
			path:    "client.go",
			old:     "\tmaxResponseBytes := transport.maxResponseBytes",
			replace: "\ttransport.maxResponseBytes = 1\n\tmaxResponseBytes := transport.maxResponseBytes",
			want:    "decoder caller composition",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if mutated[tt.path] == sources[tt.path] {
				t.Fatal("captured or direct input mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, tt.want)
		})
	}

	t.Run("client local captured response mutator", func(t *testing.T) {
		mutated := l8CloneWorkerV2GuardSources(sources)
		mutated["client.go"] = strings.Replace(mutated["client.go"], "\treturn response, nil", "\tmutateResponse := func() { response = Response{} }\n\tmutateResponse()\n\treturn response, nil", 1)
		if mutated["client.go"] == sources["client.go"] {
			t.Fatal("local captured response mutator did not change the positive fixture")
		}
		l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
	})

	for _, tt := range []struct {
		name     string
		path     string
		old      string
		replace  string
		jobValue bool
	}{
		{
			name:    "client rewrites request operation before direct JSON encode",
			path:    "client.go",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\trequest.Operation = \"neighbor\"\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
		{
			name:    "server rewrites decoded request operation",
			path:    "server.go",
			old:     "\treturn request, nil",
			replace: "\trequest.Operation = \"neighbor\"\n\treturn request, nil",
		},
		{
			name:    "server rewrites decoded request field through pointer alias root",
			path:    "server.go",
			old:     "\treturn request, nil",
			replace: "\trequestAlias := &request\n\trequestAlias.Operation = \"neighbor\"\n\treturn request, nil",
		},
		{
			name:     "store rewrites decoded nested job value",
			path:     "job_store_v2.go",
			old:      "\treturn state, nil",
			replace:  "\tstate.JobV2.Value = \"neighbor\"\n\treturn state, nil",
			jobValue: true,
		},
		{
			name:     "store rewrites decoded nested job value through pointer alias root",
			path:     "job_store_v2.go",
			old:      "\treturn state, nil",
			replace:  "\tstateAlias := &state\n\tstateAlias.JobV2.Value = \"neighbor\"\n\treturn state, nil",
			jobValue: true,
		},
		{
			name:    "client replaces receiver before response limit snapshot",
			path:    "client.go",
			old:     "\tmaxResponseBytes := transport.maxResponseBytes",
			replace: "\ttransport = unixSocketClientTransport{}\n\tmaxResponseBytes := transport.maxResponseBytes",
		},
		{
			name:    "store replaces receiver before open",
			path:    "job_store_v2.go",
			old:     "\treader, err := store.openStoredJobStateV2(jobID)",
			replace: "\tstore = &jobStoreV2{}\n\treader, err := store.openStoredJobStateV2(jobID)",
		},
		{
			name:    "server preconsumes bounded reader before exact decoder",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\t_, _ = io.ReadAll(io.LimitReader(reader, 1))\n\tvar request Request",
		},
		{
			name:    "client preconsumes bounded connection before exact decoder",
			path:    "client.go",
			old:     "\tvar response Response",
			replace: "\t_, _ = io.ReadAll(io.LimitReader(connection, 1))\n\tvar response Response",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			if tt.jobValue {
				mutated["types.go"] = strings.Replace(mutated["types.go"], "type JobV2 struct{}", "type JobV2 struct { Value string }", 1)
			}
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if mutated[tt.path] == sources[tt.path] {
				t.Fatal("rooted field, receiver, or input-consumption mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name    string
		path    string
		old     string
		replace string
	}{
		{
			name:    "server goto bypasses exact decoder",
			path:    "server.go",
			old:     "\tvar request Request\n\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }\n\treturn request, nil",
			replace: "\tvar request Request\n\tgoto decoded\n\tif err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }\n decoded:\n\t;\n\treturn request, nil",
		},
		{
			name:    "store goto bypasses exact decoder",
			path:    "job_store_v2.go",
			old:     "\tvar state storedJobStateV2\n\tif err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil { return storedJobStateV2{}, errors.New(\"stored job state is malformed\") }\n\treturn state, nil",
			replace: "\tvar state storedJobStateV2\n\tgoto decoded\n\tif err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil { return storedJobStateV2{}, errors.New(\"stored job state is malformed\") }\n decoded:\n\t;\n\treturn state, nil",
		},
		{
			name:    "client goto bypasses required half-close",
			path:    "client.go",
			old:     "\tif err := halfCloser.CloseWrite(); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"write worker request framing failed\")\n\t}\n\tmaxResponseBytes := transport.maxResponseBytes",
			replace: "\tgoto framed\n\tif err := halfCloser.CloseWrite(); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"write worker request framing failed\")\n\t}\n framed:\n\t;\n\tmaxResponseBytes := transport.maxResponseBytes",
		},
		{
			name:    "client goto bypasses exact response decoder",
			path:    "client.go",
			old:     "\tvar response Response\n\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"read worker response failed\")\n\t}\n\treturn response, nil",
			replace: "\tvar response Response\n\tgoto decoded\n\tif err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {\n\t\tif ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }\n\t\treturn Response{}, errors.New(\"read worker response failed\")\n\t}\n decoded:\n\t;\n\treturn response, nil",
		},
		{
			name:    "client emits extra unhandled direct request frame",
			path:    "client.go",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\tjson.NewEncoder(connection).Encode(request.WithDefaults())\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if mutated[tt.path] == sources[tt.path] {
				t.Fatal("control-flow or duplicate-encoder mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	for _, tt := range []struct {
		name     string
		path     string
		old      string
		replace  string
		jobValue bool
	}{
		{
			name:    "server replaces receiver before configured limit use",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tserver = &Server{maxRequestBytes: 1}\n\tvar request Request",
		},
		{
			name:    "client rewrites request field through field pointer",
			path:    "client.go",
			old:     "\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
			replace: "\tfieldAlias := &request.Operation\n\t*fieldAlias = \"neighbor\"\n\tif err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {",
		},
		{
			name:    "server rewrites decoded request field through field pointer",
			path:    "server.go",
			old:     "\treturn request, nil",
			replace: "\tfieldAlias := &request.Operation\n\t*fieldAlias = \"neighbor\"\n\treturn request, nil",
		},
		{
			name:     "store rewrites decoded nested job field through field pointer",
			path:     "job_store_v2.go",
			old:      "\treturn state, nil",
			replace:  "\tfieldAlias := &state.JobV2.Value\n\t*fieldAlias = \"neighbor\"\n\treturn state, nil",
			jobValue: true,
		},
		{
			name:    "store replaces job identity through pointer alias before open",
			path:    "job_store_v2.go",
			old:     "\treader, err := store.openStoredJobStateV2(jobID)",
			replace: "\tjobIDAlias := &jobID\n\t*jobIDAlias = \"job-neighbor\"\n\treader, err := store.openStoredJobStateV2(jobID)",
		},
		{
			name:    "server directly reads decoder input before decode",
			path:    "server.go",
			old:     "\tvar request Request",
			replace: "\tvar scratch [1]byte\n\t_, _ = reader.Read(scratch[:])\n\tvar request Request",
		},
		{
			name:    "client directly reads connection before response decode",
			path:    "client.go",
			old:     "\tvar response Response",
			replace: "\tvar scratch [1]byte\n\t_, _ = connection.Read(scratch[:])\n\tvar response Response",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			if tt.jobValue {
				mutated["types.go"] = strings.Replace(mutated["types.go"], "type JobV2 struct{}", "type JobV2 struct { Value string }", 1)
			}
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.old, tt.replace, 1)
			if mutated[tt.path] == sources[tt.path] {
				t.Fatal("receiver, field-pointer, or job identity mutation did not change the positive fixture")
			}
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}

	otherWrapperOutput := l8CloneWorkerV2GuardSources(sources)
	otherWrapperOutput["protocol_decode.go"] = strings.Replace(otherWrapperOutput["protocol_decode.go"], "var output Response", "var output Response\n\tvar other Response", 1)
	otherWrapperOutput["protocol_decode.go"] = strings.Replace(otherWrapperOutput["protocol_decode.go"], "return output, nil", "return other, nil", 1)
	l8AssertWorkerV2GuardRejects(t, otherWrapperOutput, policy, "decoder caller composition")
	responseWrapperHelper := l8CloneWorkerV2GuardSources(sources)
	responseWrapperHelper["protocol_decode.go"] = strings.Replace(responseWrapperHelper["protocol_decode.go"],
		"decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output)",
		"callWorkerResponseInto(reader, defaultMaxResponseBytes, &output)", 1)
	responseWrapperHelper["protocol_decode.go"] += "\nfunc callWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error { return decodeWorkerResponseInto(reader, maxBytes, output) }\n"
	l8AssertWorkerV2GuardRejects(t, responseWrapperHelper, policy, "decoder caller composition")

	directGenericStore := l8CloneWorkerV2GuardSources(sources)
	directGenericStore["job_store_v2.go"] = strings.Replace(directGenericStore["job_store_v2.go"],
		"decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state)",
		"decodeGenericStoredJobStateV2(reader, maxStoredJobStateV2Bytes, &state)", 1)
	directGenericStore["job_store_v2.go"] += "\nfunc decodeGenericStoredJobStateV2(reader io.Reader, maxBytes int64, output *storedJobStateV2) error { return decodeStoredJobStateV2Into(reader, maxBytes, output) }\n"
	l8AssertWorkerV2GuardRejects(t, directGenericStore, policy, "decoder caller composition")

	for _, tt := range []struct {
		name   string
		path   string
		callee string
	}{
		{name: "server helper bypass", path: "server.go", callee: "decodeWorkerRequestInto"},
		{name: "client helper bypass", path: "client.go", callee: "decodeWorkerResponseInto"},
		{name: "store helper bypass", path: "job_store_v2.go", callee: "decodeStoredJobStateV2Into"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			helper := "call" + strings.TrimPrefix(tt.callee, "decode")
			mutated[tt.path] = strings.Replace(mutated[tt.path], tt.callee+"(", helper+"(", 1)
			mutated[tt.path] += "\nfunc " + helper + "(reader io.Reader, maxBytes int64, output " + map[string]string{
				"decodeWorkerRequestInto":    "*Request",
				"decodeWorkerResponseInto":   "*Response",
				"decodeStoredJobStateV2Into": "*storedJobStateV2",
			}[tt.callee] + ") error { return " + tt.callee + "(reader, maxBytes, output) }\n"
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}
}

func TestL8WorkerV2GuardRejectsCallerWholeValueEscapesAndCleanupBypasses(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{
			"job_store_v2.go":    true,
			"protocol_decode.go": true,
		},
		mixed: map[string]bool{
			"client.go": true,
			"server.go": true,
			"types.go":  true,
		},
	}
	sources := map[string]string{
		"types.go": `package sandboxworker
type JobStartRequestV2 struct{}
type JobV2 struct{}
type callerNestedValue struct { Value string }
type Request struct { Operation string; JobStartV2 *JobStartRequestV2; Nested *callerNestedValue }
type Response struct { JobV2 *JobV2; Nested *callerNestedValue }
type storedJobStateV2 struct { JobV2 JobV2; Nested *callerNestedValue }
func (request Request) WithDefaults() Request { return request }`,
		"protocol_decode.go": `package sandboxworker
import "io"
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error { return nil }
func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error { return nil }
func decodeStoredJobStateV2Into(reader io.Reader, maxBytes int64, output *storedJobStateV2) error { return nil }
func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output); err != nil { return Response{}, err }
	return output, nil
}`,
		"server.go": `package sandboxworker
import "io"
const configuredMaxRequestBytesV2 int64 = 8 << 20
type Server struct { maxRequestBytes int64 }
func configuredServerV2() *Server { return &Server{maxRequestBytes: configuredMaxRequestBytesV2} }
func (server *Server) readRequest(reader io.Reader) (Request, *Response) {
	var request Request
	if err := decodeWorkerRequestInto(reader, server.maxRequestBytes, &request); err != nil { return Request{}, &Response{} }
	return request, nil
}`,
		"client.go": `package sandboxworker
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)
const defaultMaxResponseBytes int64 = 1 << 20
type unixSocketClientTransport struct { maxResponseBytes int64 }
type workerResponseConnection interface { io.Reader; io.Writer; Close() error; SetDeadline(time.Time) error }
func openResponseReader() (workerResponseConnection, error) { return nil, nil }
func (transport unixSocketClientTransport) RoundTrip(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	connection, err := openResponseReader()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("open worker connection failed")
	}
	defer connection.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	defer close(done)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := json.NewEncoder(connection).Encode(request.WithDefaults()); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request failed")
	}
	halfCloser, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
	if err := halfCloser.CloseWrite(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("write worker request framing failed")
	}
	maxResponseBytes := transport.maxResponseBytes
	if maxResponseBytes <= 0 { maxResponseBytes = defaultMaxResponseBytes }
	var response Response
	if err := decodeWorkerResponseInto(connection, maxResponseBytes, &response); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return Response{}, ctxErr }
		return Response{}, errors.New("read worker response failed")
	}
	return response, nil
}`,
		"job_store_v2.go": `package sandboxworker
import (
	"errors"
	"io"
	"os"
	"path/filepath"
)
const maxStoredJobStateV2Bytes int64 = 64 << 10
type jobStoreV2 struct { root string }
type storedJobReaderV2 interface { io.Reader; Close() error }
func validJobSafeID(value string) bool { return value != "" }
func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	if store == nil || !validJobSafeID(jobID) {
		return nil, errors.New("stored job state is unavailable")
	}
	path := filepath.Join(store.root, jobID+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxStoredJobStateV2Bytes {
		return nil, errors.New("stored job state is unavailable")
	}
	return os.Open(path)
}
func (store *jobStoreV2) load(jobID string) (storedJobStateV2, error) {
	reader, err := store.openStoredJobStateV2(jobID)
	if err != nil { return storedJobStateV2{}, errors.New("stored job state could not be opened") }
	defer reader.Close()
	var state storedJobStateV2
	if err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil { return storedJobStateV2{}, errors.New("stored job state is malformed") }
	return state, nil
}`,
	}
	l8AssertWorkerV2GuardAllows(t, sources, policy)

	for _, tt := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{
			name: "client connection assigned to package global",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedConnection workerResponseConnection\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdefer connection.Close()", "\tleakedConnection = connection\n\tdefer connection.Close()", 1)
			},
		},
		{
			name: "store reader assigned to package global",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] += "\nvar leakedReader storedJobReaderV2\n"
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()", "\tleakedReader = reader\n\tdefer reader.Close()", 1)
			},
		},
		{
			name: "client clears done channel",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdone := make(chan struct{})", "\tdone := make(chan struct{})\n\tdone = nil", 1)
			},
		},
		{
			name: "client replaces done channel",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdone := make(chan struct{})", "\tdone := make(chan struct{})\n\tdone = make(chan struct{})", 1)
			},
		},
		{
			name: "client eagerly closes done channel",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdefer close(done)", "\tclose(done)\n\tdefer close(done)", 1)
			},
		},
		{
			name: "client signals done channel before deferred close",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\t}()\n\tdefer close(done)", "\t}()\n\tdone <- struct{}{}\n\tdefer close(done)", 1)
			},
		},
		{
			name: "client ranges done channel before watcher and deferred close",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdone := make(chan struct{})", "\tdone := make(chan struct{})\n\tfor range done {}", 1)
			},
		},
		{
			name: "client select sends done channel before deferred close",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\t}()\n\tdefer close(done)", "\t}()\n\tselect {\n\tcase done <- struct{}{}:\n\tdefault:\n\t}\n\tdefer close(done)", 1)
			},
		},
		{
			name: "client adds asynchronous done channel range consumer",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdone := make(chan struct{})", "\tdone := make(chan struct{})\n\tgo func() {\n\t\tfor range done {}\n\t}()", 1)
			},
		},
		{
			name: "client adds comparison-only done channel goroutine",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdone := make(chan struct{})", "\tdone := make(chan struct{})\n\tgo func() {\n\t\tif done != nil {\n\t\t\tfor {}\n\t\t}\n\t}()", 1)
			},
		},
		{
			name: "client exposes connection before cleanup defer",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdefer connection.Close()", "\tif exposed, ok := connection.(error); ok { return Response{}, exposed }\n\tdefer connection.Close()", 1)
			},
		},
		{
			name: "store exposes reader before cleanup defer",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()", "\tif exposed, ok := reader.(error); ok { return storedJobStateV2{}, exposed }\n\tdefer reader.Close()", 1)
			},
		},
		{
			name: "client request assigned to package global",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedRequest Request\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tif err := json.NewEncoder", "\tleakedRequest = request\n\tif err := json.NewEncoder", 1)
			},
		},
		{
			name: "client response assigned to package global",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedResponse Response\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\treturn response, nil", "\tleakedResponse = response\n\treturn response, nil", 1)
			},
		},
		{
			name: "server request sent to package channel",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] += "\nvar leakedRequests = make(chan Request, 1)\n"
				mutated["server.go"] = strings.Replace(mutated["server.go"], "\treturn request, nil", "\tleakedRequests <- request\n\treturn request, nil", 1)
			},
		},
		{
			name: "store state assigned through package composite",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] += "\ntype leakedStoredStateBox struct { Value storedJobStateV2 }\nvar leakedStoredState leakedStoredStateBox\n"
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\treturn state, nil", "\tleakedStoredState = leakedStoredStateBox{Value: state}\n\treturn state, nil", 1)
			},
		},
		{
			name: "client connection assigned through package composite",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\ntype leakedConnectionBox struct { Value workerResponseConnection }\nvar leakedConnectionComposite leakedConnectionBox\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdefer connection.Close()", "\tleakedConnectionComposite = leakedConnectionBox{Value: connection}\n\tdefer connection.Close()", 1)
			},
		},
		{
			name: "store reader sent to package channel",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] += "\nvar leakedReaders = make(chan storedJobReaderV2, 1)\n"
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\tdefer reader.Close()", "\tleakedReaders <- reader\n\tdefer reader.Close()", 1)
			},
		},
		{
			name: "client request escapes through IIFE parameter",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedIIFERequest Request\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tif err := json.NewEncoder", "\tfunc(value Request) { leakedIIFERequest = value }(request)\n\tif err := json.NewEncoder", 1)
			},
		},
		{
			name: "client request escapes through goroutine parameter",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedGoroutineRequest Request\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tif err := json.NewEncoder", "\tgo func(value Request) { leakedGoroutineRequest = value }(request)\n\tif err := json.NewEncoder", 1)
			},
		},
		{
			name: "client response escapes through IIFE parameter",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedIIFEResponse Response\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\treturn response, nil", "\tfunc(value Response) { leakedIIFEResponse = value }(response)\n\treturn response, nil", 1)
			},
		},
		{
			name: "client connection escapes through IIFE parameter",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] += "\nvar leakedIIFEConnection workerResponseConnection\n"
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tdefer connection.Close()", "\tdefer connection.Close()\n\tfunc(value workerResponseConnection) { leakedIIFEConnection = value }(connection)", 1)
			},
		},
		{
			name: "server request escapes through IIFE parameter",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] += "\nvar leakedIIFEServerRequest Request\n"
				mutated["server.go"] = strings.Replace(mutated["server.go"], "\treturn request, nil", "\tfunc(value Request) { leakedIIFEServerRequest = value }(request)\n\treturn request, nil", 1)
			},
		},
		{
			name: "client request shallow copy mutates nested pointer",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\tif err := json.NewEncoder", "\trequestAlias := request\n\trequestAlias.Nested.Value = \"mutated\"\n\tif err := json.NewEncoder", 1)
			},
		},
		{
			name: "client response shallow copy mutates nested pointer",
			mutate: func(mutated map[string]string) {
				mutated["client.go"] = strings.Replace(mutated["client.go"], "\treturn response, nil", "\tresponseAlias := response\n\tresponseAlias.Nested.Value = \"mutated\"\n\treturn response, nil", 1)
			},
		},
		{
			name: "store state shallow copy mutates nested pointer",
			mutate: func(mutated map[string]string) {
				mutated["job_store_v2.go"] = strings.Replace(mutated["job_store_v2.go"], "\treturn state, nil", "\tstateAlias := state\n\tstateAlias.Nested.Value = \"mutated\"\n\treturn state, nil", 1)
			},
		},
		{
			name: "server request shallow copy mutates nested pointer",
			mutate: func(mutated map[string]string) {
				mutated["server.go"] = strings.Replace(mutated["server.go"], "\treturn request, nil", "\trequestAlias := request\n\trequestAlias.Nested.Value = \"mutated\"\n\treturn request, nil", 1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			tt.mutate(mutated)
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "decoder caller composition")
		})
	}
}

func TestL8WorkerV2GuardLocksExactBoundedRawPreflightSeam(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{
		"job_store_v2.go":    true,
		"protocol_decode.go": true,
	}}
	requestSource := `package sandboxworker
import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)
type JobStartRequestV2 struct { Value string }
type Request struct { JobStartV2 *JobStartRequestV2 }
func validateWorkerJSONPreflightV2(raw string) error {
	if len(raw) == 0 { return errors.New("worker request is empty") }
	return nil
}
func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 { return nil, errors.New("worker JSON limit is invalid") }
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil { return nil, err }
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 { return nil, errors.New("worker JSON exceeds limit") }
		if n == 0 && probeErr == io.EOF { return raw, nil }
		if probeErr != nil { return nil, probeErr }
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil { return err }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`
	l8AssertWorkerV2GuardAllows(t, map[string]string{"protocol_decode.go": requestSource}, policy)

	privateSource := strings.NewReplacer(
		`type JobStartRequestV2 struct { Value string }
type Request struct { JobStartV2 *JobStartRequestV2 }`,
		`type storedJobStateV2 struct { SubmittedAt time.Time `+"`json:\"submittedAt\"`"+` }`,
		`func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error`,
		`func decodeStoredJobStateV2Into(reader io.Reader, maxBytes int64, output *storedJobStateV2) error`,
	).Replace(requestSource)
	privateSource = strings.Replace(privateSource, `"io"`, `"io"
	"time"`, 1)
	l8AssertWorkerV2GuardAllows(t, map[string]string{"protocol_decode.go": privateSource}, policy)

	latePreflight := strings.Replace(requestSource, "\tif err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }\n", "", 1)
	latePreflight = strings.Replace(latePreflight, "\tif err := decoder.Decode(&trailing); err != io.EOF { return errors.New(\"trailing JSON\") }\n\treturn nil\n}", "\tif err := decoder.Decode(&trailing); err != io.EOF { return errors.New(\"trailing JSON\") }\n\tif err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }\n\treturn nil\n}", 1)
	tests := []struct {
		name   string
		path   string
		source string
	}{
		{name: "omitted preflight", path: "protocol_decode.go", source: strings.Replace(requestSource, "\tif err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }\n", "", 1)},
		{name: "late preflight", path: "protocol_decode.go", source: latePreflight},
		{name: "wrong scanner buffer", path: "protocol_decode.go", source: strings.Replace(requestSource, "\tif err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }", "\tother := append([]byte(nil), raw...)\n\tif err := validateWorkerJSONPreflightV2(string(other)); err != nil { return err }", 1)},
		{name: "wrong decoder buffer", path: "protocol_decode.go", source: strings.Replace(requestSource, "\tdecoder := json.NewDecoder(bytes.NewReader(raw))", "\tdecoder := json.NewDecoder(bytes.NewReader(append([]byte(nil), raw...)))", 1)},
		{name: "unbounded read", path: "protocol_decode.go", source: strings.Replace(requestSource, "io.ReadAll(limited)", "io.ReadAll(reader)", 1)},
		{name: "missing positive limit validation", path: "protocol_decode.go", source: strings.Replace(requestSource, "\tif maxBytes <= 0 { return nil, errors.New(\"worker JSON limit is invalid\") }\n", "", 1)},
		{name: "wrong limited reader", path: "protocol_decode.go", source: strings.Replace(requestSource, "R: reader, N: maxBytes", "R: bytes.NewReader(nil), N: maxBytes", 1)},
		{name: "wrong limited bound", path: "protocol_decode.go", source: strings.Replace(requestSource, "R: reader, N: maxBytes", "R: reader, N: maxBytes-1", 1)},
		{name: "wrong probe reader", path: "protocol_decode.go", source: strings.Replace(requestSource, "io.ReadFull(reader, probe[:])", "io.ReadFull(limited, probe[:])", 1)},
		{name: "wrong probe size", path: "protocol_decode.go", source: strings.Replace(requestSource, "var probe [1]byte", "var probe [2]byte", 1)},
		{name: "ignored probe error", path: "protocol_decode.go", source: strings.Replace(requestSource, "if probeErr != nil { return nil, probeErr }", "if probeErr != nil { return raw, nil }", 1)},
		{name: "outer limited inner", path: "protocol_decode.go", source: strings.Replace(requestSource, "readWorkerJSONBoundedV2(reader, maxBytes)", "readWorkerJSONBoundedV2(io.LimitReader(reader, maxBytes), maxBytes)", 1)},
		{name: "wrong function", path: "protocol_decode.go", source: strings.Replace(requestSource, "decodeWorkerRequestInto", "decodeWorkerPayloadInto", 1)},
		{name: "wrong output", path: "protocol_decode.go", source: strings.NewReplacer("type Request struct", "type RequestV2 struct", "output *Request", "output *RequestV2").Replace(requestSource)},
		{name: "wrong file", path: "job_store_v2.go", source: requestSource},
		{name: "raw reassignment", path: "protocol_decode.go", source: strings.Replace(requestSource, "\tdecoder :=", "\traw = append(raw[:0], raw...)\n\tdecoder :=", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{tt.path: tt.source}, policy, "implicit interface callback")
		})
	}

	callbackScanner := strings.Replace(requestSource, `"io"`, `"io"
	"fmt"`, 1)
	callbackScanner = strings.Replace(callbackScanner,
		`func validateWorkerJSONPreflightV2(raw string) error {
	if len(raw) == 0 { return errors.New("worker request is empty") }
	return nil
}`,
		`type preflightRendererV2 struct{}
func (preflightRendererV2) String() string { return "" }
func validateWorkerJSONPreflightV2(raw string) error {
	_ = raw
	_ = fmt.Sprint(preflightRendererV2{})
	return nil
}`,
		1,
	)
	l8AssertWorkerV2GuardRejects(t, map[string]string{"protocol_decode.go": callbackScanner}, policy, "implicit interface callback")

	mutableScanner := strings.Replace(requestSource, "func validateWorkerJSONPreflightV2(raw string) error", "func validateWorkerJSONPreflightV2(raw []byte) error", 1)
	mutableScanner = strings.Replace(mutableScanner, "validateWorkerJSONPreflightV2(string(raw))", "validateWorkerJSONPreflightV2(raw)", 1)
	mutableScanner = strings.Replace(mutableScanner, "\tif len(raw) == 0", "\tif len(raw) > 0 { raw[0] = '{' }\n\tif len(raw) == 0", 1)
	l8AssertWorkerV2GuardRejects(t, map[string]string{"protocol_decode.go": mutableScanner}, policy, "implicit interface callback")
}

func TestL8WorkerV2GuardAllowsOnlyExactAuditedJSONMarshalSeams(t *testing.T) {
	keyPolicy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{
		"job_store_v2.go":    true,
		"job_v2_helpers.go":  true,
		"job_v2_service.go":  true,
		"protocol_decode.go": true,
	}}
	keySource := `package sandboxworker
	import (
		"crypto/sha256"
		"encoding/hex"
		"encoding/json"
		"github.com/jywlabs/hal/internal/sandboxruntime"
	)
	type ExecRequest struct { Metadata *sandboxruntime.RuntimeMetadata ` + "`json:\"metadata,omitempty\"`" + ` }
	type JobStartRequestV2 struct { Exec ExecRequest ` + "`json:\"exec\"`" + ` }
	type jobRequestIdentityV2 struct {
		DriverID string ` + "`json:\"driverId\"`" + `
		PrincipalID string ` + "`json:\"principalId\"`" + `
		DaemonGeneration string ` + "`json:\"daemonGeneration\"`" + `
		Request JobStartRequestV2 ` + "`json:\"request\"`" + `
	}
	func canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration string, request JobStartRequestV2) (string, string, string, JobStartRequestV2) {
		return driverID, principalID, daemonGeneration, request
	}
	func jobRequestKeyV2(driverID, principalID, daemonGeneration string, request JobStartRequestV2) (string, error) {
		canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)
		identity := jobRequestIdentityV2{DriverID: canonicalDriverID, PrincipalID: canonicalPrincipalID, DaemonGeneration: canonicalDaemonGeneration, Request: canonicalRequest}
		payload, err := json.Marshal(identity)
		if err != nil { return "", err }
		digest := sha256.Sum256(payload)
		return "request-v2-" + hex.EncodeToString(digest[:]), nil
	}`
	l8AssertWorkerV2GuardAllows(t, map[string]string{"job_v2_helpers.go": keySource}, keyPolicy)
	aliasedKeySource := strings.NewReplacer(
		"type ExecRequest struct",
		"type auditedRuntimeMetadataV2 = sandboxruntime.RuntimeMetadata\ntype ExecRequest struct",
		"*sandboxruntime.RuntimeMetadata",
		"*auditedRuntimeMetadataV2",
	).Replace(keySource)
	l8AssertWorkerV2GuardAllows(t, map[string]string{"job_v2_helpers.go": aliasedKeySource}, keyPolicy)

	storeSource := `package sandboxworker
import (
	"encoding/json"
	"time"
)
type JobV2 struct { SubmittedAt time.Time ` + "`json:\"submittedAt\"`" + ` }
type storedJobStateV2 struct { JobV2 JobV2; RequestKey string ` + "`json:\"requestKey\"`" + `; PrincipalID string ` + "`json:\"principalId\"`" + `; DaemonGeneration string ` + "`json:\"daemonGeneration\"`" + ` }
	func encodeStoredJobStateV2(state storedJobStateV2) ([]byte, error) { return json.Marshal(state) }`
	l8AssertWorkerV2GuardAllows(t, map[string]string{"job_store_v2.go": storeSource}, keyPolicy)
	aliasedStoreSource := strings.Replace(storeSource, "type JobV2 struct { SubmittedAt time.Time", "type auditedTimeV2 = time.Time\ntype JobV2 struct { SubmittedAt auditedTimeV2", 1)
	l8AssertWorkerV2GuardAllows(t, map[string]string{"job_store_v2.go": aliasedStoreSource}, keyPolicy)

	responseEncodeSource := `package sandboxworker
import (
	"encoding/json"
	"io"
	"time"
)
type JobV2 struct { SubmittedAt time.Time ` + "`json:\"submittedAt\"`" + ` }
type Response struct { JobV2 *JobV2 ` + "`json:\"jobV2,omitempty\"`" + ` }
func encodeWorkerResponse(writer io.Writer, response Response) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(response)
}`
	l8AssertWorkerV2GuardAllows(t, map[string]string{"protocol_decode.go": responseEncodeSource}, keyPolicy)

	marshalTests := []struct {
		name   string
		path   string
		source string
	}{
		{name: "canonical identity parameters swapped before initialization", path: "job_v2_helpers.go", source: strings.Replace(keySource, "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest :=", "driverID, principalID = principalID, driverID\n\t\tcanonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest :=", 1)},
		{name: "nested request metadata cleared before identity initialization", path: "job_v2_helpers.go", source: strings.Replace(keySource, "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest :=", "request.Exec.Metadata = nil\n\t\tcanonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest :=", 1)},
		{name: "unrelated statement before canonicalization", path: "job_v2_helpers.go", source: strings.Replace(keySource, "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest :=", "_ = 0\n\t\tcanonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest :=", 1)},
		{name: "unrelated statement between identity and marshal", path: "job_v2_helpers.go", source: strings.Replace(keySource, "payload, err := json.Marshal(identity)", "_ = 0\n\t\tpayload, err := json.Marshal(identity)", 1)},
		{name: "shared request metadata mutated after identity initialization", path: "job_v2_helpers.go", source: strings.Replace(keySource, "payload, err := json.Marshal(identity)", "canonicalRequest.Exec.Metadata.Backend = \"mutated\"\n\t\tpayload, err := json.Marshal(identity)", 1)},
		{name: "marshaled identity payload mutated before digest", path: "job_v2_helpers.go", source: strings.Replace(keySource, "digest := sha256.Sum256(payload)", "payload[0] = '{'\n\t\tdigest := sha256.Sum256(payload)", 1)},
		{name: "identity digest mutated before canonical return", path: "job_v2_helpers.go", source: strings.Replace(keySource, "return \"request-v2-\" + hex.EncodeToString(digest[:]), nil", "digest[0] ^= 1\n\t\treturn \"request-v2-\" + hex.EncodeToString(digest[:]), nil", 1)},
		{name: "canonical identity fields swapped after initialization", path: "job_v2_helpers.go", source: strings.Replace(keySource, "payload, err := json.Marshal(identity)", "identity.DriverID, identity.PrincipalID = identity.PrincipalID, identity.DriverID\n\t\tpayload, err := json.Marshal(identity)", 1)},
		{name: "canonical identity fields swapped through pointer alias", path: "job_v2_helpers.go", source: strings.Replace(keySource, "payload, err := json.Marshal(identity)", "identityAlias := &identity\n\t\tidentityAlias.DriverID, identityAlias.PrincipalID = identityAlias.PrincipalID, identityAlias.DriverID\n\t\tpayload, err := json.Marshal(identity)", 1)},
		{name: "adjacent runtime metadata", path: "job_v2_helpers.go", source: strings.Replace(keySource, "RuntimeMetadata", "RuntimeTemplateStatusMetadata", 1)},
		{name: "swapped canonicalization inputs", path: "job_v2_helpers.go", source: strings.Replace(keySource, "canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)", "canonicalJobRequestIdentityInputsV2(principalID, driverID, daemonGeneration, request)", 1)},
		{name: "swapped canonical identity bindings", path: "job_v2_helpers.go", source: strings.Replace(keySource, "DriverID: canonicalDriverID, PrincipalID: canonicalPrincipalID, DaemonGeneration: canonicalDaemonGeneration, Request: canonicalRequest", "DriverID: canonicalPrincipalID, PrincipalID: canonicalDriverID, DaemonGeneration: canonicalDaemonGeneration, Request: canonicalRequest", 1)},
		{name: "wrong driver identity binding", path: "job_v2_helpers.go", source: strings.Replace(keySource, "DriverID: canonicalDriverID", "DriverID: canonicalPrincipalID + canonicalDriverID[:0]", 1)},
		{name: "wrong principal identity binding", path: "job_v2_helpers.go", source: strings.Replace(keySource, "PrincipalID: canonicalPrincipalID", "PrincipalID: canonicalDriverID + canonicalPrincipalID[:0]", 1)},
		{name: "constant principal identity binding", path: "job_v2_helpers.go", source: strings.Replace(keySource, "PrincipalID: canonicalPrincipalID", `PrincipalID: "principal-fixed" + canonicalPrincipalID[:0]`, 1)},
		{name: "wrong daemon generation identity binding", path: "job_v2_helpers.go", source: strings.Replace(keySource, "DaemonGeneration: canonicalDaemonGeneration", "DaemonGeneration: canonicalPrincipalID + canonicalDaemonGeneration[:0]", 1)},
		{name: "missing driver identity binding", path: "job_v2_helpers.go", source: strings.NewReplacer("canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)\n\t\t_ = canonicalDriverID", "DriverID: canonicalDriverID, ", "").Replace(keySource)},
		{name: "wrong request identity binding", path: "job_v2_helpers.go", source: strings.Replace(keySource, "Request: canonicalRequest", "Request: JobStartRequestV2{Exec: canonicalRequest.Exec}", 1)},
		{name: "unkeyed canonical identity", path: "job_v2_helpers.go", source: strings.Replace(keySource, "jobRequestIdentityV2{DriverID: canonicalDriverID, PrincipalID: canonicalPrincipalID, DaemonGeneration: canonicalDaemonGeneration, Request: canonicalRequest}", "jobRequestIdentityV2{canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest}", 1)},
		{name: "missing request driver identity", path: "job_v2_helpers.go", source: strings.NewReplacer("\t\tDriverID string `json:\"driverId\"`\n", "", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)\n\t\t_ = canonicalDriverID", "DriverID: canonicalDriverID, ", "").Replace(keySource)},
		{name: "missing request principal identity", path: "job_v2_helpers.go", source: strings.NewReplacer("\t\tPrincipalID string `json:\"principalId\"`\n", "", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)\n\t\t_ = canonicalPrincipalID", "PrincipalID: canonicalPrincipalID, ", "").Replace(keySource)},
		{name: "missing request daemon generation identity", path: "job_v2_helpers.go", source: strings.NewReplacer("\t\tDaemonGeneration string `json:\"daemonGeneration\"`\n", "", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)", "canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)\n\t\t_ = canonicalDaemonGeneration", "DaemonGeneration: canonicalDaemonGeneration, ", "").Replace(keySource)},
		{name: "wrong canonical request field", path: "job_v2_helpers.go", source: strings.Replace(keySource, "Request JobStartRequestV2 `json:\"request\"`", "Request any `json:\"request\"`", 1)},
		{name: "nested custom marshal", path: "job_v2_helpers.go", source: `package sandboxworker
import "encoding/json"
type callbackV2 struct{}
func (callbackV2) MarshalJSON() ([]byte, error) { return nil, nil }
type JobStartRequestV2 struct { Value callbackV2 }
func jobRequestKeyV2(request JobStartRequestV2) ([]byte, error) { return json.Marshal(request) }`},
		{name: "nested custom text marshal", path: "job_v2_helpers.go", source: `package sandboxworker
import "encoding/json"
type callbackV2 string
func (callbackV2) MarshalText() ([]byte, error) { return nil, nil }
type JobStartRequestV2 struct { Value callbackV2 }
func jobRequestKeyV2(request JobStartRequestV2) ([]byte, error) { return json.Marshal(request) }`},
		{name: "nested interface", path: "job_v2_helpers.go", source: `package sandboxworker
import "encoding/json"
type JobStartRequestV2 struct { Value any }
func jobRequestKeyV2(request JobStartRequestV2) ([]byte, error) { return json.Marshal(request) }`},
		{name: "wrong key file", path: "job_v2_service.go", source: keySource},
		{name: "wrong key function", path: "job_v2_helpers.go", source: strings.Replace(keySource, "jobRequestKeyV2", "encodeJobRequestV2", 1)},
		{name: "wrong store function", path: "job_store_v2.go", source: strings.Replace(storeSource, "encodeStoredJobStateV2", "encodeStoredJobSnapshotV2", 1)},
		{name: "wrong store file", path: "job_v2_service.go", source: storeSource},
		{name: "missing stored principal", path: "job_store_v2.go", source: strings.Replace(storeSource, "; PrincipalID string `json:\"principalId\"`", "", 1)},
		{name: "missing stored daemon generation", path: "job_store_v2.go", source: strings.Replace(storeSource, "; DaemonGeneration string `json:\"daemonGeneration\"`", "", 1)},
		{name: "wrong stored request key tag", path: "job_store_v2.go", source: strings.Replace(storeSource, `json:"requestKey"`, `json:"requestIdentity"`, 1)},
		{name: "wrong response encoder file", path: "job_v2_service.go", source: responseEncodeSource},
		{name: "wrong response encoder function", path: "protocol_decode.go", source: strings.Replace(responseEncodeSource, "encodeWorkerResponse", "encodeWorkerSnapshot", 1)},
	}
	for _, tt := range marshalTests {
		t.Run(tt.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{tt.path: tt.source}, keyPolicy, "implicit interface callback")
		})
	}

	unmarshalSource := strings.Replace(storeSource, `func encodeStoredJobStateV2(state storedJobStateV2) ([]byte, error) { return json.Marshal(state) }`, `func decodeStoredJobStateV2(raw []byte, state *storedJobStateV2) error { return json.Unmarshal(raw, state) }`, 1)
	l8AssertWorkerV2GuardRejects(t, map[string]string{"job_store_v2.go": unmarshalSource}, keyPolicy, "implicit interface callback")

	for name, field := range map[string]string{
		"store nested marshal":   `Value storedEncoderV2`,
		"store nested interface": `Value any`,
	} {
		t.Run(name, func(t *testing.T) {
			callbackDeclaration := ""
			if strings.Contains(field, "storedEncoderV2") {
				callbackDeclaration = "type storedEncoderV2 struct{}\nfunc (storedEncoderV2) MarshalJSON() ([]byte, error) { return nil, nil }\n"
			}
			source := "package sandboxworker\nimport \"encoding/json\"\n" + callbackDeclaration + "type JobV2 struct { " + field + " }\ntype storedJobStateV2 struct { JobV2 JobV2 }\nfunc encodeStoredJobStateV2(state storedJobStateV2) ([]byte, error) { return json.Marshal(state) }"
			l8AssertWorkerV2GuardRejects(t, map[string]string{"job_store_v2.go": source}, keyPolicy, "implicit interface callback")
		})
	}
}

func TestL8WorkerV2GuardAllowsAuditedRuntimeMetadataInOuterStrictDecoders(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"protocol_decode.go": true}}
	for name, source := range map[string]string{
		"request": `package sandboxworker
	import (
		"bytes"
		"encoding/json"
	"errors"
	"io"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)
type RuntimeTarget struct { Metadata *sandboxruntime.RuntimeMetadata }
type Target struct { Runtime RuntimeTarget }
type JobStartRequestV2 struct { Target Target }
type Request struct { JobStartV2 *JobStartRequestV2 }
func validateWorkerJSONPreflightV2(raw string) error {
	if len(raw) == 0 { return errors.New("worker request is empty") }
	return nil
}
func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 { return nil, errors.New("worker JSON limit is invalid") }
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil { return nil, err }
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 { return nil, errors.New("worker JSON exceeds limit") }
		if n == 0 && probeErr == io.EOF { return raw, nil }
		if probeErr != nil { return nil, probeErr }
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil { return err }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}
`,
		"response": `package sandboxworker
	import (
		"bytes"
		"encoding/json"
	"errors"
	"io"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)
type Status struct { Metadata *sandboxruntime.RuntimeMetadata }
type Response struct { Status *Status }
func validateWorkerJSONPreflightV2(raw string) error {
	if len(raw) == 0 { return errors.New("worker response is empty") }
	return nil
}
func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 { return nil, errors.New("worker JSON limit is invalid") }
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil { return nil, err }
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 { return nil, errors.New("worker JSON exceeds limit") }
		if n == 0 && probeErr == io.EOF { return raw, nil }
		if probeErr != nil { return nil, probeErr }
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}
func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil { return err }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}
const defaultMaxResponseBytes int64 = 1<<20
func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output); err != nil { return Response{}, err }
	return output, nil
}`,
	} {
		t.Run(name, func(t *testing.T) {
			l8AssertWorkerV2GuardAllows(t, map[string]string{"protocol_decode.go": source}, policy)
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"protocol_decode.go": `package sandboxworker
import (
	"encoding/json"
	"errors"
	"io"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)
type Request struct { Metadata *sandboxruntime.RuntimeTemplateStatusMetadata }
func decodeWorkerRequest(reader io.Reader, output *Request) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}`,
	}, policy, "implicit interface callback")
}

func TestL8WorkerV2GuardAllowsSafeMixedEnvelopeFieldsAndTypedClient(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{
			"job_v2_client.go": true,
			"job_v2_types.go":  true,
		},
		mixed: map[string]bool{
			"client.go": true,
			"types.go":  true,
		},
	}
	safeEnvelope := map[string]string{
		"job_v2_types.go": `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
type JobStartRequestV2 struct {
	ContractVersion string ` + "`json:\"contractVersion\"`" + `
}
type JobV2 struct {
	ID string ` + "`json:\"id\"`" + `
}`,
		"types.go": `package sandboxworker
type Request struct {
	Operation  string             ` + "`json:\"operation\"`" + `
	JobStartV2 *JobStartRequestV2 ` + "`json:\"jobStartV2,omitempty\"`" + `
}
type Response struct {
	OK    bool   ` + "`json:\"ok\"`" + `
	JobV2 *JobV2 ` + "`json:\"jobV2,omitempty\"`" + `
}`,
	}
	l8AssertWorkerV2GuardAllows(t, safeEnvelope, policy)

	clientSources := l8CloneWorkerV2GuardSources(safeEnvelope)
	clientSources["client.go"] = `package sandboxworker
import "context"
type Client struct{}
func (client *Client) roundTrip(context.Context, Request) (Response, error) {
	return Response{OK: true, JobV2: &JobV2{ID: "job-safe"}}, nil
}`
	clientSources["job_v2_client.go"] = `package sandboxworker
import "context"
func (client *Client) StartJobV2(ctx context.Context, request JobStartRequestV2) (*JobV2, error) {
	response, err := client.roundTrip(ctx, Request{Operation: OperationJobStartV2, JobStartV2: &request})
	if err != nil {
		return nil, err
	}
	return response.JobV2, nil
}`
	l8AssertWorkerV2GuardAllows(t, clientSources, policy)

	forbiddenField := l8CloneWorkerV2GuardSources(safeEnvelope)
	forbiddenField["types.go"] = `package sandboxworker
type Request struct {
	JobStartV2 *JobStartRequestV2 ` + "`json:\"jobStartV2,omitempty\"`" + `
	SecretV2   string             ` + "`json:\"secretValue,omitempty\"`" + `
}`
	l8AssertWorkerV2GuardRejects(t, forbiddenField, policy, `json:\"secret`)

	forbiddenClosure := l8CloneWorkerV2GuardSources(safeEnvelope)
	forbiddenClosure["job_v2_types.go"] = `package sandboxworker
type JobStartRequestV2 struct {
	Credential jobCredentialRecord
}
type JobV2 struct{ ID string }`
	forbiddenClosure["shared.go"] = `package sandboxworker
type jobCredentialRecord struct{ Label string }`
	l8AssertWorkerV2GuardRejects(t, forbiddenClosure, policy, "outside the exact allowlist")
}

func l8CloneWorkerV2GuardSources(sources map[string]string) map[string]string {
	cloned := make(map[string]string, len(sources))
	for path, source := range sources {
		cloned[path] = source
	}
	return cloned
}

type l8WorkerV2GuardPolicy struct {
	dedicated map[string]bool
	mixed     map[string]bool
}

func l8WorkerV2ProductionGuardPolicy() l8WorkerV2GuardPolicy {
	return l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{
			"job_manager_v2.go":  true,
			"job_service_v2.go":  true,
			"job_store_v2.go":    true,
			"job_v2_client.go":   true,
			"job_v2_helpers.go":  true,
			"job_v2_service.go":  true,
			"job_v2_types.go":    true,
			"protocol_decode.go": true,
		},
		mixed: map[string]bool{
			"client.go":      true,
			"handler.go":     true,
			"job_helpers.go": true,
			"server.go":      true,
			"types.go":       true,
		},
	}
}

func (policy l8WorkerV2GuardPolicy) allows(path string) bool {
	base := filepath.Base(path)
	return policy.dedicated[base] || policy.mixed[base]
}

type l8WorkerV2ParsedFile struct {
	path           string
	fileSet        *token.FileSet
	parsed         *ast.File
	imports        map[string]string
	alwaysImports  []string
	globalImports  []string
	valueSpecUnits map[*ast.ValueSpec][]*ast.ValueSpec
}

type l8WorkerV2GuardScope struct {
	file                  *l8WorkerV2ParsedFile
	node                  ast.Node
	initializerEvaluation bool
	terminalAnalysis      *l8WorkerV2TerminalAnalysis
}

type l8WorkerV2TerminalAnalysis struct {
	declarations   map[*types.Func]*ast.FuncDecl
	memo           map[*types.Func]bool
	visiting       map[*types.Func]bool
	localLiterals  map[types.Object]*ast.FuncLit
	literalAliases map[types.Object]types.Object
	mutableLocals  map[types.Object]bool
	literalMemo    map[*ast.FuncLit]bool
	literalVisit   map[*ast.FuncLit]bool
}

type l8WorkerV2SemanticUnit struct {
	scope       l8WorkerV2GuardScope
	definitions []types.Object
	uses        []types.Object
	tainted     bool
}

type l8WorkerV2OperationAnalysis struct {
	declarations map[*types.Func]*ast.FuncDecl
	results      map[*types.Func]map[int]bool
	staticValues map[types.Object]ast.Expr
}

const l8WorkerV2MaxExactOperationLength = len("job_resolve_v2")

func l8AuditWorkerV2Sources(sources map[string]string, policy l8WorkerV2GuardPolicy) error {
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	fileSet := token.NewFileSet()
	parsedFiles := make([]*l8WorkerV2ParsedFile, 0, len(paths))
	filesByAST := make(map[*ast.File]*l8WorkerV2ParsedFile, len(paths))
	var roots []l8WorkerV2GuardScope
	for _, path := range paths {
		parsed, err := parser.ParseFile(fileSet, path, sources[path], 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		valueSpecUnits, err := l8WorkerV2NormalizeValueSpecUnits(parsed)
		if err != nil {
			return fmt.Errorf("normalize value declarations in %s: %w", path, err)
		}
		file := &l8WorkerV2ParsedFile{
			path:           path,
			fileSet:        fileSet,
			parsed:         parsed,
			imports:        make(map[string]string, len(parsed.Imports)),
			valueSpecUnits: valueSpecUnits,
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("unquote import in %s: %w", path, err)
			}
			name := filepath.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "_" {
				file.alwaysImports = append(file.alwaysImports, importPath)
				file.globalImports = append(file.globalImports, importPath)
				continue
			}
			if name == "." {
				file.alwaysImports = append(file.alwaysImports, importPath)
				continue
			}
			file.imports[name] = importPath
		}
		parsedFiles = append(parsedFiles, file)
		filesByAST[parsed] = file

		base := filepath.Base(path)
		containsV2 := l8WorkerV2ASTContainsMarker(parsed)
		if containsV2 && !policy.allows(path) {
			return fmt.Errorf("production file %s contains worker-v2 declarations/references outside the exact allowlist", path)
		}
		switch {
		case policy.dedicated[base]:
			for _, declaration := range parsed.Decls {
				if generated, ok := declaration.(*ast.GenDecl); ok && generated.Tok == token.IMPORT {
					continue
				}
				for _, unit := range l8WorkerV2DeclarationUnits(declaration) {
					roots = append(roots, l8WorkerV2GuardScope{file: file, node: unit})
				}
			}
		case policy.mixed[base] && containsV2:
			for _, declaration := range parsed.Decls {
				for _, node := range l8WorkerV2MixedDeclarationScopes(declaration, file.valueSpecUnits) {
					roots = append(roots, l8WorkerV2GuardScope{file: file, node: node})
				}
			}
		}
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	astFiles := make([]*ast.File, 0, len(parsedFiles))
	for _, file := range parsedFiles {
		astFiles = append(astFiles, file.parsed)
	}
	var typeImporter types.Importer = importer.Default()
	for _, file := range parsedFiles {
		allImports := append(append([]string(nil), file.alwaysImports...), l8WorkerV2ImportValues(file.imports)...)
		for _, importPath := range allImports {
			if strings.HasPrefix(importPath, "github.com/jywlabs/hal/") {
				typeImporter = importer.ForCompiler(fileSet, "source", nil)
				break
			}
		}
	}
	config := types.Config{Importer: l8WorkerV2GuardImporter{fallback: typeImporter}}
	checkedPackage, err := config.Check("github.com/jywlabs/hal/internal/sandboxworker", fileSet, astFiles, info)
	if err != nil {
		return fmt.Errorf("type-check worker-v2 guard sources: %w", err)
	}
	if err := l8WorkerV2ValidateDecoderCallerComposition(parsedFiles, info); err != nil {
		return err
	}
	if err := l8WorkerV2ValidateClientHalfCloseComposition(parsedFiles, info); err != nil {
		return err
	}
	operationAnalysis := l8WorkerV2BuildOperationAnalysis(parsedFiles, info)
	semanticRoots := l8WorkerV2SemanticRoots(parsedFiles, info, operationAnalysis)
	roots = append(roots, semanticRoots...)
	if len(roots) == 0 {
		return nil
	}
	if err := l8RejectWorkerV2PackageGlobalForbiddenImports(parsedFiles); err != nil {
		return err
	}
	roots = append(roots, l8WorkerV2RuntimeOperationAssemblyRoots(parsedFiles, info, policy, operationAnalysis)...)
	// Every explicit init body and package-variable value expression executes
	// before any request can reach a V2 handler. These evaluation-only roots may
	// live outside the D1C allowlist, but they do not make deferred V1 functions
	// or unrelated declarations general V2 roots.
	roots = append(roots, l8WorkerV2PackageInitializerRoots(parsedFiles)...)

	objects := make(map[types.Object]l8WorkerV2GuardScope)
	for _, file := range parsedFiles {
		for _, declaration := range file.parsed.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if object := info.Defs[typed.Name]; object != nil {
					objects[object] = l8WorkerV2GuardScope{file: file, node: typed}
				}
			case *ast.GenDecl:
				if typed.Tok == token.IMPORT {
					continue
				}
				for _, spec := range typed.Specs {
					switch value := spec.(type) {
					case *ast.TypeSpec:
						if object := info.Defs[value.Name]; object != nil {
							objects[object] = l8WorkerV2GuardScope{file: file, node: value}
						}
					case *ast.ValueSpec:
						for _, unit := range file.valueSpecUnits[value] {
							for _, name := range unit.Names {
								if object := info.Defs[name]; object != nil {
									objects[object] = l8WorkerV2GuardScope{file: file, node: unit}
								}
							}
						}
					}
				}
			}
		}
	}
	staticFunctionAliases := l8WorkerV2StaticFunctionAliases(parsedFiles, info, objects)

	type selectedScope struct {
		node                  ast.Node
		initializerEvaluation bool
	}
	selected := make(map[selectedScope]bool)
	queue := make([]l8WorkerV2GuardScope, 0, len(roots))
	selectScope := func(scope l8WorkerV2GuardScope) error {
		key := selectedScope{node: scope.node, initializerEvaluation: scope.initializerEvaluation}
		if scope.node == nil || selected[key] {
			return nil
		}
		if !scope.initializerEvaluation && !policy.allows(scope.file.path) && !l8WorkerV2AllowedCompatibilityDeclaration(scope) {
			name := "declaration"
			switch typed := scope.node.(type) {
			case *ast.FuncDecl:
				name = typed.Name.Name
			case *ast.TypeSpec:
				name = typed.Name.Name
			case *ast.ValueSpec:
				if len(typed.Names) > 0 {
					name = typed.Names[0].Name
				}
			}
			return fmt.Errorf("worker-v2 declaration closure reaches production file %s declaration %s outside the exact allowlist", scope.file.path, name)
		}
		selected[key] = true
		queue = append(queue, scope)
		return nil
	}
	for _, root := range roots {
		if err := selectScope(root); err != nil {
			return err
		}
	}

	for len(queue) > 0 {
		scope := queue[0]
		queue = queue[1:]
		if l8WorkerV2LockedV1CompatibilityDeclaration(scope) {
			continue
		}
		if err := l8InspectWorkerV2Scope(scope, info, staticFunctionAliases, operationAnalysis); err != nil {
			return err
		}
		if err := l8RejectWorkerV2ForbiddenSurface(scope); err != nil {
			return err
		}
		if function, ok := scope.node.(*ast.FuncDecl); ok && function.Body == nil {
			return fmt.Errorf("worker-v2 production path in %s reaches forbidden bodyless declaration", scope.file.path)
		}
		if scope.initializerEvaluation {
			for _, function := range l8WorkerV2InitializerInvokedFunctions(scope, info, staticFunctionAliases) {
				referenced, ok := objects[function]
				if !ok {
					continue
				}
				referenced.initializerEvaluation = true
				if err := selectScope(referenced); err != nil {
					return err
				}
			}
		}
		var closureErr error
		l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
			if closureErr != nil {
				return false
			}
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			object := info.Uses[identifier]
			if object == nil || object.Pkg() != checkedPackage {
				return true
			}
			if _, isFunction := object.(*types.Func); isFunction && scope.initializerEvaluation {
				// Initializer expressions execute calls, not merely stored named
				// function values. Exact direct and immutable-alias calls are rooted
				// separately above.
				return true
			}
			referenced, ok := objects[object]
			if !ok {
				return true
			}
			for _, narrowed := range l8WorkerV2ReferencedDeclarationScopes(referenced) {
				narrowed.initializerEvaluation = scope.initializerEvaluation
				if err := selectScope(narrowed); err != nil {
					closureErr = err
					return false
				}
			}
			return true
		})
		if closureErr != nil {
			return closureErr
		}
	}
	return nil
}

func l8WorkerV2AllowedCompatibilityDeclaration(scope l8WorkerV2GuardScope) bool {
	if filepath.Base(scope.file.path) != "exec.go" {
		return false
	}
	switch typed := scope.node.(type) {
	case *ast.TypeSpec:
		return typed.Name.Name == "ExecRequest" && l8WorkerV2DeclarationDigest(scope) == "44d05fedce4c14a73f3a0436d59bc7d6dd829c1b937c393755ee8a37717e87b8"
	case *ast.FuncDecl:
		if typed.Name.Name != "Validate" || typed.Recv == nil || len(typed.Recv.List) != 1 {
			return false
		}
		receiver := typed.Recv.List[0].Type
		if pointer, ok := receiver.(*ast.StarExpr); ok {
			receiver = pointer.X
		}
		identifier, ok := receiver.(*ast.Ident)
		if !ok {
			return false
		}
		return identifier.Name == "ExecRequest" && l8WorkerV2DeclarationDigest(scope) == "682ec7b9a175527065baef078c937c7031a3cd64a8776e7c16440aec938a75c1"
	}
	return false
}

func l8WorkerV2LockedV1CompatibilityDeclaration(scope l8WorkerV2GuardScope) bool {
	if scope.file == nil || scope.file.parsed == nil || l8WorkerV2ASTContainsMarker(scope.node) {
		return false
	}
	base := filepath.Base(scope.file.path)
	switch base {
	case "client.go":
		function, ok := scope.node.(*ast.FuncDecl)
		if !ok || function.Recv != nil {
			return false
		}
		expected := map[string]string{
			"sanitizeProtocolErrorDetail":    "f037db919f22d39bcf49576976323284c0c792bb7bccfd7c696fb33a772fc9dc",
			"validateClientIOResponseLimits": "7a13178e2ab04e6ed902ac00706ab8dd16e51374ff7fe7412e84f65b76c44021",
		}[function.Name.Name]
		return expected != "" && l8WorkerV2DeclarationDigest(scope) == expected
	case "types.go":
		function, ok := scope.node.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Validate" || function.Recv == nil || len(function.Recv.List) != 1 {
			return false
		}
		receiver := function.Recv.List[0].Type
		if pointer, ok := receiver.(*ast.StarExpr); ok {
			receiver = pointer.X
		}
		identifier, ok := receiver.(*ast.Ident)
		if !ok {
			return false
		}
		expected := map[string]string{
			"Request":  "805caa08835f7aaf31c17b78e4ecfd81b93f4be514c6b63f3493b91af2224ac8",
			"Response": "bb78d61280818156524648c118d69a31f0c89975b83736d957e119e0a0874451",
		}[identifier.Name]
		return expected != "" && l8WorkerV2DeclarationDigest(scope) == expected
	case "exec.go":
		return l8WorkerV2AllowedCompatibilityDeclaration(scope)
	default:
		return false
	}
}

func l8WorkerV2DeclarationDigest(scope l8WorkerV2GuardScope) string {
	buffer := &bytes.Buffer{}
	if scope.file == nil || scope.file.fileSet == nil || scope.node == nil || format.Node(buffer, scope.file.fileSet, scope.node) != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(buffer.Bytes()))
}

func l8WorkerV2StaticFunctionAliases(files []*l8WorkerV2ParsedFile, info *types.Info, objects map[types.Object]l8WorkerV2GuardScope) map[types.Object]*types.Func {
	mutated := make(map[types.Object]bool)
	for _, file := range files {
		ast.Inspect(file.parsed, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || assignment.Tok == token.DEFINE {
				return true
			}
			for _, target := range assignment.Lhs {
				if object := l8WorkerV2ExpressionObject(target, info); object != nil {
					mutated[object] = true
				}
			}
			return true
		})
	}
	aliases := make(map[types.Object]*types.Func)
	for changed := true; changed; {
		changed = false
		for object, scope := range objects {
			variable, ok := object.(*types.Var)
			if !ok || mutated[variable] || aliases[variable] != nil {
				continue
			}
			spec, ok := scope.node.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range spec.Names {
				if info.Defs[name] != variable {
					continue
				}
				valueIndex := l8WorkerV2PairedExpressionIndex(index, len(spec.Values))
				if valueIndex < 0 {
					continue
				}
				called := l8WorkerV2CalledObject(spec.Values[valueIndex], info)
				function, isFunction := called.(*types.Func)
				if !isFunction {
					function = aliases[called]
				}
				if function != nil {
					aliases[variable] = function
					changed = true
				}
			}
		}
	}
	return aliases
}

func l8WorkerV2InitializerInvokedFunctions(scope l8WorkerV2GuardScope, info *types.Info, aliases map[types.Object]*types.Func) []*types.Func {
	seen := make(map[*types.Func]bool)
	var result []*types.Func
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		object := l8WorkerV2CalledObject(call.Fun, info)
		function, ok := object.(*types.Func)
		if !ok {
			function = aliases[object]
		}
		if function != nil && !seen[function] {
			seen[function] = true
			result = append(result, function)
		}
		return true
	})
	return result
}

func l8WorkerV2SemanticRoots(files []*l8WorkerV2ParsedFile, info *types.Info, analysis *l8WorkerV2OperationAnalysis) []l8WorkerV2GuardScope {
	var units []l8WorkerV2SemanticUnit
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			for _, node := range l8WorkerV2SemanticDeclarationUnits(declaration, file.valueSpecUnits) {
				unit := l8WorkerV2SemanticUnit{
					scope:   l8WorkerV2GuardScope{file: file, node: node},
					tainted: l8WorkerV2ASTContainsMarker(node) || l8WorkerV2ContainsExactOperationConstant(node, info, analysis),
				}
				ast.Inspect(node, func(candidate ast.Node) bool {
					identifier, ok := candidate.(*ast.Ident)
					if !ok {
						return true
					}
					if object := info.Defs[identifier]; object != nil {
						unit.definitions = append(unit.definitions, object)
					}
					if object := info.Uses[identifier]; object != nil {
						unit.uses = append(unit.uses, object)
					}
					return true
				})
				units = append(units, unit)
			}
		}
	}

	taintedObjects := make(map[types.Object]bool)
	addDefinitions := func(unit l8WorkerV2SemanticUnit) {
		for _, object := range unit.definitions {
			taintedObjects[object] = true
		}
	}
	for _, unit := range units {
		if unit.tainted {
			addDefinitions(unit)
		}
	}
	for changed := true; changed; {
		changed = false
		for index := range units {
			if units[index].tainted {
				continue
			}
			for _, object := range units[index].uses {
				if !taintedObjects[object] {
					continue
				}
				units[index].tainted = true
				addDefinitions(units[index])
				changed = true
				break
			}
		}
	}

	var roots []l8WorkerV2GuardScope
	for _, unit := range units {
		if unit.tainted {
			roots = append(roots, unit.scope)
		}
	}
	return roots
}

func l8WorkerV2RuntimeOperationAssemblyRoots(files []*l8WorkerV2ParsedFile, info *types.Info, policy l8WorkerV2GuardPolicy, analysis *l8WorkerV2OperationAnalysis) []l8WorkerV2GuardScope {
	var roots []l8WorkerV2GuardScope
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			for _, node := range l8WorkerV2SemanticDeclarationUnits(declaration, file.valueSpecUnits) {
				scope := l8WorkerV2GuardScope{file: file, node: node}
				invalid, recoverableV2 := l8WorkerV2ContainsInvalidOperationValue(scope, info, analysis)
				if invalid && (recoverableV2 || policy.dedicated[filepath.Base(file.path)]) {
					roots = append(roots, l8WorkerV2GuardScope{file: file, node: node})
				}
			}
		}
	}
	return roots
}

func l8WorkerV2PackageInitializerRoots(files []*l8WorkerV2ParsedFile) []l8WorkerV2GuardScope {
	var roots []l8WorkerV2GuardScope
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			if generated, ok := declaration.(*ast.GenDecl); ok && generated.Tok == token.VAR {
				for _, rawSpec := range generated.Specs {
					spec, ok := rawSpec.(*ast.ValueSpec)
					if !ok || len(spec.Values) == 0 {
						continue
					}
					for _, expression := range spec.Values {
						roots = append(roots, l8WorkerV2GuardScope{
							file:                  file,
							node:                  expression,
							initializerEvaluation: true,
						})
					}
				}
			}
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || function.Name.Name != "init" {
				continue
			}
			roots = append(roots, l8WorkerV2GuardScope{
				file:                  file,
				node:                  function,
				initializerEvaluation: true,
			})
		}
	}
	return roots
}

func l8WorkerV2InspectScopeAST(scope l8WorkerV2GuardScope, inspect func(ast.Node) bool) {
	if scope.node == nil {
		return
	}
	if !scope.initializerEvaluation {
		ast.Inspect(scope.node, inspect)
		return
	}
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(scope.node, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})

	executed := make(map[*ast.FuncLit]bool)
	resolved := make(map[*ast.FuncLit]bool)
	var executes func(*ast.FuncLit) bool
	executes = func(literal *ast.FuncLit) bool {
		if resolved[literal] {
			return executed[literal]
		}
		resolved[literal] = true
		parent := parents[literal]
		for {
			if _, ok := parent.(*ast.ParenExpr); !ok {
				break
			}
			parent = parents[parent]
		}
		call, ok := parent.(*ast.CallExpr)
		if !ok || l8WorkerV2UnparenExpression(call.Fun) != literal {
			return false
		}
		for ancestor := parents[call]; ancestor != nil; ancestor = parents[ancestor] {
			if outer, ok := ancestor.(*ast.FuncLit); ok && !executes(outer) {
				return false
			}
		}
		executed[literal] = true
		return true
	}

	ast.Inspect(scope.node, func(node ast.Node) bool {
		if literal, ok := node.(*ast.FuncLit); ok && !executes(literal) {
			inspect(node)
			return false
		}
		return inspect(node)
	})
}

func l8WorkerV2BuildOperationAnalysis(files []*l8WorkerV2ParsedFile, info *types.Info) *l8WorkerV2OperationAnalysis {
	analysis := &l8WorkerV2OperationAnalysis{
		declarations: make(map[*types.Func]*ast.FuncDecl),
		results:      make(map[*types.Func]map[int]bool),
		staticValues: make(map[types.Object]ast.Expr),
	}
	functionScopes := make(map[*types.Func]l8WorkerV2GuardScope)
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			if generated, ok := declaration.(*ast.GenDecl); ok && (generated.Tok == token.VAR || generated.Tok == token.CONST) {
				for _, rawSpec := range generated.Specs {
					spec, ok := rawSpec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for index, name := range spec.Names {
						if len(spec.Values) != len(spec.Names) || index >= len(spec.Values) {
							continue
						}
						if object := info.Defs[name]; object != nil {
							analysis.staticValues[object] = spec.Values[index]
						}
					}
				}
			}
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			object, ok := info.Defs[function.Name].(*types.Func)
			if !ok {
				continue
			}
			analysis.declarations[object] = function
			functionScopes[object] = l8WorkerV2GuardScope{file: file, node: function}
		}
	}
	for iteration := 0; iteration < l8WorkerV2MaxExactOperationLength; iteration++ {
		changed := false
		for function, scope := range functionScopes {
			signature, _ := function.Type().Underlying().(*types.Signature)
			if signature == nil || signature.Results() == nil || signature.Results().Len() == 0 {
				continue
			}
			aliases := l8WorkerV2OperationAliases(scope, info, analysis)
			ast.Inspect(analysis.declarations[function].Body, func(node ast.Node) bool {
				if _, nested := node.(*ast.FuncLit); nested {
					return false
				}
				returned, ok := node.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for resultIndex := 0; resultIndex < signature.Results().Len(); resultIndex++ {
					expression, component, ok := l8WorkerV2ResultExpression(resultIndex, signature.Results().Len(), returned.Results)
					if !ok || !l8WorkerV2OperationValueAt(expression, component, info, aliases, analysis) {
						continue
					}
					if analysis.results[function] == nil {
						analysis.results[function] = make(map[int]bool)
					}
					if !analysis.results[function][resultIndex] {
						analysis.results[function][resultIndex] = true
						changed = true
					}
				}
				return false
			})
		}
		if !changed {
			break
		}
	}
	return analysis
}

func l8WorkerV2ResultExpression(index, resultCount int, expressions []ast.Expr) (ast.Expr, int, bool) {
	if index < 0 || len(expressions) == 0 {
		return nil, 0, false
	}
	if len(expressions) == resultCount && index < len(expressions) {
		return expressions[index], 0, true
	}
	if len(expressions) == 1 && index < resultCount {
		return expressions[0], index, true
	}
	return nil, 0, false
}

func l8WorkerV2AssignmentExpression(index, targetCount int, expressions []ast.Expr) (ast.Expr, int, bool) {
	return l8WorkerV2ResultExpression(index, targetCount, expressions)
}

func l8WorkerV2OperationValueAt(expression ast.Expr, component int, info *types.Info, aliases map[types.Object]bool, analysis *l8WorkerV2OperationAnalysis) bool {
	if expression == nil || component < 0 {
		return false
	}
	if component == 0 {
		if _, tuple := info.TypeOf(expression).(*types.Tuple); !tuple && l8WorkerV2IsOperationTarget(expression, info, aliases) {
			return true
		}
	}
	call, ok := l8WorkerV2UnparenExpression(expression).(*ast.CallExpr)
	if !ok || analysis == nil {
		return false
	}
	function, _ := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
	return function != nil && analysis.results[function][component]
}

func l8WorkerV2ContainsInvalidOperationValue(scope l8WorkerV2GuardScope, info *types.Info, analysis *l8WorkerV2OperationAnalysis) (bool, bool) {
	if scope.node == nil || info == nil {
		return false, false
	}
	// Arbitrary runtime string construction is undecidable. The guard therefore
	// enforces a structural invariant at identifiable operation definitions,
	// assignments, request fields, comparisons, switch cases, and returns: D1C
	// values must remain compile-time constants. Exact D1C files and units in the
	// V2 dependency closure fail closed on unknown runtime values. Outside that
	// scope, only statically recoverable V2 construction becomes a new root, so
	// unchanged V1 operation helpers are not swept into the D1C allowlist.
	invalid := false
	recoverableV2 := false
	operationAliases := l8WorkerV2OperationAliases(scope, info, analysis)
	inspectValue := func(expression ast.Expr) {
		if expression == nil || !l8WorkerV2IsStringType(info.TypeOf(expression)) {
			return
		}
		if info.Types[expression].Value != nil {
			return
		}
		invalid = true
		if value, known := l8WorkerV2StaticString(expression, info, analysis); known && l8WorkerV2IsExactOperationString(value) {
			recoverableV2 = true
		}
	}
	var inspectValueAt func(ast.Expr, int, map[*types.Func]bool, int)
	inspectValueAt = func(expression ast.Expr, component int, seen map[*types.Func]bool, depth int) {
		if expression == nil || depth >= l8WorkerV2MaxExactOperationLength {
			inspectValue(expression)
			return
		}
		call, ok := l8WorkerV2UnparenExpression(expression).(*ast.CallExpr)
		if !ok || analysis == nil {
			inspectValue(expression)
			return
		}
		function, _ := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
		declaration := analysis.declarations[function]
		if function == nil || declaration == nil || seen[function] {
			inspectValue(expression)
			return
		}
		seen[function] = true
		defer delete(seen, function)
		signature, _ := function.Type().Underlying().(*types.Signature)
		if signature == nil || signature.Results() == nil || component >= signature.Results().Len() {
			inspectValue(expression)
			return
		}
		resolved := false
		helperScope := l8WorkerV2GuardScope{file: scope.file, node: declaration}
		helperAliases := l8WorkerV2OperationAliases(helperScope, info, analysis)
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			returned, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			value, nestedComponent, ok := l8WorkerV2ResultExpression(component, signature.Results().Len(), returned.Results)
			if !ok {
				return false
			}
			resolved = true
			if !l8WorkerV2OperationValueAt(value, nestedComponent, info, helperAliases, analysis) {
				inspectValueAt(value, nestedComponent, seen, depth+1)
			}
			return false
		})
		if !resolved {
			inspectValue(expression)
		}
	}
	if function, ok := scope.node.(*ast.FuncDecl); ok && l8WorkerV2FunctionIdentifiesOperationReturn(function, info) {
		ast.Inspect(function.Body, func(candidate ast.Node) bool {
			if literal, ok := candidate.(*ast.FuncLit); ok && literal != nil {
				return false
			}
			returned, ok := candidate.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, expression := range returned.Results {
				inspectValue(expression)
			}
			return false
		})
	}
	l8WorkerV2InspectScopeAST(scope, func(candidate ast.Node) bool {
		switch typed := candidate.(type) {
		case *ast.ValueSpec:
			for index, name := range typed.Names {
				value, component, ok := l8WorkerV2AssignmentExpression(index, len(typed.Names), typed.Values)
				if ok && l8WorkerV2IsOperationTarget(name, info, operationAliases) {
					propagated := !l8WorkerV2IsOperationTarget(name, info, nil) && l8WorkerV2OperationValueAt(value, component, info, operationAliases, analysis)
					if !propagated {
						inspectValueAt(value, component, make(map[*types.Func]bool), 0)
					}
				}
			}
		case *ast.AssignStmt:
			for index, left := range typed.Lhs {
				value, component, ok := l8WorkerV2AssignmentExpression(index, len(typed.Lhs), typed.Rhs)
				if ok && l8WorkerV2IsOperationTarget(left, info, operationAliases) {
					propagated := !l8WorkerV2IsOperationTarget(left, info, nil) && l8WorkerV2OperationValueAt(value, component, info, operationAliases, analysis)
					if !propagated {
						inspectValueAt(value, component, make(map[*types.Func]bool), 0)
					}
				}
			}
		case *ast.KeyValueExpr:
			identifier, ok := typed.Key.(*ast.Ident)
			if ok && l8WorkerV2ObjectIdentifiesOperationField(info.Uses[identifier]) {
				if !l8WorkerV2OperationValueAt(typed.Value, 0, info, operationAliases, analysis) {
					inspectValueAt(typed.Value, 0, make(map[*types.Func]bool), 0)
				}
			}
		case *ast.CompositeLit:
			literalType := info.TypeOf(typed)
			if literalType == nil {
				break
			}
			structType, ok := types.Unalias(literalType).Underlying().(*types.Struct)
			if !ok {
				break
			}
			for index, rawElement := range typed.Elts {
				if _, keyed := rawElement.(*ast.KeyValueExpr); keyed || index >= structType.NumFields() {
					continue
				}
				expression := rawElement
				if l8WorkerV2ObjectIdentifiesOperationField(structType.Field(index)) && !l8WorkerV2OperationValueAt(expression, 0, info, operationAliases, analysis) {
					inspectValueAt(expression, 0, make(map[*types.Func]bool), 0)
				}
			}
		case *ast.BinaryExpr:
			if typed.Op != token.EQL && typed.Op != token.NEQ {
				break
			}
			leftOperation := l8WorkerV2IsOperationTarget(typed.X, info, operationAliases)
			rightOperation := l8WorkerV2IsOperationTarget(typed.Y, info, operationAliases)
			switch {
			case leftOperation && rightOperation:
				// Comparing two operation-bearing values propagates or validates an
				// operation; it does not assemble a new identifier.
			case leftOperation:
				inspectValue(typed.Y)
			case rightOperation:
				inspectValue(typed.X)
			}
		case *ast.SwitchStmt:
			if typed.Tag == nil || !l8WorkerV2IsOperationTarget(typed.Tag, info, operationAliases) {
				break
			}
			for _, statement := range typed.Body.List {
				clause, ok := statement.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expression := range clause.List {
					if !l8WorkerV2OperationValueAt(expression, 0, info, operationAliases, analysis) {
						inspectValueAt(expression, 0, make(map[*types.Func]bool), 0)
					}
				}
			}
		}
		return true
	})
	return invalid, recoverableV2
}

func l8WorkerV2OperationAliases(scope l8WorkerV2GuardScope, info *types.Info, analysis *l8WorkerV2OperationAnalysis) map[types.Object]bool {
	aliases := make(map[types.Object]bool)
	for changed := true; changed; {
		changed = false
		l8WorkerV2InspectScopeAST(scope, func(candidate ast.Node) bool {
			var left []ast.Expr
			var right []ast.Expr
			switch typed := candidate.(type) {
			case *ast.ValueSpec:
				for _, name := range typed.Names {
					left = append(left, name)
				}
				right = typed.Values
			case *ast.AssignStmt:
				left = typed.Lhs
				right = typed.Rhs
			default:
				return true
			}
			for index, target := range left {
				value, component, ok := l8WorkerV2AssignmentExpression(index, len(left), right)
				if !ok || !l8WorkerV2OperationValueAt(value, component, info, aliases, analysis) {
					continue
				}
				object := l8WorkerV2ExpressionObject(target, info)
				if object != nil && !aliases[object] {
					aliases[object] = true
					changed = true
				}
			}
			return true
		})
	}
	return aliases
}

func l8WorkerV2PairedExpressionIndex(index, expressionCount int) int {
	if expressionCount == 0 {
		return -1
	}
	if index < expressionCount {
		return index
	}
	return expressionCount - 1
}

func l8WorkerV2FunctionIdentifiesOperationReturn(function *ast.FuncDecl, info *types.Info) bool {
	if function == nil || function.Type == nil || function.Type.Results == nil {
		return false
	}
	if l8WorkerV2ObjectIdentifiesOperation(info.Defs[function.Name]) {
		return true
	}
	for _, result := range function.Type.Results.List {
		for _, name := range result.Names {
			if l8WorkerV2IsOperationTarget(name, info, nil) {
				return true
			}
		}
		if identifier, ok := result.Type.(*ast.Ident); ok && l8WorkerV2ObjectIdentifiesOperation(info.Uses[identifier]) {
			return true
		}
	}
	return false
}

func l8WorkerV2IsOperationTarget(expression ast.Expr, info *types.Info, aliases map[types.Object]bool) bool {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.StarExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.SelectorExpr:
			object := info.Uses[typed.Sel]
			if variable, ok := object.(*types.Var); ok && variable.IsField() {
				return aliases[object] || l8WorkerV2ObjectIdentifiesOperationField(object) || l8WorkerV2TypeIdentifiesOperation(object.Type())
			}
			return aliases[object] || l8WorkerV2ObjectIdentifiesOperation(object)
		case *ast.Ident:
			object := info.Defs[typed]
			if object == nil {
				object = info.Uses[typed]
			}
			return aliases[object] || l8WorkerV2ObjectIdentifiesOperation(object) ||
				(object != nil && l8WorkerV2TypeIdentifiesOperation(object.Type()))
		default:
			return false
		}
	}
}

func l8WorkerV2ExpressionObject(expression ast.Expr, info *types.Info) types.Object {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.StarExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.SelectorExpr:
			if object := info.Uses[typed.Sel]; object != nil {
				return object
			}
			return nil
		case *ast.Ident:
			if object := info.Defs[typed]; object != nil {
				return object
			}
			return info.Uses[typed]
		default:
			return nil
		}
	}
}

func l8WorkerV2ObjectIdentifiesOperation(object types.Object) bool {
	return object != nil && strings.Contains(strings.ToLower(object.Name()), "operation")
}

func l8WorkerV2ObjectIdentifiesOperationField(object types.Object) bool {
	variable, ok := object.(*types.Var)
	return ok && variable.IsField() && strings.EqualFold(variable.Name(), "operation")
}

func l8WorkerV2TypeIdentifiesOperation(typ types.Type) bool {
	if alias, ok := typ.(*types.Alias); ok && alias.Obj() != nil && strings.EqualFold(alias.Obj().Name(), "operation") {
		return true
	}
	object := l8WorkerV2NamedTypeObject(typ)
	return object != nil && strings.EqualFold(object.Name(), "operation")
}

func l8WorkerV2IsStringType(typ types.Type) bool {
	if typ == nil {
		return false
	}
	basic, ok := types.Unalias(typ).Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func l8WorkerV2ContainsExactOperationConstant(node ast.Node, info *types.Info, analysis *l8WorkerV2OperationAnalysis) bool {
	if node == nil || info == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if found {
			return false
		}
		if expression, ok := candidate.(ast.Expr); ok {
			found = l8WorkerV2IsExactOperationConstant(info.Types[expression].Value)
			if !found {
				value, exact := l8WorkerV2StaticString(expression, info, analysis)
				found = exact && l8WorkerV2IsExactOperationString(value)
			}
		}
		identifier, ok := candidate.(*ast.Ident)
		if !ok || found {
			return !found
		}
		for _, object := range []types.Object{info.Defs[identifier], info.Uses[identifier]} {
			value, ok := object.(*types.Const)
			if ok && l8WorkerV2IsExactOperationConstant(value.Val()) {
				found = true
				break
			}
		}
		return !found
	})
	return found
}

func l8WorkerV2StaticString(expression ast.Expr, info *types.Info, analysis *l8WorkerV2OperationAnalysis) (string, bool) {
	if expression == nil || info == nil {
		return "", false
	}
	if value := info.Types[expression].Value; value != nil && value.Kind() == constant.String {
		return constant.StringVal(value), true
	}
	switch typed := expression.(type) {
	case *ast.ParenExpr:
		return l8WorkerV2StaticString(typed.X, info, analysis)
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", false
		}
		left, leftOK := l8WorkerV2StaticString(typed.X, info, analysis)
		right, rightOK := l8WorkerV2StaticString(typed.Y, info, analysis)
		if !leftOK || !rightOK {
			return "", false
		}
		if len(left) > l8WorkerV2MaxExactOperationLength-len(right) {
			return "", false
		}
		return left + right, true
	case *ast.IndexExpr:
		return l8WorkerV2StaticIndexedString(typed, info, analysis)
	case *ast.CallExpr:
		if len(typed.Args) == 1 && l8WorkerV2IsStringConversion(typed.Fun, info) {
			return l8WorkerV2StaticCodePoints(typed.Args[0], info, analysis)
		}
		return l8WorkerV2StaticStandardLibraryString(typed, info, analysis)
	default:
		return "", false
	}
}

func l8WorkerV2StaticIndexedString(indexed *ast.IndexExpr, info *types.Info, analysis *l8WorkerV2OperationAnalysis) (string, bool) {
	if indexed == nil {
		return "", false
	}
	indexValue := info.Types[indexed.Index].Value
	if indexValue == nil {
		return "", false
	}
	literal, ok := l8WorkerV2UnparenExpression(indexed.X).(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	typ := info.TypeOf(literal)
	if typ == nil {
		return "", false
	}
	switch types.Unalias(typ).Underlying().(type) {
	case *types.Map:
		for _, rawElement := range literal.Elts {
			keyed, ok := rawElement.(*ast.KeyValueExpr)
			if !ok {
				return "", false
			}
			keyValue := info.Types[keyed.Key].Value
			if keyValue != nil && constant.Compare(keyValue, token.EQL, indexValue) {
				return l8WorkerV2StaticString(keyed.Value, info, analysis)
			}
		}
		return "", false
	case *types.Array, *types.Slice:
		index, exact := constant.Int64Val(indexValue)
		if !exact || index < 0 || index >= int64(l8WorkerV2MaxExactOperationLength) {
			return "", false
		}
		nextIndex := int64(0)
		for _, rawElement := range literal.Elts {
			elementIndex := nextIndex
			if keyed, ok := rawElement.(*ast.KeyValueExpr); ok {
				value := info.Types[keyed.Key].Value
				if value == nil {
					return "", false
				}
				var keyExact bool
				elementIndex, keyExact = constant.Int64Val(value)
				if !keyExact {
					return "", false
				}
				rawElement = keyed.Value
			}
			if elementIndex == index {
				return l8WorkerV2StaticString(rawElement, info, analysis)
			}
			nextIndex = elementIndex + 1
		}
	}
	return "", false
}

func l8WorkerV2StaticStandardLibraryString(call *ast.CallExpr, info *types.Info, analysis *l8WorkerV2OperationAnalysis) (string, bool) {
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil {
		return "", false
	}
	switch object.Pkg().Path() + "." + object.Name() {
	case "strings.Join":
		if len(call.Args) != 2 {
			return "", false
		}
		parts, ok := l8WorkerV2StaticStringSlice(call.Args[0], info, analysis)
		if !ok {
			return "", false
		}
		separator, ok := l8WorkerV2StaticString(call.Args[1], info, analysis)
		if !ok {
			return "", false
		}
		length := len(separator) * max(0, len(parts)-1)
		for _, part := range parts {
			length += len(part)
			if length > l8WorkerV2MaxExactOperationLength {
				return "", false
			}
		}
		return strings.Join(parts, separator), true
	case "strings.Repeat":
		if len(call.Args) != 2 {
			return "", false
		}
		value, ok := l8WorkerV2StaticString(call.Args[0], info, analysis)
		countValue := info.Types[call.Args[1]].Value
		if countValue == nil {
			return "", false
		}
		count, exact := constant.Int64Val(countValue)
		if !ok || !exact || count < 0 || count > int64(l8WorkerV2MaxExactOperationLength) {
			return "", false
		}
		if count != 0 && len(value) > l8WorkerV2MaxExactOperationLength/int(count) {
			return "", false
		}
		return strings.Repeat(value, int(count)), true
	case "fmt.Sprintf":
		return l8WorkerV2StaticSprintf(call, info, analysis)
	default:
		return "", false
	}
}

func l8WorkerV2StaticStringSlice(expression ast.Expr, info *types.Info, analysis *l8WorkerV2OperationAnalysis) ([]string, bool) {
	return l8WorkerV2StaticStringSliceResolved(expression, info, analysis, make(map[types.Object]bool), 0)
}

func l8WorkerV2StaticStringSliceResolved(expression ast.Expr, info *types.Info, analysis *l8WorkerV2OperationAnalysis, visiting map[types.Object]bool, depth int) ([]string, bool) {
	if expression == nil || depth >= l8WorkerV2MaxExactOperationLength {
		return nil, false
	}
	unwrapped := l8WorkerV2UnparenExpression(expression)
	var sliced *ast.SliceExpr
	if expression, ok := unwrapped.(*ast.SliceExpr); ok {
		sliced = expression
		unwrapped = l8WorkerV2UnparenExpression(sliced.X)
	}
	if address, ok := unwrapped.(*ast.UnaryExpr); ok && address.Op == token.AND {
		unwrapped = l8WorkerV2UnparenExpression(address.X)
	}
	if identifier, ok := unwrapped.(*ast.Ident); ok && analysis != nil {
		object := info.Uses[identifier]
		if object == nil {
			object = info.Defs[identifier]
		}
		value := analysis.staticValues[object]
		if object == nil || value == nil || visiting[object] {
			return nil, false
		}
		visiting[object] = true
		defer delete(visiting, object)
		return l8WorkerV2StaticStringSliceResolved(value, info, analysis, visiting, depth+1)
	}
	literal, ok := unwrapped.(*ast.CompositeLit)
	if !ok || len(literal.Elts) > l8WorkerV2MaxExactOperationLength {
		return nil, false
	}
	typ := info.TypeOf(literal)
	if typ == nil {
		return nil, false
	}
	length := int64(-1)
	switch underlying := types.Unalias(typ).Underlying().(type) {
	case *types.Array:
		if !l8WorkerV2IsStringType(underlying.Elem()) {
			return nil, false
		}
		length = underlying.Len()
	case *types.Slice:
		if !l8WorkerV2IsStringType(underlying.Elem()) {
			return nil, false
		}
	default:
		return nil, false
	}
	if length > int64(l8WorkerV2MaxExactOperationLength) {
		return nil, false
	}
	indexedValues := make(map[int64]string, len(literal.Elts))
	nextIndex := int64(0)
	maxIndex := int64(-1)
	for _, rawElement := range literal.Elts {
		index := nextIndex
		if keyed, ok := rawElement.(*ast.KeyValueExpr); ok {
			indexValue := info.Types[keyed.Key].Value
			if indexValue == nil {
				return nil, false
			}
			var exact bool
			index, exact = constant.Int64Val(indexValue)
			if !exact {
				return nil, false
			}
			rawElement = keyed.Value
		}
		if index < 0 || index >= int64(l8WorkerV2MaxExactOperationLength) || (length >= 0 && index >= length) {
			return nil, false
		}
		value, ok := l8WorkerV2StaticString(rawElement, info, analysis)
		if !ok {
			return nil, false
		}
		indexedValues[index] = value
		if index > maxIndex {
			maxIndex = index
		}
		nextIndex = index + 1
	}
	if length < 0 {
		length = maxIndex + 1
	}
	values := make([]string, length)
	for index, value := range indexedValues {
		values[index] = value
	}
	if sliced == nil {
		return values, true
	}
	low, ok := l8WorkerV2StaticSliceBound(sliced.Low, 0, info)
	if !ok {
		return nil, false
	}
	high, ok := l8WorkerV2StaticSliceBound(sliced.High, length, info)
	if !ok || low < 0 || low > high || high > length {
		return nil, false
	}
	if sliced.Max != nil {
		maximum, ok := l8WorkerV2StaticSliceBound(sliced.Max, length, info)
		if !ok || maximum < high || maximum > length {
			return nil, false
		}
	}
	return values[low:high], true
}

func l8WorkerV2StaticSliceBound(expression ast.Expr, fallback int64, info *types.Info) (int64, bool) {
	if expression == nil {
		return fallback, true
	}
	value := info.Types[expression].Value
	if value == nil {
		return 0, false
	}
	bound, exact := constant.Int64Val(value)
	return bound, exact
}

func l8WorkerV2StaticSprintf(call *ast.CallExpr, info *types.Info, analysis *l8WorkerV2OperationAnalysis) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	formatValue, ok := l8WorkerV2StaticString(call.Args[0], info, analysis)
	if !ok || len(formatValue) > l8WorkerV2MaxExactOperationLength {
		return "", false
	}
	var result strings.Builder
	argumentIndex := 1
	for index := 0; index < len(formatValue); index++ {
		if formatValue[index] != '%' {
			result.WriteByte(formatValue[index])
			continue
		}
		index++
		if index >= len(formatValue) {
			return "", false
		}
		if formatValue[index] == '%' {
			result.WriteByte('%')
			continue
		}
		precision := -1
		if formatValue[index] == '.' {
			index++
			start := index
			for index < len(formatValue) && formatValue[index] >= '0' && formatValue[index] <= '9' {
				index++
			}
			if start == index || index >= len(formatValue) {
				return "", false
			}
			parsed, err := strconv.Atoi(formatValue[start:index])
			if err != nil || parsed < 0 || parsed > l8WorkerV2MaxExactOperationLength {
				return "", false
			}
			precision = parsed
		}
		if argumentIndex >= len(call.Args) {
			return "", false
		}
		argument := call.Args[argumentIndex]
		argumentIndex++
		switch formatValue[index] {
		case 's', 'v':
			if precision >= 0 && formatValue[index] != 's' {
				return "", false
			}
			value, exact := l8WorkerV2StaticString(argument, info, analysis)
			if !exact {
				return "", false
			}
			if precision >= 0 {
				runes := []rune(value)
				if precision < len(runes) {
					value = string(runes[:precision])
				}
			}
			result.WriteString(value)
		case 'c', 'd':
			if precision >= 0 {
				return "", false
			}
			constantValue := info.Types[argument].Value
			if constantValue == nil {
				return "", false
			}
			value, exact := constant.Int64Val(constantValue)
			if !exact {
				return "", false
			}
			if formatValue[index] == 'c' {
				if value < 0 || value > 0x10ffff {
					return "", false
				}
				result.WriteRune(rune(value))
			} else {
				result.WriteString(strconv.FormatInt(value, 10))
			}
		default:
			return "", false
		}
		if result.Len() > l8WorkerV2MaxExactOperationLength {
			return "", false
		}
	}
	if argumentIndex != len(call.Args) {
		return "", false
	}
	return result.String(), true
}

func l8WorkerV2UnparenExpression(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func l8WorkerV2IsStringConversion(expression ast.Expr, info *types.Info) bool {
	identifier, ok := expression.(*ast.Ident)
	if !ok || identifier.Name != "string" {
		return false
	}
	typeName, ok := info.Uses[identifier].(*types.TypeName)
	if !ok {
		return false
	}
	basic, ok := typeName.Type().Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func l8WorkerV2StaticCodePoints(expression ast.Expr, info *types.Info, _ *l8WorkerV2OperationAnalysis) (string, bool) {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.CallExpr:
			if len(typed.Args) != 1 {
				return "", false
			}
			if _, ok := info.TypeOf(typed.Fun).(*types.Signature); ok {
				return "", false
			}
			expression = typed.Args[0]
		default:
			goto unwrapped
		}
	}

unwrapped:
	literal, ok := expression.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	typ := info.TypeOf(literal)
	if typ == nil {
		return "", false
	}
	underlying := typ.Underlying()
	var element types.Type
	switch typed := underlying.(type) {
	case *types.Slice:
		element = typed.Elem()
	case *types.Array:
		element = typed.Elem()
	default:
		return "", false
	}
	basic, ok := types.Unalias(element).Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return "", false
	}
	indexedValues := make(map[int64]rune, len(literal.Elts))
	nextIndex := int64(0)
	maxIndex := int64(-1)
	for _, rawElement := range literal.Elts {
		index := nextIndex
		if keyed, ok := rawElement.(*ast.KeyValueExpr); ok {
			key := info.Types[keyed.Key].Value
			if key == nil || key.Kind() != constant.Int {
				return "", false
			}
			var exact bool
			index, exact = constant.Int64Val(key)
			if !exact || index < 0 {
				return "", false
			}
			rawElement = keyed.Value
		}
		if index >= int64(l8WorkerV2MaxExactOperationLength) {
			return "", false
		}
		expression := rawElement
		value := info.Types[expression].Value
		if value == nil || value.Kind() != constant.Int {
			return "", false
		}
		integer, exact := constant.Int64Val(value)
		if !exact || integer < 0 || integer > 0x10ffff {
			return "", false
		}
		indexedValues[index] = rune(integer)
		if index > maxIndex {
			maxIndex = index
		}
		nextIndex = index + 1
	}
	values := make([]rune, maxIndex+1)
	for index, value := range indexedValues {
		values[index] = value
	}
	if basic.Kind() == types.Uint8 {
		bytesValue := make([]byte, len(values))
		for index, value := range values {
			if value > 0xff {
				return "", false
			}
			bytesValue[index] = byte(value)
		}
		return string(bytesValue), true
	}
	return string(values), true
}

func l8WorkerV2IsExactOperationConstant(value constant.Value) bool {
	if value == nil || value.Kind() != constant.String {
		return false
	}
	return l8WorkerV2IsExactOperationString(constant.StringVal(value))
}

func l8WorkerV2IsExactOperationString(value string) bool {
	switch value {
	case "job_start_v2", "job_resolve_v2", "job_status_v2", "job_logs_v2", "job_cancel_v2":
		return true
	default:
		return false
	}
}

func l8WorkerV2SemanticDeclarationUnits(declaration ast.Decl, valueSpecUnits map[*ast.ValueSpec][]*ast.ValueSpec) []ast.Node {
	switch typed := declaration.(type) {
	case *ast.FuncDecl:
		return []ast.Node{typed}
	case *ast.GenDecl:
		if typed.Tok == token.IMPORT {
			return nil
		}
		var units []ast.Node
		for _, spec := range typed.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				for _, unit := range valueSpecUnits[valueSpec] {
					units = append(units, unit)
				}
				continue
			}
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || l8WorkerV2ASTContainsMarker(typeSpec.Name) {
				units = append(units, spec)
				continue
			}
			switch value := typeSpec.Type.(type) {
			case *ast.StructType:
				for _, field := range value.Fields.List {
					units = append(units, field)
				}
			case *ast.InterfaceType:
				for _, field := range value.Methods.List {
					units = append(units, field)
				}
			default:
				units = append(units, spec)
			}
		}
		return units
	default:
		return nil
	}
}

func l8WorkerV2NormalizeValueSpecUnits(file *ast.File) (map[*ast.ValueSpec][]*ast.ValueSpec, error) {
	unitsBySpec := make(map[*ast.ValueSpec][]*ast.ValueSpec)
	for _, declaration := range file.Decls {
		generated, ok := declaration.(*ast.GenDecl)
		if !ok || generated.Tok == token.IMPORT {
			continue
		}

		var inheritedValues []ast.Expr
		var inheritedType ast.Expr
		for _, rawSpec := range generated.Specs {
			spec, ok := rawSpec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			effective := spec
			if generated.Tok == token.CONST {
				switch {
				case len(spec.Values) > 0:
					inheritedValues = spec.Values
					inheritedType = spec.Type
				case len(inheritedValues) == 0:
					return nil, fmt.Errorf("const declaration omits values before a preceding expression list")
				default:
					clone := *spec
					clone.Type = inheritedType
					clone.Values = append([]ast.Expr(nil), inheritedValues...)
					effective = &clone
				}
				if len(effective.Names) == 0 || len(effective.Names) != len(effective.Values) {
					return nil, fmt.Errorf("const declaration has ambiguous name/value cardinality")
				}
			}
			unitsBySpec[spec] = l8WorkerV2SplitValueSpecSemanticUnits(effective)
		}
	}
	return unitsBySpec, nil
}

func l8WorkerV2SplitValueSpecSemanticUnits(spec *ast.ValueSpec) []*ast.ValueSpec {
	if len(spec.Names) == 0 || len(spec.Names) != len(spec.Values) {
		// A single RHS may produce multiple values. Likewise, an explicit type
		// applies to every name in a declaration without initializers. Keep those
		// declarations whole so one V2 dependency cannot be hidden in a sibling.
		return []*ast.ValueSpec{spec}
	}

	units := make([]*ast.ValueSpec, 0, len(spec.Names))
	for index, name := range spec.Names {
		unit := *spec
		unit.Names = []*ast.Ident{name}
		unit.Values = []ast.Expr{spec.Values[index]}
		units = append(units, &unit)
	}
	return units
}

func l8WorkerV2ImportValues(imports map[string]string) []string {
	values := make([]string, 0, len(imports))
	for _, importPath := range imports {
		values = append(values, importPath)
	}
	return values
}

type l8WorkerV2GuardImporter struct {
	fallback types.Importer
}

func (value l8WorkerV2GuardImporter) Import(path string) (*types.Package, error) {
	if path == "golang.org/x/sys/unix" {
		return l8WorkerV2UnixFixturePackage(), nil
	}
	return value.fallback.Import(path)
}

func l8WorkerV2UnixFixturePackage() *types.Package {
	pkg := types.NewPackage("golang.org/x/sys/unix", "unix")
	scope := pkg.Scope()
	empty := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	for _, name := range []string{
		"RawSyscall", "RawSyscall6", "Syscall", "Syscall6", "Socket", "Connect",
		"Mmap", "Mlock", "Munlock", "Munmap", "Exec", "Kill", "Mount", "Unshare", "Setns",
	} {
		scope.Insert(types.NewFunc(token.NoPos, pkg, name, empty))
	}
	errorType := types.Universe.Lookup("error").Type()
	flockParameters := types.NewTuple(
		types.NewParam(token.NoPos, pkg, "fd", types.Typ[types.Int]),
		types.NewParam(token.NoPos, pkg, "how", types.Typ[types.Int]),
	)
	flockResults := types.NewTuple(types.NewParam(token.NoPos, pkg, "err", errorType))
	scope.Insert(types.NewFunc(token.NoPos, pkg, "Flock", types.NewSignatureType(nil, nil, nil, flockParameters, flockResults, false)))
	statFields := []*types.Var{
		types.NewField(token.NoPos, pkg, "Uid", types.Typ[types.Uint32], false),
		types.NewField(token.NoPos, pkg, "Gid", types.Typ[types.Uint32], false),
		types.NewField(token.NoPos, pkg, "Mode", types.Typ[types.Uint32], false),
	}
	statName := types.NewTypeName(token.NoPos, pkg, "Stat_t", nil)
	types.NewNamed(statName, types.NewStruct(statFields, nil), nil)
	scope.Insert(statName)
	for index, name := range []string{"LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN"} {
		scope.Insert(types.NewConst(token.NoPos, pkg, name, types.Typ[types.UntypedInt], constant.MakeInt64(int64(index+1))))
	}
	pkg.MarkComplete()
	return pkg
}

func l8WorkerV2MixedDeclarationScopes(declaration ast.Decl, valueSpecUnits map[*ast.ValueSpec][]*ast.ValueSpec) []ast.Node {
	switch typed := declaration.(type) {
	case *ast.GenDecl:
		if typed.Tok == token.IMPORT {
			return nil
		}
		var scopes []ast.Node
		for _, spec := range typed.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				for _, unit := range valueSpecUnits[valueSpec] {
					if l8WorkerV2ASTContainsMarker(unit) {
						scopes = append(scopes, unit)
					}
				}
				continue
			}
			if !l8WorkerV2ASTContainsMarker(spec) {
				continue
			}
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || strings.Contains(strings.ToLower(typeSpec.Name.Name), "v2") {
				scopes = append(scopes, spec)
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				scopes = append(scopes, spec)
				continue
			}
			for _, field := range structType.Fields.List {
				if l8WorkerV2ASTContainsMarker(field) {
					scopes = append(scopes, field)
				}
			}
		}
		return scopes
	case *ast.FuncDecl:
		if l8WorkerV2FunctionSignatureContainsMarker(typed) {
			return []ast.Node{typed}
		}
		return l8WorkerV2MixedFunctionBodyScopes(typed.Body)
	default:
		return nil
	}
}

func l8WorkerV2FunctionSignatureContainsMarker(function *ast.FuncDecl) bool {
	if function == nil {
		return false
	}
	cloned := *function
	cloned.Body = nil
	return l8WorkerV2ASTContainsMarker(&cloned)
}

func l8WorkerV2MixedFunctionBodyScopes(body *ast.BlockStmt) []ast.Node {
	if body == nil || !l8WorkerV2ASTContainsMarker(body) {
		return nil
	}
	// Mixed dispatch functions are intentionally audited as one control-flow
	// unit. Case-only slicing misses switch initializers, fallthrough targets,
	// and later switches reached after a V2 branch. Unrelated legacy sibling
	// functions remain outside the object-identity closure.
	return []ast.Node{body}
}

func l8WorkerV2ReferencedDeclarationScopes(scope l8WorkerV2GuardScope) []l8WorkerV2GuardScope {
	typeSpec, ok := scope.node.(*ast.TypeSpec)
	if !ok || strings.Contains(strings.ToLower(typeSpec.Name.Name), "v2") {
		return []l8WorkerV2GuardScope{scope}
	}
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		return []l8WorkerV2GuardScope{scope}
	}
	exactMixedEnvelope := filepath.Base(scope.file.path) == "types.go" && (typeSpec.Name.Name == "Request" || typeSpec.Name.Name == "Response")
	if !exactMixedEnvelope && !l8WorkerV2ASTContainsMarker(structType) {
		return []l8WorkerV2GuardScope{scope}
	}
	var result []l8WorkerV2GuardScope
	for _, field := range structType.Fields.List {
		if l8WorkerV2ASTContainsMarker(field) {
			result = append(result, l8WorkerV2GuardScope{file: scope.file, node: field})
		}
	}
	return result
}

func l8InspectWorkerV2Scope(scope l8WorkerV2GuardScope, info *types.Info, staticFunctionAliases map[types.Object]*types.Func, operationAnalysis *l8WorkerV2OperationAnalysis) error {
	if invalid, _ := l8WorkerV2ContainsInvalidOperationValue(scope, info, operationAnalysis); invalid {
		name := "declaration"
		if function, ok := scope.node.(*ast.FuncDecl); ok {
			name = function.Name.Name
		}
		return fmt.Errorf("worker-v2 production path in %s declaration %s uses forbidden runtime operation assembly; operation identifiers must use locked constants", scope.file.path, name)
	}
	if err := l8RejectWorkerV2SemanticExternalSurfaces(scope, info); err != nil {
		return err
	}
	var inspectionErr error
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		if inspectionErr != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if l8WorkerV2IsTypedDecoderInnerCall(call, info) && !l8WorkerV2AllowedExactDecoderCallerCall(scope, call, info) {
			scopeName := "declaration"
			if function, ok := scope.node.(*ast.FuncDecl); ok {
				scopeName = function.Name.Name
			}
			inspectionErr = fmt.Errorf("worker-v2 production path in %s declaration %s violates exact decoder caller composition", scope.file.path, scopeName)
			return false
		}
		if l8WorkerV2CallMayInvokeImplicitInterface(call, info) && !l8WorkerV2AllowedBoundedStrictDecoderCall(scope, call, info) && !l8WorkerV2AllowedExactJSONMarshalCall(scope, call, info) && !l8WorkerV2AllowedExactJSONEncoderCall(scope, call, info) && !l8WorkerV2AllowedExactClientRoundTripFormatting(scope, call, info) && !l8WorkerV2AllowedExactServerRequestValidationFormatting(scope, call, info) && !l8WorkerV2AllowedExactClientContextClassification(scope, call, info) {
			scopeName := "declaration"
			if function, ok := scope.node.(*ast.FuncDecl); ok {
				scopeName = function.Name.Name
			}
			called := l8WorkerV2CalledObject(call.Fun, info)
			if called != nil && called.Pkg() != nil {
				inspectionErr = fmt.Errorf("worker-v2 production path in %s declaration %s uses forbidden implicit interface callback through external call %s.%s", scope.file.path, scopeName, called.Pkg().Path(), called.Name())
			} else {
				inspectionErr = fmt.Errorf("worker-v2 production path in %s declaration %s uses forbidden implicit interface callback through external call", scope.file.path, scopeName)
			}
			return false
		}
		kind := l8WorkerV2DynamicCallKind(call.Fun, info)
		if kind == "function-value" && scope.initializerEvaluation && staticFunctionAliases[l8WorkerV2CalledObject(call.Fun, info)] != nil {
			kind = ""
		}
		if kind == "interface" && (l8WorkerV2AllowedExactClientTransportCall(scope, call, info) || l8WorkerV2AllowedExactClientContextErrCall(scope, call, info) || l8WorkerV2AllowedExactClientErrorStringCall(scope, call, info) || l8WorkerV2AllowedExactCodecResourceLifecycleCall(scope, call, info)) {
			kind = ""
		}
		if kind != "" {
			scopeName := "declaration"
			if function, ok := scope.node.(*ast.FuncDecl); ok {
				scopeName = function.Name.Name
			}
			called := l8WorkerV2CalledObject(call.Fun, info)
			if called != nil && called.Pkg() != nil {
				inspectionErr = fmt.Errorf("worker-v2 production path in %s declaration %s uses forbidden %s dispatch through %s.%s", scope.file.path, scopeName, kind, called.Pkg().Path(), called.Name())
			} else {
				inspectionErr = fmt.Errorf("worker-v2 production path in %s declaration %s uses forbidden %s dispatch", scope.file.path, scopeName, kind)
			}
			return false
		}
		return true
	})
	return inspectionErr
}

func l8WorkerV2AllowedExactClientRoundTripFormatting(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || !l8WorkerV2ExactClientCompatibilityFunction(scope) || len(call.Args) != 2 {
		return false
	}
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil || object.Pkg().Path() != "fmt" || object.Name() != "Sprintf" {
		return false
	}
	formatValue := info.Types[call.Args[0]].Value
	if formatValue == nil || formatValue.Kind() != constant.String {
		return false
	}
	format := constant.StringVal(formatValue)
	return (function.Name.Name == "roundTrip" && format == "malformed worker request: %v") ||
		(function.Name.Name == "validateClientResponse" && format == "malformed worker response: %v")
}

func l8WorkerV2AllowedExactServerRequestValidationFormatting(scope l8WorkerV2GuardScope, candidate *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "server.go" || function.Name.Name != "readRequest" {
		return false
	}
	decoderCall := l8WorkerV2SingleTypedDecoderCall(function, info)
	if decoderCall == nil || len(decoderCall.Args) != 3 {
		return false
	}
	output := l8WorkerV2AddressedObject(decoderCall.Args[2], "Request", info)
	formatCall, exact := l8WorkerV2ExactValidatedServerRequestFlow(function, decoderCall, output, info)
	return exact && candidate == formatCall
}

func l8WorkerV2AllowedExactClientContextClassification(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || !l8WorkerV2ExactClientCompatibilityFunction(scope) || (function.Name.Name != "clientContextError" && function.Name.Name != "clientContextOrTransportError") || len(call.Args) != 2 {
		return false
	}
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil || object.Pkg().Path() != "errors" || object.Name() != "Is" {
		return false
	}
	first, ok := l8WorkerV2UnparenExpression(call.Args[0]).(*ast.Ident)
	if !ok || first.Name != "err" {
		return false
	}
	second, ok := l8WorkerV2UnparenExpression(call.Args[1]).(*ast.SelectorExpr)
	if !ok || (second.Sel.Name != "Canceled" && second.Sel.Name != "DeadlineExceeded") {
		return false
	}
	secondObject := info.Uses[second.Sel]
	return secondObject != nil && secondObject.Pkg() != nil && secondObject.Pkg().Path() == "context"
}

func l8WorkerV2AllowedExactClientTransportCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || !l8WorkerV2ExactClientCompatibilityFunction(scope) || function.Name.Name != "roundTrip" || function.Recv == nil || len(function.Recv.List) != 1 {
		return false
	}
	receiverPointer, ok := function.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	receiverType, ok := receiverPointer.X.(*ast.Ident)
	if !ok || receiverType.Name != "Client" {
		return false
	}
	callSelector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	selection := info.Selections[callSelector]
	if selection == nil {
		return false
	}
	method, ok := selection.Obj().(*types.Func)
	if !ok || method.Name() != "RoundTrip" || !l8WorkerV2IsExactClientTransportInterface(method.Type()) {
		return false
	}
	transportSelector, ok := l8WorkerV2UnparenExpression(callSelector.X).(*ast.SelectorExpr)
	if !ok || transportSelector.Sel.Name != "transport" {
		return false
	}
	field, ok := info.Uses[transportSelector.Sel].(*types.Var)
	if !ok || !field.IsField() || field.Name() != "transport" || !l8WorkerV2IsExactClientTransportInterface(field.Type()) {
		return false
	}
	receiver, ok := l8WorkerV2UnparenExpression(transportSelector.X).(*ast.Ident)
	if !ok || len(function.Recv.List[0].Names) != 1 {
		return false
	}
	return info.Uses[receiver] == info.Defs[function.Recv.List[0].Names[0]]
}

func l8WorkerV2AllowedExactClientContextErrCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || !l8WorkerV2ExactClientCompatibilityFunction(scope) || function.Name.Name != "roundTrip" || function.Type.Params == nil {
		return false
	}
	selector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Err" || len(call.Args) != 0 {
		return false
	}
	selection := info.Selections[selector]
	if selection == nil || selection.Obj() == nil || selection.Obj().Pkg() == nil || selection.Obj().Pkg().Path() != "context" || selection.Obj().Name() != "Err" {
		return false
	}
	receiver, ok := l8WorkerV2UnparenExpression(selector.X).(*ast.Ident)
	if !ok {
		return false
	}
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == "ctx" && info.Uses[receiver] == info.Defs[name] {
				return true
			}
		}
	}
	return false
}

func l8WorkerV2AllowedExactClientErrorStringCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || !l8WorkerV2ExactClientCompatibilityFunction(scope) || function.Name.Name != "clientContextOrTransportError" || len(call.Args) != 0 {
		return false
	}
	selector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Error" {
		return false
	}
	receiver, ok := l8WorkerV2UnparenExpression(selector.X).(*ast.Ident)
	if !ok || receiver.Name != "err" {
		return false
	}
	selection := info.Selections[selector]
	return selection != nil && selection.Obj() != nil && selection.Obj().Pkg() == nil && selection.Obj().Name() == "Error"
}

func l8WorkerV2ExactClientCompatibilityFunction(scope l8WorkerV2GuardScope) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "client.go" {
		return false
	}
	expected := map[string]string{
		"roundTrip":                     "c458a12ddce44baa17ec4cbddc28d06abb30af3d1c1be1f00047e57f337c522e",
		"validateClientResponse":        "9230b6eb87b32c32cae9180b5bb5113cf2ee5a5b5dc11f49b70e66f93cfe2a50",
		"clientContextOrTransportError": "82eec74cfdb14ab39ff71baeb26254ec76a6ef1be1d9e44a6134dd874389dd32",
		"clientContextError":            "087527510258465c4a4d7435f9d33af13edb0c785e94017452316edd9ed947bf",
	}[function.Name.Name]
	return expected != "" && l8WorkerV2DeclarationDigest(scope) == expected
}

func l8WorkerV2AllowedExactCodecResourceLifecycleCall(scope l8WorkerV2GuardScope, candidate *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || function.Body == nil || candidate == nil {
		return false
	}
	switch filepath.Base(scope.file.path) {
	case "client.go":
		if function.Name.Name != "RoundTrip" {
			return false
		}
		parameters := l8WorkerV2FunctionParameterObjects(function, info)
		newEncoder, encodeCall, exactEncode := l8WorkerV2ExactClientRequestEncoderCalls(function, info)
		if !exactEncode || newEncoder == nil || len(newEncoder.Args) != 1 {
			return false
		}
		connection := l8WorkerV2ExpressionObject(newEncoder.Args[0], info)
		if len(parameters) != 2 || !exactEncode || connection == nil {
			return false
		}
		calls, _, _, exact := l8WorkerV2ExactClientConnectionLifecycle(function, connection, parameters[0], encodeCall, info)
		return exact && l8WorkerV2CallInSet(candidate, calls)
	case "job_store_v2.go":
		switch function.Name.Name {
		case "load":
			decoderCall := l8WorkerV2SingleTypedDecoderCall(function, info)
			if decoderCall == nil || len(decoderCall.Args) != 3 {
				return false
			}
			reader := l8WorkerV2ExpressionObject(decoderCall.Args[0], info)
			closeCall, _, exact := l8WorkerV2ExactDeferredReaderClose(function, reader, decoderCall, info)
			return exact && candidate == closeCall
		case "openStoredJobStateV2":
			method, _ := info.Defs[function.Name].(*types.Func)
			calls, exact := l8WorkerV2ExactReceiverRootedStoredJobOpener(scope.file, method, info)
			return exact && l8WorkerV2CallInSet(candidate, calls)
		default:
			return false
		}
	default:
		return false
	}
}

func l8WorkerV2SingleTypedDecoderCall(function *ast.FuncDecl, info *types.Info) *ast.CallExpr {
	var result *ast.CallExpr
	count := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if ok && l8WorkerV2IsTypedDecoderInnerCall(call, info) {
			result = call
			count++
		}
		return true
	})
	if count != 1 {
		return nil
	}
	return result
}

func l8WorkerV2NoExtraneousResponseAddressCall(function *ast.FuncDecl, decoderCall *ast.CallExpr, info *types.Info) bool {
	if function == nil || function.Body == nil || decoderCall == nil {
		return false
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if ok && call != decoderCall && len(call.Args) == 3 && l8WorkerV2AddressedObject(call.Args[2], "Response", info) != nil {
			valid = false
			return false
		}
		return true
	})
	return valid
}

func l8WorkerV2CallInSet(candidate *ast.CallExpr, calls []*ast.CallExpr) bool {
	for _, call := range calls {
		if candidate == call {
			return true
		}
	}
	return false
}

func l8WorkerV2IsExactClientTransportInterface(typ types.Type) bool {
	if signature, ok := typ.(*types.Signature); ok && signature.Recv() != nil {
		typ = signature.Recv().Type()
	}
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" && named.Obj().Name() == "ClientTransport"
}

func l8WorkerV2IsTypedDecoderInnerCall(call *ast.CallExpr, info *types.Info) bool {
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil || object.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" {
		return false
	}
	switch object.Name() {
	case "decodeWorkerRequestInto", "decodeWorkerResponseInto", "decodeStoredJobStateV2Into":
		return true
	default:
		return false
	}
}

func l8WorkerV2AllowedExactDecoderCallerCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || len(call.Args) != 3 {
		return false
	}
	switch object.Name() {
	case "decodeWorkerRequestInto":
		return l8WorkerV2ExactServerRequestDecoderCall(scope, call, info)
	case "decodeWorkerResponseInto":
		return l8WorkerV2ExactUnixResponseDecoderCall(scope, call, info) || l8WorkerV2ExactBehavioralResponseDecoderCall(scope, call, info)
	case "decodeStoredJobStateV2Into":
		return l8WorkerV2ExactStoreStateDecoderCall(scope, call, info)
	default:
		return false
	}
}

func l8WorkerV2ExactServerRequestDecoderCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "server.go" || function.Name.Name != "readRequest" {
		return false
	}
	receiver := l8WorkerV2ExactReceiverObject(function, "Server", true, info)
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if receiver == nil || len(parameters) != 1 || !l8WorkerV2IsExactIOReader(parameters[0].Type()) || !l8WorkerV2ExactRequestErrorResponseResults(function, info) {
		return false
	}
	reader := parameters[0]
	output := l8WorkerV2AddressedObject(call.Args[2], "Request", info)
	common := output != nil && l8WorkerV2ExpressionObject(call.Args[0], info) == reader &&
		l8WorkerV2ExactSelectorRoot(call.Args[1], receiver, "maxRequestBytes", info) &&
		l8WorkerV2NoUnconditionalTerminalBefore(function, call, info, scope.terminalAnalysis) &&
		l8WorkerV2ObjectHasNoReassignments(function, receiver, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, reader, info) &&
		l8WorkerV2ObjectOnlyConsumedByExactCalls(function, reader, []*ast.CallExpr{call}, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, reader, []*ast.CallExpr{call}, nil, false, info) &&
		l8WorkerV2SelectorHasNoMutations(function, receiver, "maxRequestBytes", info) &&
		l8WorkerV2ExactTopLevelCodecConditional(function, call, info) &&
		l8WorkerV2ExactTopLevelSuccessAfterCall(function, output, call, info)
	if !common {
		return false
	}
	minimal := l8WorkerV2ObjectHasNoReassignments(function, output, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, output, []*ast.CallExpr{call}, nil, true, info)
	_, validated := l8WorkerV2ExactValidatedServerRequestFlow(function, call, output, info)
	return minimal || validated
}

func l8WorkerV2ExactValidatedServerRequestFlow(function *ast.FuncDecl, decoderCall *ast.CallExpr, request types.Object, info *types.Info) (*ast.CallExpr, bool) {
	if function == nil || function.Body == nil || decoderCall == nil || request == nil || len(function.Body.List) != 5 {
		return nil, false
	}
	declaration, ok := function.Body.List[0].(*ast.DeclStmt)
	if !ok || l8WorkerV2ExpressionObjectFromSingleVarDeclaration(declaration, info) != request {
		return nil, false
	}
	decodeFailure, ok := function.Body.List[1].(*ast.IfStmt)
	if !ok || !l8WorkerV2IfInitializerCalls(decodeFailure, decoderCall, info) || decodeFailure.Else != nil || len(decodeFailure.Body.List) != 2 {
		return nil, false
	}
	decodeErr := l8WorkerV2IfInitializerErrorObject(decodeFailure, decoderCall, info)
	if decodeErr == nil || !l8WorkerV2IsErrorComparison(decodeFailure.Cond, decodeErr, nil, info) {
		return nil, false
	}
	decodeResponse, exactResponse := l8WorkerV2ExactProtocolErrorResponseDefinition(decodeFailure.Body.List[0], []l8WorkerV2ExactProtocolErrorArgument{
		{constantString: stringPointer("")},
		{packageConstant: "OperationProtocolError"},
		{packageConstant: "ErrorCodeMalformedRequest"},
		{constantString: stringPointer("malformed worker request")},
	}, info)
	if !exactResponse || !l8WorkerV2IsZeroStructAndAddressedObjectReturn(decodeFailure.Body.List[1], "Request", decodeResponse, info) {
		return nil, false
	}
	defaults, ok := function.Body.List[2].(*ast.AssignStmt)
	if !ok || defaults.Tok != token.ASSIGN || len(defaults.Lhs) != 1 || len(defaults.Rhs) != 1 || l8WorkerV2ExpressionObject(defaults.Lhs[0], info) != request {
		return nil, false
	}
	defaultsCall, ok := l8WorkerV2UnparenExpression(defaults.Rhs[0]).(*ast.CallExpr)
	if !ok || !l8WorkerV2ExactObjectMethodCall(defaultsCall, request, "WithDefaults", nil, info) {
		return nil, false
	}
	validation, ok := function.Body.List[3].(*ast.IfStmt)
	if !ok || validation.Else != nil || len(validation.Body.List) != 2 {
		return nil, false
	}
	validateCall, validateErr := l8WorkerV2ExactRequestValidationInitializer(validation, request, info)
	if validateCall == nil || validateErr == nil || !l8WorkerV2IsErrorComparison(validation.Cond, validateErr, nil, info) {
		return nil, false
	}
	formatCall := l8WorkerV2ExactMalformedRequestFormatCall(validation.Body.List[0], validateErr, info)
	if formatCall == nil {
		return nil, false
	}
	validationResponse, exactValidationResponse := l8WorkerV2ExactProtocolErrorResponseDefinition(validation.Body.List[0], []l8WorkerV2ExactProtocolErrorArgument{
		{selectorRoot: request, selectorField: "RequestID"},
		{selectorRoot: request, selectorField: "Operation"},
		{packageConstant: "ErrorCodeMalformedRequest"},
		{expression: formatCall},
	}, info)
	if !exactValidationResponse || !l8WorkerV2IsObjectAndAddressedObjectReturn(validation.Body.List[1], request, validationResponse, info) {
		return nil, false
	}
	returned, ok := function.Body.List[4].(*ast.ReturnStmt)
	return formatCall, ok && len(returned.Results) == 2 && l8WorkerV2ExpressionObject(returned.Results[0], info) == request && l8WorkerV2IsNilExpression(returned.Results[1], info)
}

type l8WorkerV2ExactProtocolErrorArgument struct {
	constantString  *string
	packageConstant string
	selectorRoot    types.Object
	selectorField   string
	expression      ast.Expr
}

func stringPointer(value string) *string {
	return &value
}

func l8WorkerV2ExactProtocolErrorResponseDefinition(statement ast.Stmt, arguments []l8WorkerV2ExactProtocolErrorArgument, info *types.Info) (types.Object, bool) {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return nil, false
	}
	response := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if response == nil || !ok || !l8WorkerV2IsExactNamedStruct(response.Type(), "Response") || call.Ellipsis.IsValid() || len(call.Args) != len(arguments) ||
		!l8WorkerV2IsExactPackageFunctionObject(l8WorkerV2CalledObject(call.Fun, info), "protocolErrorResponse") {
		return nil, false
	}
	for index, expected := range arguments {
		argument := call.Args[index]
		switch {
		case expected.constantString != nil:
			value := info.Types[argument].Value
			if value == nil || value.Kind() != constant.String || constant.StringVal(value) != *expected.constantString {
				return nil, false
			}
		case expected.packageConstant != "":
			object, ok := l8WorkerV2ExpressionObject(argument, info).(*types.Const)
			if !ok || object.Pkg() == nil || object.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || object.Name() != expected.packageConstant || object.Pkg().Scope().Lookup(expected.packageConstant) != object {
				return nil, false
			}
		case expected.selectorRoot != nil:
			if !l8WorkerV2ExactSelectorRoot(argument, expected.selectorRoot, expected.selectorField, info) {
				return nil, false
			}
		case expected.expression != nil:
			if l8WorkerV2UnparenExpression(argument) != l8WorkerV2UnparenExpression(expected.expression) {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return response, true
}

func l8WorkerV2IsZeroStructAndAddressedObjectReturn(statement ast.Stmt, structName string, object types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 || l8WorkerV2DirectAddressedObject(returned.Results[1], info) != object {
		return false
	}
	literal, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.CompositeLit)
	return ok && len(literal.Elts) == 0 && l8WorkerV2IsExactNamedStruct(info.TypeOf(literal), structName)
}

func l8WorkerV2ExactRequestValidationInitializer(conditional *ast.IfStmt, request types.Object, info *types.Info) (*ast.CallExpr, types.Object) {
	if conditional == nil || conditional.Init == nil {
		return nil, nil
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return nil, nil
	}
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok || !l8WorkerV2ExactObjectMethodCall(call, request, "Validate", nil, info) {
		return nil, nil
	}
	return call, l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
}

func l8WorkerV2ExactMalformedRequestFormatCall(statement ast.Stmt, validationErr types.Object, info *types.Info) *ast.CallExpr {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 {
		return nil
	}
	responseCall, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok || len(responseCall.Args) != 4 {
		return nil
	}
	formatCall, ok := l8WorkerV2UnparenExpression(responseCall.Args[3]).(*ast.CallExpr)
	if !ok || !l8WorkerV2IsExactPackageCall(formatCall, "fmt", "Sprintf", 2, info) || l8WorkerV2ExpressionObject(formatCall.Args[1], info) != validationErr {
		return nil
	}
	formatValue := info.Types[formatCall.Args[0]].Value
	if formatValue == nil || formatValue.Kind() != constant.String || constant.StringVal(formatValue) != "malformed worker request: %v" {
		return nil
	}
	return formatCall
}

func l8WorkerV2IsObjectAndAddressedObjectReturn(statement ast.Stmt, first, second types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && l8WorkerV2ExpressionObject(returned.Results[0], info) == first && l8WorkerV2DirectAddressedObject(returned.Results[1], info) == second
}

func l8WorkerV2ExactUnixResponseDecoderCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "client.go" || function.Name.Name != "RoundTrip" {
		return false
	}
	receiver := l8WorkerV2ExactReceiverObject(function, "unixSocketClientTransport", false, info)
	if receiver == nil || !l8WorkerV2ExactRoundTripSignature(function, info) || !l8WorkerV2IsExactObjectExpression(call.Args[0], info) {
		return false
	}
	connection := l8WorkerV2ExpressionObject(call.Args[0], info)
	output := l8WorkerV2AddressedObject(call.Args[2], "Response", info)
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if len(parameters) != 2 {
		return false
	}
	request := parameters[1]
	newEncoder, encodeCall, exactEncode := l8WorkerV2ExactClientRequestEncoderCalls(function, info)
	if !exactEncode || newEncoder == nil || len(newEncoder.Args) != 1 {
		return false
	}
	encodedConnection := l8WorkerV2ExpressionObject(newEncoder.Args[0], info)
	acquireCall, acquireErr := l8WorkerV2TopLevelAcquisitionForObject(function, connection, info)
	lifecycleCalls, connectionLifecycleCalls, acquisitionErrorBranch, exactLifecycle := l8WorkerV2ExactClientConnectionLifecycle(function, connection, parameters[0], encodeCall, info)
	halfCloseAssertion := l8WorkerV2ExactClientConnectionHalfCloseAssertion(function, connection, info)
	connectionCalls := append(append([]*ast.CallExpr(nil), connectionLifecycleCalls...), encodeCall, call)
	if connection == nil || encodedConnection != connection || acquireCall == nil || acquireErr == nil || output == nil ||
		!l8WorkerV2NoUnconditionalTerminalBefore(function, acquireCall, info, scope.terminalAnalysis) ||
		!l8WorkerV2NoUnconditionalTerminalBefore(function, call, info, scope.terminalAnalysis) ||
		!exactEncode || !exactLifecycle || len(lifecycleCalls) == 0 || !l8WorkerV2ObjectHasNoReassignments(function, receiver, info) ||
		!l8WorkerV2ObjectHasNoReassignments(function, request, info) ||
		!l8WorkerV2ObjectHasNoWholeValueEscapes(function, request, []*ast.CallExpr{encodeCall}, nil, false, info) ||
		!l8WorkerV2ObjectHasNoReassignments(function, connection, info) || !l8WorkerV2ObjectHasNoReassignments(function, output, info) ||
		!l8WorkerV2ObjectOnlyConsumedByExactCalls(function, connection, connectionCalls, info) ||
		!l8WorkerV2ObjectHasNoWholeValueEscapes(function, connection, connectionCalls, []*ast.TypeAssertExpr{halfCloseAssertion}, false, info) ||
		!l8WorkerV2ObjectHasNoWholeValueEscapes(function, output, []*ast.CallExpr{call}, nil, true, info) ||
		!l8WorkerV2NoExtraneousResponseAddressCall(function, call, info) ||
		!l8WorkerV2ExactTopLevelSuccessAfterCall(function, output, call, info) ||
		!l8WorkerV2ExactClientCodecErrorBranch(function, call, parameters[0], acquireCall, info) ||
		!l8WorkerV2ExactClientSafeBranches(function, connection, acquireCall, acquireErr, acquisitionErrorBranch, info) {
		return false
	}
	limit := l8WorkerV2ExpressionObject(call.Args[1], info)
	return limit != nil && l8WorkerV2ExactPostDefaultLimit(function, call, receiver, limit, info) &&
		l8WorkerV2ObjectHasNoIndirectMutations(function, limit, info)
}

func l8WorkerV2ExactBehavioralResponseDecoderCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "protocol_decode.go" || function.Name.Name != "decodeWorkerResponse" || function.Recv != nil || function.Body == nil || len(function.Body.List) != 3 {
		return false
	}
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if len(parameters) != 1 || !l8WorkerV2IsExactIOReader(parameters[0].Type()) || !l8WorkerV2ExactResponseErrorResults(function, info) {
		return false
	}
	output := l8WorkerV2AddressedObject(call.Args[2], "Response", info)
	return output != nil && l8WorkerV2ExpressionObject(call.Args[0], info) == parameters[0] &&
		l8WorkerV2ExactPackageInt64Constant(call.Args[1], "defaultMaxResponseBytes", 1<<20, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, output, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, parameters[0], []*ast.CallExpr{call}, nil, false, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, output, []*ast.CallExpr{call}, nil, true, info) &&
		l8WorkerV2ExactThreeStatementResponseWrapper(function, call, output, info)
}

func l8WorkerV2ExactStoreStateDecoderCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "job_store_v2.go" || function.Name.Name != "load" || !l8WorkerV2ExactStoreLoadSignature(function, info) {
		return false
	}
	receiver := l8WorkerV2ExactReceiverObject(function, "jobStoreV2", true, info)
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	reader := l8WorkerV2ExpressionObject(call.Args[0], info)
	output := l8WorkerV2AddressedObject(call.Args[2], "storedJobStateV2", info)
	readerClose, acquisitionErrorBranch, exactReaderClose := l8WorkerV2ExactDeferredReaderClose(function, reader, call, info)
	acquireCall, acquireErr := l8WorkerV2TopLevelAcquisitionForObject(function, reader, info)
	return receiver != nil && len(parameters) == 1 && reader != nil && output != nil &&
		exactReaderClose && acquireCall != nil && acquireErr != nil &&
		l8WorkerV2NoUnconditionalTerminalBefore(function, acquireCall, info, scope.terminalAnalysis) &&
		l8WorkerV2NoUnconditionalTerminalBefore(function, call, info, scope.terminalAnalysis) &&
		l8WorkerV2ObjectHasNoReassignments(function, receiver, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, parameters[0], info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, parameters[0], []*ast.CallExpr{acquireCall}, nil, false, info) &&
		l8WorkerV2ObjectIsAcquiredCallResult(function, reader, "", parameters[0], info) &&
		l8WorkerV2IsExactStoredJobOpenCall(scope.file, function, acquireCall, receiver, parameters[0], info) &&
		l8WorkerV2ObjectHasNoReassignments(function, reader, info) && l8WorkerV2ObjectHasNoReassignments(function, output, info) &&
		l8WorkerV2ObjectOnlyConsumedByExactCalls(function, reader, []*ast.CallExpr{readerClose, call}, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, reader, []*ast.CallExpr{readerClose, call}, nil, false, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, output, []*ast.CallExpr{call}, nil, true, info) &&
		l8WorkerV2ExactPackageInt64Constant(call.Args[1], "maxStoredJobStateV2Bytes", 64<<10, info) &&
		l8WorkerV2ExactTopLevelSuccessAfterCall(function, output, call, info) &&
		l8WorkerV2ExactStoreSafeBranches(function, call, acquireErr, acquisitionErrorBranch, info)
}

func l8WorkerV2ExactClientConnectionLifecycle(function *ast.FuncDecl, connection, ctx types.Object, encodeCall *ast.CallExpr, info *types.Info) ([]*ast.CallExpr, []*ast.CallExpr, *ast.IfStmt, bool) {
	if function == nil || function.Body == nil || connection == nil || ctx == nil || encodeCall == nil {
		return nil, nil, nil, false
	}
	acquireCall, acquireErr := l8WorkerV2TopLevelAcquisitionForObject(function, connection, info)
	if acquireCall == nil || acquireErr == nil || !l8WorkerV2ExactClientNilContextNormalization(function, ctx, acquireCall, info) {
		return nil, nil, nil, false
	}
	var deferredClose, deferredDoneClose, cancellationClose, contextDone, contextDeadline, setDeadline *ast.CallExpr
	var done types.Object
	var deferClosePos, donePos, goPos, deferDonePos, deadlinePos token.Pos
	closeCalls, doneCalls, deadlineCalls, setDeadlineCalls, doneCloseCalls, doneReceives := 0, 0, 0, 0, 0, 0

	for _, statement := range function.Body.List {
		switch statement := statement.(type) {
		case *ast.DeferStmt:
			if l8WorkerV2ExactObjectMethodCall(statement.Call, connection, "Close", nil, info) {
				deferredClose = statement.Call
				deferClosePos = statement.Pos()
				continue
			}
			if done != nil && l8WorkerV2ExactBuiltinCall(statement.Call, "close", done, info) {
				deferredDoneClose = statement.Call
				deferDonePos = statement.Pos()
			}
		case *ast.AssignStmt:
			if candidate := l8WorkerV2ExactDoneChannelDefinition(statement, info); candidate != nil {
				done = candidate
				donePos = statement.Pos()
			}
		}
	}
	if deferredClose == nil || deferredDoneClose == nil || done == nil || deferDonePos == token.NoPos {
		return nil, nil, nil, false
	}
	acquisitionErrorBranch := l8WorkerV2ExactCleanupDeferImmediatelyAfterAcquisitionError(function, acquireCall, acquireErr, deferredClose, info)
	if acquisitionErrorBranch == nil ||
		!l8WorkerV2ObjectHasNoReassignments(function, done, info) ||
		!l8WorkerV2ObjectHasNoWholeValueEscapes(function, done, []*ast.CallExpr{deferredDoneClose}, nil, false, info) {
		return nil, nil, nil, false
	}

	for _, statement := range function.Body.List {
		switch statement := statement.(type) {
		case *ast.GoStmt:
			cancelCall, doneCall, ok := l8WorkerV2ExactCancellationClosure(statement, connection, ctx, done, info)
			if ok {
				cancellationClose = cancelCall
				contextDone = doneCall
				goPos = statement.Pos()
			}
		case *ast.IfStmt:
			deadlineCall, setCall, ok := l8WorkerV2ExactDeadlinePropagation(statement, connection, ctx, info)
			if ok {
				contextDeadline = deadlineCall
				setDeadline = setCall
				deadlinePos = statement.Pos()
			}
		}
	}
	if cancellationClose == nil || contextDone == nil || contextDeadline == nil || setDeadline == nil {
		return nil, nil, nil, false
	}

	ast.Inspect(function.Body, func(node ast.Node) bool {
		if receive, ok := node.(*ast.UnaryExpr); ok && receive.Op == token.ARROW && l8WorkerV2ExpressionObject(receive.X, info) == done {
			doneReceives++
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case l8WorkerV2ExactObjectMethodCall(call, connection, "Close", nil, info):
			closeCalls++
		case l8WorkerV2ExactObjectMethodCall(call, ctx, "Done", nil, info):
			doneCalls++
		case l8WorkerV2ExactObjectMethodCall(call, ctx, "Deadline", nil, info):
			deadlineCalls++
		case l8WorkerV2ExactObjectMethodCallArity(call, connection, "SetDeadline", 1, info):
			setDeadlineCalls++
		}
		if l8WorkerV2ExactBuiltinCall(call, "close", done, info) {
			doneCloseCalls++
		}
		return true
	})
	exactOrder := deferClosePos < donePos && donePos < goPos && goPos < deferDonePos && deferDonePos < deadlinePos && deadlinePos < encodeCall.Pos()
	allCalls := []*ast.CallExpr{deferredClose, cancellationClose, contextDone, contextDeadline, setDeadline}
	connectionCalls := []*ast.CallExpr{deferredClose, cancellationClose, setDeadline}
	return allCalls, connectionCalls, acquisitionErrorBranch, exactOrder && closeCalls == 2 && doneCalls == 1 && deadlineCalls == 1 && setDeadlineCalls == 1 && doneCloseCalls == 1 && doneReceives == 1 && l8WorkerV2ObjectUseCount(function, done, info) == 2
}

func l8WorkerV2ExactClientNilContextNormalization(function *ast.FuncDecl, ctx types.Object, acquireCall *ast.CallExpr, info *types.Info) bool {
	if function == nil || function.Body == nil || ctx == nil || acquireCall == nil || len(function.Body.List) == 0 {
		return false
	}
	conditional, ok := function.Body.List[0].(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 1 || conditional.End() > acquireCall.Pos() {
		return false
	}
	comparison, ok := l8WorkerV2UnparenExpression(conditional.Cond).(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL || l8WorkerV2ExpressionObject(comparison.X, info) != ctx || !l8WorkerV2IsNilExpression(comparison.Y, info) {
		return false
	}
	assignment, ok := conditional.Body.List[0].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || l8WorkerV2ExpressionObject(assignment.Lhs[0], info) != ctx {
		return false
	}
	background, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok || !l8WorkerV2IsPackageCall(background, "context", "Background", 0, info) {
		return false
	}
	target := func(expression ast.Expr) bool { return l8WorkerV2ExpressionObject(expression, info) == ctx }
	aliases := l8WorkerV2PointerAliases(function, target, info)
	writes := 0
	valid := l8WorkerV2StorageHasNoEscapes(function, target, aliases, info)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			for _, left := range statement.Lhs {
				if target(left) {
					writes++
					continue
				}
				if l8WorkerV2AssignmentMutatesStorage(left, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if target(statement.X) || l8WorkerV2AssignmentMutatesStorage(statement.X, target, aliases, info) {
				valid = false
				return false
			}
		}
		return true
	})
	return valid && writes == 1
}

func l8WorkerV2ExactCleanupDeferImmediatelyAfterAcquisitionError(function *ast.FuncDecl, acquireCall *ast.CallExpr, acquireErr types.Object, closeCall *ast.CallExpr, info *types.Info) *ast.IfStmt {
	if function == nil || function.Body == nil || acquireCall == nil || acquireErr == nil || closeCall == nil {
		return nil
	}
	for index, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 || assignment.Rhs[0].Pos() != acquireCall.Pos() || index+2 >= len(function.Body.List) {
			continue
		}
		errorBranch, ok := function.Body.List[index+1].(*ast.IfStmt)
		if !ok || !l8WorkerV2IsErrorComparison(errorBranch.Cond, acquireErr, nil, info) {
			return nil
		}
		deferred, ok := function.Body.List[index+2].(*ast.DeferStmt)
		if !ok || deferred.Call != closeCall {
			return nil
		}
		return errorBranch
	}
	return nil
}

func l8WorkerV2ExactDoneChannelDefinition(statement *ast.AssignStmt, info *types.Info) types.Object {
	if statement == nil || statement.Tok != token.DEFINE || len(statement.Lhs) != 1 || len(statement.Rhs) != 1 {
		return nil
	}
	call, ok := l8WorkerV2UnparenExpression(statement.Rhs[0]).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || l8WorkerV2CalledObject(call.Fun, info) != types.Universe.Lookup("make") {
		return nil
	}
	channel, ok := l8WorkerV2UnparenExpression(call.Args[0]).(*ast.ChanType)
	if !ok || channel.Dir != ast.SEND|ast.RECV {
		return nil
	}
	structure, ok := l8WorkerV2UnparenExpression(channel.Value).(*ast.StructType)
	if !ok || structure.Fields == nil || len(structure.Fields.List) != 0 {
		return nil
	}
	return l8WorkerV2ExpressionObject(statement.Lhs[0], info)
}

func l8WorkerV2ExactCancellationClosure(statement *ast.GoStmt, connection, ctx, done types.Object, info *types.Info) (*ast.CallExpr, *ast.CallExpr, bool) {
	if statement == nil || statement.Call == nil || len(statement.Call.Args) != 0 {
		return nil, nil, false
	}
	closure, ok := l8WorkerV2UnparenExpression(statement.Call.Fun).(*ast.FuncLit)
	if !ok || closure.Type.Params == nil || len(closure.Type.Params.List) != 0 || closure.Type.Results != nil || closure.Body == nil || len(closure.Body.List) != 1 {
		return nil, nil, false
	}
	selection, ok := closure.Body.List[0].(*ast.SelectStmt)
	if !ok || selection.Body == nil || len(selection.Body.List) != 2 {
		return nil, nil, false
	}
	var cancellationClose, contextDone *ast.CallExpr
	doneCase := false
	for _, rawClause := range selection.Body.List {
		clause, ok := rawClause.(*ast.CommClause)
		if !ok || clause.Comm == nil {
			return nil, nil, false
		}
		receive, ok := clause.Comm.(*ast.ExprStmt)
		if !ok {
			return nil, nil, false
		}
		arrow, ok := l8WorkerV2UnparenExpression(receive.X).(*ast.UnaryExpr)
		if !ok || arrow.Op != token.ARROW {
			return nil, nil, false
		}
		if call, ok := l8WorkerV2UnparenExpression(arrow.X).(*ast.CallExpr); ok && l8WorkerV2ExactObjectMethodCall(call, ctx, "Done", nil, info) {
			if len(clause.Body) != 1 {
				return nil, nil, false
			}
			assignment, ok := clause.Body[0].(*ast.AssignStmt)
			if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || !l8WorkerV2IsBlankIdentifier(assignment.Lhs[0]) {
				return nil, nil, false
			}
			closeCall, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
			if !ok || !l8WorkerV2ExactObjectMethodCall(closeCall, connection, "Close", nil, info) {
				return nil, nil, false
			}
			contextDone = call
			cancellationClose = closeCall
			continue
		}
		if l8WorkerV2ExpressionObject(arrow.X, info) == done && len(clause.Body) == 0 {
			doneCase = true
			continue
		}
		return nil, nil, false
	}
	return cancellationClose, contextDone, cancellationClose != nil && contextDone != nil && doneCase
}

func l8WorkerV2ExactDeadlinePropagation(statement *ast.IfStmt, connection, ctx types.Object, info *types.Info) (*ast.CallExpr, *ast.CallExpr, bool) {
	if statement == nil || statement.Else != nil || statement.Init == nil || len(statement.Body.List) != 1 {
		return nil, nil, false
	}
	assignment, ok := statement.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return nil, nil, false
	}
	deadline := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	okObject := l8WorkerV2ExpressionObject(assignment.Lhs[1], info)
	deadlineCall, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if deadline == nil || okObject == nil || !ok || !l8WorkerV2ExactObjectMethodCall(deadlineCall, ctx, "Deadline", nil, info) || l8WorkerV2ExpressionObject(statement.Cond, info) != okObject {
		return nil, nil, false
	}
	setAssignment, ok := statement.Body.List[0].(*ast.AssignStmt)
	if !ok || setAssignment.Tok != token.ASSIGN || len(setAssignment.Lhs) != 1 || len(setAssignment.Rhs) != 1 || !l8WorkerV2IsBlankIdentifier(setAssignment.Lhs[0]) {
		return nil, nil, false
	}
	setCall, ok := l8WorkerV2UnparenExpression(setAssignment.Rhs[0]).(*ast.CallExpr)
	if !ok || !l8WorkerV2ExactObjectMethodCall(setCall, connection, "SetDeadline", []types.Object{deadline}, info) {
		return nil, nil, false
	}
	return deadlineCall, setCall, true
}

func l8WorkerV2ExactDeferredReaderClose(function *ast.FuncDecl, reader types.Object, decoderCall *ast.CallExpr, info *types.Info) (*ast.CallExpr, *ast.IfStmt, bool) {
	if function == nil || function.Body == nil || reader == nil || decoderCall == nil {
		return nil, nil, false
	}
	var deferredClose *ast.CallExpr
	closeCalls := 0
	for _, statement := range function.Body.List {
		deferred, ok := statement.(*ast.DeferStmt)
		if ok && l8WorkerV2ExactObjectMethodCall(deferred.Call, reader, "Close", nil, info) {
			deferredClose = deferred.Call
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && l8WorkerV2ExactObjectMethodCall(call, reader, "Close", nil, info) {
			closeCalls++
		}
		return true
	})
	acquireCall, acquireErr := l8WorkerV2TopLevelAcquisitionForObject(function, reader, info)
	acquisitionErrorBranch := l8WorkerV2ExactCleanupDeferImmediatelyAfterAcquisitionError(function, acquireCall, acquireErr, deferredClose, info)
	return deferredClose, acquisitionErrorBranch, deferredClose != nil && deferredClose.Pos() < decoderCall.Pos() && closeCalls == 1 && acquisitionErrorBranch != nil
}

func l8WorkerV2ExactObjectMethodCall(call *ast.CallExpr, receiver types.Object, method string, arguments []types.Object, info *types.Info) bool {
	if !l8WorkerV2ExactObjectMethodCallArity(call, receiver, method, len(arguments), info) {
		return false
	}
	for index, expected := range arguments {
		if l8WorkerV2ExpressionObject(call.Args[index], info) != expected {
			return false
		}
	}
	return true
}

func l8WorkerV2ExactObjectMethodCallArity(call *ast.CallExpr, receiver types.Object, method string, arguments int, info *types.Info) bool {
	if call == nil || receiver == nil || len(call.Args) != arguments {
		return false
	}
	selector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method || l8WorkerV2ExpressionObject(selector.X, info) != receiver {
		return false
	}
	selection := info.Selections[selector]
	return selection != nil && selection.Obj() != nil && selection.Obj().Name() == method
}

func l8WorkerV2ExactBuiltinCall(call *ast.CallExpr, name string, argument types.Object, info *types.Info) bool {
	return call != nil && len(call.Args) == 1 && l8WorkerV2CalledObject(call.Fun, info) == types.Universe.Lookup(name) && l8WorkerV2ExpressionObject(call.Args[0], info) == argument
}

func l8WorkerV2IsBlankIdentifier(expression ast.Expr) bool {
	identifier, ok := l8WorkerV2UnparenExpression(expression).(*ast.Ident)
	return ok && identifier.Name == "_"
}

func l8WorkerV2ExactReceiverObject(function *ast.FuncDecl, name string, pointer bool, info *types.Info) types.Object {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return nil
	}
	receiver := info.Defs[function.Recv.List[0].Names[0]]
	if receiver == nil {
		return nil
	}
	typ := types.Unalias(receiver.Type())
	if pointer {
		resolved, ok := typ.(*types.Pointer)
		if !ok {
			return nil
		}
		typ = types.Unalias(resolved.Elem())
	}
	named, ok := typ.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || named.Obj().Name() != name {
		return nil
	}
	return receiver
}

func l8WorkerV2ExactRequestErrorResponseResults(function *ast.FuncDecl, info *types.Info) bool {
	signature, ok := info.Defs[function.Name].Type().(*types.Signature)
	return ok && signature.Results().Len() == 2 && l8WorkerV2IsExactNamedStruct(signature.Results().At(0).Type(), "Request") && l8WorkerV2IsExactNamedStructPointer(signature.Results().At(1).Type(), "Response")
}

func l8WorkerV2ExactRoundTripSignature(function *ast.FuncDecl, info *types.Info) bool {
	signature, ok := info.Defs[function.Name].Type().(*types.Signature)
	if !ok || signature.Params().Len() != 2 || signature.Results().Len() != 2 || !l8WorkerV2IsExactNamedStruct(signature.Params().At(1).Type(), "Request") || !l8WorkerV2IsExactNamedStruct(signature.Results().At(0).Type(), "Response") || !types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("error").Type()) {
		return false
	}
	named, ok := types.Unalias(signature.Params().At(0).Type()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "Context"
}

func l8WorkerV2ExactResponseErrorResults(function *ast.FuncDecl, info *types.Info) bool {
	signature, ok := info.Defs[function.Name].Type().(*types.Signature)
	return ok && signature.Params().Len() == 1 && signature.Results().Len() == 2 && l8WorkerV2IsExactNamedStruct(signature.Results().At(0).Type(), "Response") && types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("error").Type())
}

func l8WorkerV2ExactStoreLoadSignature(function *ast.FuncDecl, info *types.Info) bool {
	signature, ok := info.Defs[function.Name].Type().(*types.Signature)
	return ok && signature.Params().Len() == 1 && types.Identical(signature.Params().At(0).Type(), types.Universe.Lookup("string").Type()) && signature.Results().Len() == 2 && l8WorkerV2IsExactNamedStruct(signature.Results().At(0).Type(), "storedJobStateV2") && types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("error").Type())
}

func l8WorkerV2AddressedObject(expression ast.Expr, name string, info *types.Info) types.Object {
	address, ok := l8WorkerV2UnparenExpression(expression).(*ast.UnaryExpr)
	if !ok || address.Op != token.AND || !l8WorkerV2IsExactNamedStruct(info.TypeOf(address.X), name) {
		return nil
	}
	return l8WorkerV2ExpressionObject(address.X, info)
}

func l8WorkerV2FunctionReturnsObject(function *ast.FuncDecl, object types.Object, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	nilErrorReturns, exactReturns := 0, 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		returned, ok := node.(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 2 || !l8WorkerV2IsNilExpression(returned.Results[1], info) {
			return true
		}
		nilErrorReturns++
		if l8WorkerV2ExpressionObject(returned.Results[0], info) == object {
			exactReturns++
		}
		return true
	})
	return nilErrorReturns == 1 && exactReturns == 1
}

func l8WorkerV2ExactTopLevelSuccessAfterCall(function *ast.FuncDecl, object types.Object, call *ast.CallExpr, info *types.Info) bool {
	if !l8WorkerV2FunctionReturnsObject(function, object, info) || call == nil {
		return false
	}
	for _, statement := range function.Body.List {
		returned, ok := statement.(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 2 || !l8WorkerV2IsNilExpression(returned.Results[1], info) {
			continue
		}
		return returned.Pos() > call.Pos() && l8WorkerV2ExpressionObject(returned.Results[0], info) == object
	}
	return false
}

func l8WorkerV2ExactTopLevelCodecConditional(function *ast.FuncDecl, call *ast.CallExpr, info *types.Info) bool {
	conditional := l8WorkerV2TopLevelIfContainingCall(function, call)
	if conditional == nil || conditional.Else != nil {
		return false
	}
	errObject := l8WorkerV2IfInitializerErrorObject(conditional, call, info)
	return errObject != nil && l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, errObject, info)
}

func l8WorkerV2ObjectHasNoReassignments(function *ast.FuncDecl, object types.Object, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	target := func(expression ast.Expr) bool {
		return l8WorkerV2ExpressionObject(expression, info) == object
	}
	aliases := l8WorkerV2PointerAliases(function, target, info)
	if !l8WorkerV2StorageHasNoEscapes(function, target, aliases, info) {
		return false
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			for _, left := range statement.Lhs {
				if target(left) {
					identifier, _ := l8WorkerV2UnparenExpression(left).(*ast.Ident)
					if identifier != nil && info.Defs[identifier] == object {
						continue
					}
					valid = false
					return false
				}
				if l8WorkerV2AssignmentMutatesStorage(left, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if target(statement.X) || l8WorkerV2AssignmentMutatesStorage(statement.X, target, aliases, info) {
				valid = false
				return false
			}
		case *ast.RangeStmt:
			if target(statement.Key) || target(statement.Value) ||
				l8WorkerV2AssignmentMutatesStorage(statement.Key, target, aliases, info) || l8WorkerV2AssignmentMutatesStorage(statement.Value, target, aliases, info) {
				valid = false
				return false
			}
		}
		return true
	})
	return valid
}

func l8WorkerV2ObjectHasNoIndirectMutations(function *ast.FuncDecl, object types.Object, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	target := func(expression ast.Expr) bool {
		return l8WorkerV2ExpressionObject(expression, info) == object
	}
	aliases := l8WorkerV2PointerAliases(function, target, info)
	if !l8WorkerV2StorageHasNoEscapes(function, target, aliases, info) {
		return false
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			for _, left := range statement.Lhs {
				if l8WorkerV2AssignmentMutatesStorage(left, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if l8WorkerV2AssignmentMutatesStorage(statement.X, target, aliases, info) {
				valid = false
				return false
			}
		}
		return true
	})
	return valid
}

func l8WorkerV2SelectorHasNoMutations(function *ast.FuncDecl, receiver types.Object, field string, info *types.Info) bool {
	if function == nil || function.Body == nil || receiver == nil || field == "" {
		return false
	}
	target := func(expression ast.Expr) bool {
		selector, ok := l8WorkerV2UnparenExpression(expression).(*ast.SelectorExpr)
		return ok && selector.Sel.Name == field && l8WorkerV2ExpressionObject(selector.X, info) == receiver
	}
	aliases := l8WorkerV2PointerAliases(function, target, info)
	if !l8WorkerV2StorageHasNoEscapes(function, target, aliases, info) {
		return false
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			for _, left := range statement.Lhs {
				if target(left) || l8WorkerV2AssignmentMutatesStorage(left, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if target(statement.X) || l8WorkerV2AssignmentMutatesStorage(statement.X, target, aliases, info) {
				valid = false
				return false
			}
		}
		return true
	})
	return valid
}

func l8WorkerV2PointerAliases(function *ast.FuncDecl, target func(ast.Expr) bool, info *types.Info) map[types.Object]bool {
	aliases := make(map[types.Object]bool)
	changed := true
	for changed {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch statement := node.(type) {
			case *ast.AssignStmt:
				if len(statement.Lhs) != len(statement.Rhs) {
					return true
				}
				for index, right := range statement.Rhs {
					left := l8WorkerV2ExpressionObject(statement.Lhs[index], info)
					if left != nil && !aliases[left] && l8WorkerV2ExpressionPointsToStorage(right, target, aliases, info) {
						aliases[left] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				if len(statement.Names) != len(statement.Values) {
					return true
				}
				for index, right := range statement.Values {
					left := info.Defs[statement.Names[index]]
					if left != nil && !aliases[left] && l8WorkerV2ExpressionPointsToStorage(right, target, aliases, info) {
						aliases[left] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func l8WorkerV2ExpressionPointsToStorage(expression ast.Expr, target func(ast.Expr) bool, aliases map[types.Object]bool, info *types.Info) bool {
	expression = l8WorkerV2UnparenExpression(expression)
	if address, ok := expression.(*ast.UnaryExpr); ok && address.Op == token.AND {
		return l8WorkerV2ExpressionRootedInStorage(address.X, target, aliases, info)
	}
	return aliases[l8WorkerV2ExpressionObject(expression, info)]
}

func l8WorkerV2ExpressionRootedInStorage(expression ast.Expr, target func(ast.Expr) bool, aliases map[types.Object]bool, info *types.Info) bool {
	expression = l8WorkerV2UnparenExpression(expression)
	if expression == nil {
		return false
	}
	if target(expression) || aliases[l8WorkerV2ExpressionObject(expression, info)] {
		return true
	}
	switch rooted := expression.(type) {
	case *ast.SelectorExpr:
		return l8WorkerV2ExpressionRootedInStorage(rooted.X, target, aliases, info)
	case *ast.StarExpr:
		return l8WorkerV2ExpressionRootedInStorage(rooted.X, target, aliases, info)
	case *ast.IndexExpr:
		return l8WorkerV2ExpressionRootedInStorage(rooted.X, target, aliases, info)
	case *ast.IndexListExpr:
		return l8WorkerV2ExpressionRootedInStorage(rooted.X, target, aliases, info)
	case *ast.SliceExpr:
		return l8WorkerV2ExpressionRootedInStorage(rooted.X, target, aliases, info)
	default:
		return false
	}
}

func l8WorkerV2AssignmentMutatesStorage(expression ast.Expr, target func(ast.Expr) bool, aliases map[types.Object]bool, info *types.Info) bool {
	expression = l8WorkerV2UnparenExpression(expression)
	switch written := expression.(type) {
	case *ast.SelectorExpr:
		return l8WorkerV2ExpressionRootedInStorage(written.X, target, aliases, info)
	case *ast.StarExpr:
		return l8WorkerV2ExpressionRootedInStorage(written.X, target, aliases, info)
	case *ast.IndexExpr:
		return l8WorkerV2ExpressionRootedInStorage(written.X, target, aliases, info)
	default:
		return false
	}
}

func l8WorkerV2StorageHasNoEscapes(function *ast.FuncDecl, target func(ast.Expr) bool, aliases map[types.Object]bool, info *types.Info) bool {
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		switch statement := node.(type) {
		case *ast.FuncLit:
			if !l8WorkerV2ClosurePreservesStorage(statement.Body, target, aliases, info) {
				valid = false
			}
			return false
		case *ast.CallExpr:
			if selector, ok := l8WorkerV2UnparenExpression(statement.Fun).(*ast.SelectorExpr); ok && l8WorkerV2ExpressionPointsToStorage(selector.X, target, aliases, info) {
				valid = false
				return false
			}
			for index, argument := range statement.Args {
				if !l8WorkerV2ExpressionPointsToStorage(argument, target, aliases, info) {
					continue
				}
				if !l8WorkerV2AllowedDecoderOutputAddress(statement, index, argument, target, info) {
					valid = false
					return false
				}
			}
		case *ast.ReturnStmt:
			for _, result := range statement.Results {
				if l8WorkerV2ExpressionPointsToStorage(result, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.SendStmt:
			if l8WorkerV2ExpressionPointsToStorage(statement.Value, target, aliases, info) {
				valid = false
				return false
			}
		case *ast.CompositeLit:
			for _, element := range statement.Elts {
				if l8WorkerV2NodeReferencesPointerStorage(element, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.AssignStmt:
			for index, right := range statement.Rhs {
				if !l8WorkerV2ExpressionPointsToStorage(right, target, aliases, info) {
					continue
				}
				if len(statement.Lhs) != len(statement.Rhs) || !l8WorkerV2IsLocalPointerAliasTarget(statement.Lhs[index], info) {
					valid = false
					return false
				}
			}
		case *ast.ValueSpec:
			for index, right := range statement.Values {
				if !l8WorkerV2ExpressionPointsToStorage(right, target, aliases, info) {
					continue
				}
				if len(statement.Names) != len(statement.Values) || !l8WorkerV2IsLocalPointerAliasTarget(statement.Names[index], info) {
					valid = false
					return false
				}
			}
		}
		return true
	})
	return valid
}

func l8WorkerV2ClosurePreservesStorage(body *ast.BlockStmt, target func(ast.Expr) bool, aliases map[types.Object]bool, info *types.Info) bool {
	valid := true
	ast.Inspect(body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			for _, left := range statement.Lhs {
				if target(left) || l8WorkerV2AssignmentMutatesStorage(left, target, aliases, info) {
					valid = false
					return false
				}
			}
			for index, right := range statement.Rhs {
				if !l8WorkerV2ExpressionPointsToStorage(right, target, aliases, info) {
					continue
				}
				if len(statement.Lhs) != len(statement.Rhs) || !l8WorkerV2IsLocalPointerAliasTarget(statement.Lhs[index], info) {
					valid = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if target(statement.X) || l8WorkerV2AssignmentMutatesStorage(statement.X, target, aliases, info) {
				valid = false
				return false
			}
		case *ast.RangeStmt:
			if target(statement.Key) || target(statement.Value) || l8WorkerV2AssignmentMutatesStorage(statement.Key, target, aliases, info) || l8WorkerV2AssignmentMutatesStorage(statement.Value, target, aliases, info) {
				valid = false
				return false
			}
		case *ast.CallExpr:
			if selector, ok := l8WorkerV2UnparenExpression(statement.Fun).(*ast.SelectorExpr); ok && l8WorkerV2ExpressionPointsToStorage(selector.X, target, aliases, info) {
				valid = false
				return false
			}
			for _, argument := range statement.Args {
				if l8WorkerV2ExpressionPointsToStorage(argument, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.ReturnStmt:
			for _, result := range statement.Results {
				if l8WorkerV2ExpressionPointsToStorage(result, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.SendStmt:
			if l8WorkerV2ExpressionPointsToStorage(statement.Value, target, aliases, info) {
				valid = false
				return false
			}
		case *ast.CompositeLit:
			for _, element := range statement.Elts {
				if l8WorkerV2NodeReferencesPointerStorage(element, target, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.ValueSpec:
			for index, right := range statement.Values {
				if !l8WorkerV2ExpressionPointsToStorage(right, target, aliases, info) {
					continue
				}
				if len(statement.Names) != len(statement.Values) || !l8WorkerV2IsLocalPointerAliasTarget(statement.Names[index], info) {
					valid = false
					return false
				}
			}
		}
		return true
	})
	return valid
}

func l8WorkerV2AllowedDecoderOutputAddress(call *ast.CallExpr, argumentIndex int, argument ast.Expr, target func(ast.Expr) bool, info *types.Info) bool {
	if argumentIndex != 2 || !l8WorkerV2IsTypedDecoderInnerCall(call, info) {
		return false
	}
	address, ok := l8WorkerV2UnparenExpression(argument).(*ast.UnaryExpr)
	return ok && address.Op == token.AND && target(address.X)
}

func l8WorkerV2IsLocalPointerAliasTarget(expression ast.Expr, info *types.Info) bool {
	identifier, ok := l8WorkerV2UnparenExpression(expression).(*ast.Ident)
	if !ok || identifier.Name == "_" || l8WorkerV2ExpressionObject(identifier, info) == nil {
		return false
	}
	_, pointer := types.Unalias(info.TypeOf(identifier)).(*types.Pointer)
	return pointer
}

func l8WorkerV2NodeReferencesPointerStorage(node ast.Node, target func(ast.Expr) bool, aliases map[types.Object]bool, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(current ast.Node) bool {
		if found {
			return false
		}
		expression, ok := current.(ast.Expr)
		if ok && l8WorkerV2ExpressionPointsToStorage(expression, target, aliases, info) {
			found = true
			return false
		}
		return true
	})
	return found
}

func l8WorkerV2ObjectOnlyConsumedByExactCalls(function *ast.FuncDecl, object types.Object, allowedCalls []*ast.CallExpr, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	aliases := l8WorkerV2ValueAliases(function, object, info)
	allowed := make(map[*ast.CallExpr]bool, len(allowedCalls))
	for _, call := range allowedCalls {
		if call != nil {
			allowed[call] = true
		}
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, closure := l8WorkerV2UnparenExpression(call.Fun).(*ast.FuncLit); closure {
			return true
		}
		if allowed[call] {
			return false
		}
		if l8WorkerV2NodeReferencesObjectSet(call, object, aliases, info) {
			valid = false
			return false
		}
		return true
	})
	return valid
}

func l8WorkerV2ObjectHasNoWholeValueEscapes(function *ast.FuncDecl, object types.Object, allowedCalls []*ast.CallExpr, allowedAssertions []*ast.TypeAssertExpr, allowFinalReturn bool, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	aliases := l8WorkerV2ValueAliases(function, object, info)
	callSet := make(map[*ast.CallExpr]bool, len(allowedCalls))
	for _, call := range allowedCalls {
		if call != nil {
			callSet[call] = true
		}
	}
	assertionSet := make(map[*ast.TypeAssertExpr]bool, len(allowedAssertions))
	for _, assertion := range allowedAssertions {
		if assertion != nil {
			assertionSet[assertion] = true
		}
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		switch statement := node.(type) {
		case *ast.CallExpr:
			if callSet[statement] {
				return false
			}
			if l8WorkerV2CallCarriesWholeObject(statement, object, aliases, info) {
				valid = false
				return false
			}
		case *ast.TypeAssertExpr:
			if assertionSet[statement] {
				return false
			}
			if l8WorkerV2ExpressionCarriesWholeObject(statement.X, object, aliases, info) {
				valid = false
				return false
			}
		case *ast.SendStmt:
			if l8WorkerV2ExpressionCarriesWholeObject(statement.Chan, object, aliases, info) ||
				l8WorkerV2ExpressionCarriesWholeObject(statement.Value, object, aliases, info) {
				valid = false
				return false
			}
		case *ast.RangeStmt:
			if l8WorkerV2ExpressionCarriesWholeObject(statement.X, object, aliases, info) {
				valid = false
				return false
			}
		case *ast.ReturnStmt:
			if allowFinalReturn && l8WorkerV2IsExactFinalObjectReturn(function, statement, object, info) {
				return false
			}
			for _, result := range statement.Results {
				if l8WorkerV2ExpressionCarriesWholeObject(result, object, aliases, info) {
					valid = false
					return false
				}
			}
		case *ast.AssignStmt:
			if l8WorkerV2AssignmentDefinesAllowedAssertionAlias(statement, object, assertionSet, info) {
				return true
			}
			for _, right := range statement.Rhs {
				if !l8WorkerV2ExpressionCarriesWholeObject(right, object, aliases, info) {
					continue
				}
				valid = false
				return false
			}
		case *ast.ValueSpec:
			for _, right := range statement.Values {
				if !l8WorkerV2ExpressionCarriesWholeObject(right, object, aliases, info) {
					continue
				}
				valid = false
				return false
			}
		case *ast.CompositeLit:
			if l8WorkerV2NodeReferencesObjectSet(statement, object, aliases, info) {
				valid = false
				return false
			}
		}
		return true
	})
	return valid
}

func l8WorkerV2AssignmentDefinesAllowedAssertionAlias(assignment *ast.AssignStmt, object types.Object, assertions map[*ast.TypeAssertExpr]bool, info *types.Info) bool {
	if assignment == nil || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || l8WorkerV2ExpressionObject(assignment.Rhs[0], info) != object {
		return false
	}
	alias := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	if alias == nil {
		return false
	}
	for assertion := range assertions {
		if l8WorkerV2ExpressionObject(assertion.X, info) == alias {
			return true
		}
	}
	return false
}

func l8WorkerV2ExpressionCarriesWholeObject(expression ast.Expr, object types.Object, aliases map[types.Object]bool, info *types.Info) bool {
	expression = l8WorkerV2UnparenExpression(expression)
	referenced := l8WorkerV2ExpressionObject(expression, info)
	if referenced == object || aliases[referenced] {
		return true
	}
	_, composite := expression.(*ast.CompositeLit)
	return composite && l8WorkerV2NodeReferencesObjectSet(expression, object, aliases, info)
}

func l8WorkerV2CallCarriesWholeObject(call *ast.CallExpr, object types.Object, aliases map[types.Object]bool, info *types.Info) bool {
	if call == nil {
		return false
	}
	if selector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr); ok && l8WorkerV2ExpressionCarriesWholeObject(selector.X, object, aliases, info) {
		return true
	}
	for _, argument := range call.Args {
		if l8WorkerV2ExpressionCarriesWholeObject(argument, object, aliases, info) {
			return true
		}
	}
	return false
}

func l8WorkerV2IsExactFinalObjectReturn(function *ast.FuncDecl, returned *ast.ReturnStmt, object types.Object, info *types.Info) bool {
	if function == nil || function.Body == nil || returned == nil || len(function.Body.List) == 0 || function.Body.List[len(function.Body.List)-1] != returned || len(returned.Results) != 2 {
		return false
	}
	return l8WorkerV2ExpressionObject(returned.Results[0], info) == object && l8WorkerV2IsNilExpression(returned.Results[1], info)
}

func l8WorkerV2ValueAliases(function *ast.FuncDecl, object types.Object, info *types.Info) map[types.Object]bool {
	aliases := make(map[types.Object]bool)
	changed := true
	for changed {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch statement := node.(type) {
			case *ast.AssignStmt:
				if len(statement.Lhs) != len(statement.Rhs) {
					return true
				}
				for index, right := range statement.Rhs {
					left := l8WorkerV2ExpressionObject(statement.Lhs[index], info)
					rightObject := l8WorkerV2ExpressionObject(right, info)
					if left != nil && !aliases[left] && (rightObject == object || aliases[rightObject]) {
						aliases[left] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				if len(statement.Names) != len(statement.Values) {
					return true
				}
				for index, right := range statement.Values {
					left := info.Defs[statement.Names[index]]
					rightObject := l8WorkerV2ExpressionObject(right, info)
					if left != nil && !aliases[left] && (rightObject == object || aliases[rightObject]) {
						aliases[left] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func l8WorkerV2NodeReferencesObjectSet(node ast.Node, object types.Object, aliases map[types.Object]bool, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(current ast.Node) bool {
		if found {
			return false
		}
		expression, ok := current.(ast.Expr)
		if !ok {
			return true
		}
		referenced := l8WorkerV2ExpressionObject(expression, info)
		if referenced == object || aliases[referenced] {
			found = true
			return false
		}
		return true
	})
	return found
}

func l8WorkerV2ObjectIsAcquiredCallResult(function *ast.FuncDecl, object types.Object, callee string, exactArgument types.Object, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	matches := 0
	for _, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) < 1 || len(assignment.Rhs) != 1 || l8WorkerV2ExpressionObject(assignment.Lhs[0], info) != object {
			continue
		}
		call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
		if !ok {
			continue
		}
		called := l8WorkerV2CalledObject(call.Fun, info)
		if callee != "" && !l8WorkerV2IsExactPackageFunctionObject(called, callee) {
			continue
		}
		if exactArgument != nil && (len(call.Args) != 1 || l8WorkerV2ExpressionObject(call.Args[0], info) != exactArgument) {
			continue
		}
		matches++
	}
	return matches == 1
}

func l8WorkerV2IsExactStoredJobOpenCall(file *l8WorkerV2ParsedFile, load *ast.FuncDecl, call *ast.CallExpr, store, jobID types.Object, info *types.Info) bool {
	if file == nil || load == nil || call == nil || store == nil || jobID == nil || len(call.Args) != 1 || l8WorkerV2ExpressionObject(call.Args[0], info) != jobID {
		return false
	}
	selector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if !ok || l8WorkerV2ExpressionObject(selector.X, info) != store {
		return false
	}
	selection := info.Selections[selector]
	method, ok := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
	if !ok || selection == nil || selection.Kind() != types.MethodVal || selection.Obj() != method || method.Name() != "openStoredJobStateV2" || method.Pkg() == nil || method.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" {
		return false
	}
	signature, ok := method.Type().(*types.Signature)
	if !ok || !l8WorkerV2IsExactJobStoreV2Pointer(signature.Recv().Type()) || signature.TypeParams() != nil || signature.RecvTypeParams() != nil || signature.Params().Len() != 1 || signature.Results().Len() != 2 ||
		!types.Identical(signature.Params().At(0).Type(), types.Universe.Lookup("string").Type()) ||
		!types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("error").Type()) {
		return false
	}
	readerType := method.Pkg().Scope().Lookup("storedJobReaderV2")
	_, exactOpener := l8WorkerV2ExactReceiverRootedStoredJobOpener(file, method, info)
	return readerType != nil && types.Identical(signature.Results().At(0).Type(), readerType.Type()) &&
		l8WorkerV2MethodReferencedOnlyByCall(load, method, selector, info) &&
		exactOpener
}

func l8WorkerV2ExactReceiverRootedStoredJobOpener(file *l8WorkerV2ParsedFile, method *types.Func, info *types.Info) ([]*ast.CallExpr, bool) {
	if file == nil || file.parsed == nil || method == nil {
		return nil, false
	}
	var opener *ast.FuncDecl
	for _, declaration := range file.parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || info.Defs[function.Name] != method {
			continue
		}
		if opener != nil {
			return nil, false
		}
		opener = function
	}
	if opener == nil || opener.Body == nil || len(opener.Body.List) != 5 {
		return nil, false
	}
	receiver := l8WorkerV2ExactReceiverObject(opener, "jobStoreV2", true, info)
	parameters := l8WorkerV2FunctionParameterObjects(opener, info)
	if receiver == nil || len(parameters) != 1 || !l8WorkerV2ExactStoredJobOpenerInputGuard(opener.Body.List[0], receiver, parameters[0], info) {
		return nil, false
	}
	pathAssignment, ok := opener.Body.List[1].(*ast.AssignStmt)
	if !ok || pathAssignment.Tok != token.DEFINE || len(pathAssignment.Lhs) != 1 || len(pathAssignment.Rhs) != 1 {
		return nil, false
	}
	pathObject := l8WorkerV2ExpressionObject(pathAssignment.Lhs[0], info)
	joinCall, ok := l8WorkerV2UnparenExpression(pathAssignment.Rhs[0]).(*ast.CallExpr)
	if !ok || pathObject == nil || !l8WorkerV2IsExactPackageCall(joinCall, "path/filepath", "Join", 2, info) ||
		!l8WorkerV2ExactSelectorRoot(joinCall.Args[0], receiver, "root", info) ||
		!l8WorkerV2ExactStoredJobFilename(joinCall.Args[1], parameters[0], info) {
		return nil, false
	}
	statAssignment, ok := opener.Body.List[2].(*ast.AssignStmt)
	if !ok || statAssignment.Tok != token.DEFINE || len(statAssignment.Lhs) != 2 || len(statAssignment.Rhs) != 1 {
		return nil, false
	}
	statInfo := l8WorkerV2ExpressionObject(statAssignment.Lhs[0], info)
	statErr := l8WorkerV2ExpressionObject(statAssignment.Lhs[1], info)
	statCall, ok := l8WorkerV2UnparenExpression(statAssignment.Rhs[0]).(*ast.CallExpr)
	if !ok || statInfo == nil || statErr == nil || !l8WorkerV2IsExactPackageCall(statCall, "os", "Lstat", 1, info) || l8WorkerV2ExpressionObject(statCall.Args[0], info) != pathObject {
		return nil, false
	}
	inspectionCalls, exactInspection := l8WorkerV2ExactStoredJobFileInspection(opener.Body.List[3], statInfo, statErr, info)
	if !exactInspection {
		return nil, false
	}
	returned, ok := opener.Body.List[4].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return nil, false
	}
	openCall, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.CallExpr)
	if !ok || !l8WorkerV2IsExactPackageCall(openCall, "os", "Open", 1, info) || l8WorkerV2ExpressionObject(openCall.Args[0], info) != pathObject {
		return nil, false
	}
	return inspectionCalls, true
}

func l8WorkerV2ExactStoredJobOpenerInputGuard(statement ast.Stmt, store, jobID types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 1 || !l8WorkerV2IsNilAndExactErrorReturn(conditional.Body.List[0], "stored job state is unavailable", info) {
		return false
	}
	either, ok := l8WorkerV2UnparenExpression(conditional.Cond).(*ast.BinaryExpr)
	if !ok || either.Op != token.LOR || !l8WorkerV2ExactObjectNilComparison(either.X, store, token.EQL, info) {
		return false
	}
	negated, ok := l8WorkerV2UnparenExpression(either.Y).(*ast.UnaryExpr)
	if !ok || negated.Op != token.NOT {
		return false
	}
	call, ok := l8WorkerV2UnparenExpression(negated.X).(*ast.CallExpr)
	return ok && l8WorkerV2IsExactPackageFunctionCall(call, "validJobSafeID", []types.Object{jobID}, info)
}

func l8WorkerV2ExactStoredJobFileInspection(statement ast.Stmt, statInfo, statErr types.Object, info *types.Info) ([]*ast.CallExpr, bool) {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 1 || !l8WorkerV2IsNilAndExactErrorReturn(conditional.Body.List[0], "stored job state is unavailable", info) {
		return nil, false
	}
	terms := l8WorkerV2FlattenBinaryExpressions(conditional.Cond, token.LOR)
	if len(terms) != 6 || !l8WorkerV2ExactObjectNilComparison(terms[0], statErr, token.NEQ, info) {
		return nil, false
	}
	regularMode, regular := l8WorkerV2ExactNegatedFileInfoRegular(terms[1], statInfo, info)
	symlinkMode, symlink := l8WorkerV2ExactFileInfoModeMaskComparison(terms[2], statInfo, "ModeSymlink", token.NEQ, 0, info)
	permissionMode, permission := l8WorkerV2ExactFileInfoModeMethodComparison(terms[3], statInfo, "Perm", token.NEQ, 0o600, info)
	nonemptySize, nonempty := l8WorkerV2ExactFileInfoIntegerComparison(terms[4], statInfo, "Size", token.LEQ, 0, info)
	boundedSize, bounded := l8WorkerV2ExactFileInfoPackageConstantComparison(terms[5], statInfo, "Size", token.GTR, "maxStoredJobStateV2Bytes", 64<<10, info)
	if !regular || !symlink || !permission || !nonempty || !bounded {
		return nil, false
	}
	return []*ast.CallExpr{regularMode, symlinkMode, permissionMode, nonemptySize, boundedSize}, true
}

func l8WorkerV2FlattenBinaryExpressions(expression ast.Expr, operation token.Token) []ast.Expr {
	binary, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || binary.Op != operation {
		return []ast.Expr{expression}
	}
	left := l8WorkerV2FlattenBinaryExpressions(binary.X, operation)
	return append(left, l8WorkerV2FlattenBinaryExpressions(binary.Y, operation)...)
}

func l8WorkerV2ExactNegatedFileInfoRegular(expression ast.Expr, statInfo types.Object, info *types.Info) (*ast.CallExpr, bool) {
	negated, ok := l8WorkerV2UnparenExpression(expression).(*ast.UnaryExpr)
	if !ok || negated.Op != token.NOT {
		return nil, false
	}
	regularCall, ok := l8WorkerV2UnparenExpression(negated.X).(*ast.CallExpr)
	if !ok || len(regularCall.Args) != 0 {
		return nil, false
	}
	selector, ok := l8WorkerV2UnparenExpression(regularCall.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "IsRegular" {
		return nil, false
	}
	modeCall, ok := l8WorkerV2UnparenExpression(selector.X).(*ast.CallExpr)
	if !ok || !l8WorkerV2ExactObjectMethodCall(modeCall, statInfo, "Mode", nil, info) {
		return nil, false
	}
	called := l8WorkerV2CalledObject(regularCall.Fun, info)
	return modeCall, called != nil && called.Pkg() != nil && called.Pkg().Path() == "io/fs" && called.Name() == "IsRegular"
}

func l8WorkerV2ExactFileInfoModeMaskComparison(expression ast.Expr, statInfo types.Object, maskName string, operation token.Token, value int64, info *types.Info) (*ast.CallExpr, bool) {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || !l8WorkerV2ExactIntegerConstant(comparison.Y, value, info) {
		return nil, false
	}
	masked, ok := l8WorkerV2UnparenExpression(comparison.X).(*ast.BinaryExpr)
	if !ok || masked.Op != token.AND {
		return nil, false
	}
	modeCall, ok := l8WorkerV2UnparenExpression(masked.X).(*ast.CallExpr)
	mask := l8WorkerV2ExpressionObject(masked.Y, info)
	return modeCall, ok && l8WorkerV2ExactObjectMethodCall(modeCall, statInfo, "Mode", nil, info) &&
		mask != nil && mask.Pkg() != nil && mask.Pkg().Path() == "os" && mask.Name() == maskName
}

func l8WorkerV2ExactFileInfoModeMethodComparison(expression ast.Expr, statInfo types.Object, method string, operation token.Token, value int64, info *types.Info) (*ast.CallExpr, bool) {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || !l8WorkerV2ExactIntegerConstant(comparison.Y, value, info) {
		return nil, false
	}
	methodCall, ok := l8WorkerV2UnparenExpression(comparison.X).(*ast.CallExpr)
	if !ok || len(methodCall.Args) != 0 {
		return nil, false
	}
	selector, ok := l8WorkerV2UnparenExpression(methodCall.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return nil, false
	}
	modeCall, ok := l8WorkerV2UnparenExpression(selector.X).(*ast.CallExpr)
	if !ok || !l8WorkerV2ExactObjectMethodCall(modeCall, statInfo, "Mode", nil, info) {
		return nil, false
	}
	called := l8WorkerV2CalledObject(methodCall.Fun, info)
	return modeCall, called != nil && called.Pkg() != nil && called.Pkg().Path() == "io/fs" && called.Name() == method
}

func l8WorkerV2ExactFileInfoIntegerComparison(expression ast.Expr, statInfo types.Object, method string, operation token.Token, value int64, info *types.Info) (*ast.CallExpr, bool) {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || !l8WorkerV2ExactIntegerConstant(comparison.Y, value, info) {
		return nil, false
	}
	call, ok := l8WorkerV2UnparenExpression(comparison.X).(*ast.CallExpr)
	return call, ok && l8WorkerV2ExactObjectMethodCall(call, statInfo, method, nil, info)
}

func l8WorkerV2ExactFileInfoPackageConstantComparison(expression ast.Expr, statInfo types.Object, method string, operation token.Token, constantName string, value int64, info *types.Info) (*ast.CallExpr, bool) {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || !l8WorkerV2ExactPackageInt64Constant(comparison.Y, constantName, value, info) {
		return nil, false
	}
	call, ok := l8WorkerV2UnparenExpression(comparison.X).(*ast.CallExpr)
	return call, ok && l8WorkerV2ExactObjectMethodCall(call, statInfo, method, nil, info)
}

func l8WorkerV2ExactIntegerConstant(expression ast.Expr, value int64, info *types.Info) bool {
	constantValue := info.Types[expression].Value
	if constantValue == nil {
		return false
	}
	got, exact := constant.Int64Val(constantValue)
	return exact && got == value
}

func l8WorkerV2ExactObjectNilComparison(expression ast.Expr, object types.Object, operation token.Token, info *types.Info) bool {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	return ok && comparison.Op == operation && l8WorkerV2ExpressionObject(comparison.X, info) == object && l8WorkerV2IsNilExpression(comparison.Y, info)
}

func l8WorkerV2IsNilAndExactErrorReturn(statement ast.Stmt, message string, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 || !l8WorkerV2IsNilExpression(returned.Results[0], info) {
		return false
	}
	call, ok := l8WorkerV2UnparenExpression(returned.Results[1]).(*ast.CallExpr)
	if !ok || !l8WorkerV2IsExactPackageCall(call, "errors", "New", 1, info) {
		return false
	}
	value := info.Types[call.Args[0]].Value
	return value != nil && value.Kind() == constant.String && constant.StringVal(value) == message
}

func l8WorkerV2IsExactPackageFunctionCall(call *ast.CallExpr, name string, arguments []types.Object, info *types.Info) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != len(arguments) || !l8WorkerV2IsExactPackageFunctionObject(l8WorkerV2CalledObject(call.Fun, info), name) {
		return false
	}
	for index, argument := range arguments {
		if l8WorkerV2ExpressionObject(call.Args[index], info) != argument {
			return false
		}
	}
	return true
}

func l8WorkerV2IsExactPackageCall(call *ast.CallExpr, packagePath, name string, argumentCount int, info *types.Info) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != argumentCount {
		return false
	}
	function, ok := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
	return ok && function.Pkg() != nil && function.Pkg().Path() == packagePath && function.Name() == name
}

func l8WorkerV2ExactStoredJobFilename(expression ast.Expr, jobID types.Object, info *types.Info) bool {
	joined, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || joined.Op != token.ADD || l8WorkerV2ExpressionObject(joined.X, info) != jobID {
		return false
	}
	value := info.Types[joined.Y].Value
	return value != nil && value.Kind() == constant.String && constant.StringVal(value) == ".json"
}

func l8WorkerV2IsExactJobStoreV2Pointer(typ types.Type) bool {
	pointer, ok := types.Unalias(typ).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(pointer.Elem()).(*types.Named)
	return ok && named.TypeArgs().Len() == 0 && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" && named.Obj().Name() == "jobStoreV2"
}

func l8WorkerV2MethodReferencedOnlyByCall(function *ast.FuncDecl, method *types.Func, allowed *ast.SelectorExpr, info *types.Info) bool {
	if function == nil || function.Body == nil || method == nil || allowed == nil {
		return false
	}
	references := 0
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		selection := info.Selections[selector]
		if selection == nil || selection.Obj() != method {
			return true
		}
		references++
		valid = selector == allowed
		return valid
	})
	return valid && references == 1
}

func l8WorkerV2IsExactPackageFunctionObject(object types.Object, name string) bool {
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil || function.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || function.Name() != name {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	return ok && signature.Recv() == nil && function.Pkg().Scope().Lookup(name) == function
}

func l8WorkerV2ExactThreeStatementResponseWrapper(function *ast.FuncDecl, call *ast.CallExpr, output types.Object, info *types.Info) bool {
	if function == nil || function.Body == nil || len(function.Body.List) != 3 || output == nil {
		return false
	}
	declaration, ok := function.Body.List[0].(*ast.DeclStmt)
	if !ok || l8WorkerV2ExpressionObjectFromSingleVarDeclaration(declaration, info) != output {
		return false
	}
	conditional, ok := function.Body.List[1].(*ast.IfStmt)
	if !ok || !l8WorkerV2IfInitializerCalls(conditional, call, info) || len(conditional.Body.List) != 1 {
		return false
	}
	errObject := l8WorkerV2IfInitializerErrorObject(conditional, call, info)
	if errObject == nil || !l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) || !l8WorkerV2IsZeroStructAndObjectReturn(conditional.Body.List[0], "Response", errObject, info) {
		return false
	}
	returned, ok := function.Body.List[2].(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && l8WorkerV2ExpressionObject(returned.Results[0], info) == output && l8WorkerV2IsNilExpression(returned.Results[1], info)
}

func l8WorkerV2ExpressionObjectFromSingleVarDeclaration(statement *ast.DeclStmt, info *types.Info) types.Object {
	if statement == nil {
		return nil
	}
	declaration, ok := statement.Decl.(*ast.GenDecl)
	if !ok || declaration.Tok != token.VAR || len(declaration.Specs) != 1 {
		return nil
	}
	spec, ok := declaration.Specs[0].(*ast.ValueSpec)
	if !ok || len(spec.Names) != 1 || len(spec.Values) != 0 {
		return nil
	}
	return info.Defs[spec.Names[0]]
}

func l8WorkerV2IsZeroStructAndObjectReturn(statement ast.Stmt, structName string, object types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 || l8WorkerV2ExpressionObject(returned.Results[1], info) != object {
		return false
	}
	literal, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.CompositeLit)
	return ok && len(literal.Elts) == 0 && l8WorkerV2IsExactNamedStruct(info.TypeOf(literal), structName)
}

func l8WorkerV2IsExactObjectExpression(expression ast.Expr, info *types.Info) bool {
	_, ok := l8WorkerV2UnparenExpression(expression).(*ast.Ident)
	return ok && l8WorkerV2ExpressionObject(expression, info) != nil
}

func l8WorkerV2ExactPackageInt64Constant(expression ast.Expr, name string, value int64, info *types.Info) bool {
	object, ok := l8WorkerV2ExpressionObject(expression, info).(*types.Const)
	if !ok || object.Pkg() == nil || object.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || object.Name() != name || !types.Identical(object.Type(), types.Universe.Lookup("int64").Type()) {
		return false
	}
	got, exact := constant.Int64Val(object.Val())
	return exact && got == value
}

func l8WorkerV2ExactPostDefaultLimit(function *ast.FuncDecl, call *ast.CallExpr, receiver, limit types.Object, info *types.Info) bool {
	initializations, defaults, writes := 0, 0, 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, left := range assignment.Lhs {
			if l8WorkerV2ExpressionObject(left, info) == limit {
				writes++
			}
		}
		if assignment.Pos() >= call.Pos() || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || l8WorkerV2ExpressionObject(assignment.Lhs[0], info) != limit {
			return true
		}
		if assignment.Tok == token.DEFINE && l8WorkerV2ExactSelectorRoot(assignment.Rhs[0], receiver, "maxResponseBytes", info) {
			initializations++
		}
		return true
	})
	for _, statement := range function.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok || conditional.Pos() >= call.Pos() || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 1 || !l8WorkerV2ExactObjectIntegerComparison(conditional.Cond, limit, token.LEQ, 0, info) {
			continue
		}
		assignment, ok := conditional.Body.List[0].(*ast.AssignStmt)
		if ok && assignment.Tok == token.ASSIGN && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 && l8WorkerV2ExpressionObject(assignment.Lhs[0], info) == limit && l8WorkerV2ExactPackageInt64Constant(assignment.Rhs[0], "defaultMaxResponseBytes", 1<<20, info) {
			defaults++
		}
	}
	return initializations == 1 && defaults == 1 && writes == 2
}

func l8WorkerV2ValidateClientHalfCloseComposition(files []*l8WorkerV2ParsedFile, info *types.Info) error {
	responseInnerDeclared := false
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && function.Name.Name == "decodeWorkerResponseInto" {
				responseInnerDeclared = true
			}
		}
	}
	if !responseInnerDeclared {
		return nil
	}
	for _, file := range files {
		if filepath.Base(file.path) != "client.go" {
			continue
		}
		for _, declaration := range file.parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || function.Name.Name != "RoundTrip" || !l8WorkerV2ReceiverNamed(function, "unixSocketClientTransport", info) {
				continue
			}
			if !l8WorkerV2ExactClientHalfCloseComposition(function, info) {
				return fmt.Errorf("worker-v2 production path in %s declaration %s violates exact client half-close composition", file.path, function.Name.Name)
			}
		}
	}
	return nil
}

func l8WorkerV2ExactClientHalfCloseComposition(function *ast.FuncDecl, info *types.Info) bool {
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if len(parameters) < 2 || function.Body == nil {
		return false
	}
	ctx := parameters[0]
	newEncoder, exactJSONEncode, exactEncode := l8WorkerV2ExactClientRequestEncoderCalls(function, info)
	decodeCall := l8WorkerV2SingleTypedDecoderCall(function, info)
	if !exactEncode || newEncoder == nil || len(newEncoder.Args) != 1 || decodeCall == nil || len(decodeCall.Args) != 3 {
		return false
	}
	decodeObject := l8WorkerV2CalledObject(decodeCall.Fun, info)
	connection := l8WorkerV2ExpressionObject(newEncoder.Args[0], info)
	output := l8WorkerV2AddressedObject(decodeCall.Args[2], "Response", info)
	acquireCall, _ := l8WorkerV2TopLevelAcquisitionForObject(function, connection, info)
	if decodeObject == nil || decodeObject.Name() != "decodeWorkerResponseInto" || connection == nil ||
		l8WorkerV2ExpressionObject(decodeCall.Args[0], info) != connection || output == nil || acquireCall == nil {
		return false
	}
	var halfCloser, okObject types.Object
	var assertionPos, closePos token.Pos
	closeCalls := 0
	var unsupported *ast.IfStmt
	var closeConditional *ast.IfStmt

	for _, statement := range function.Body.List {
		if assignment, ok := statement.(*ast.AssignStmt); ok && assignment.Tok == token.DEFINE && len(assignment.Lhs) >= 1 && len(assignment.Rhs) == 1 {
			if len(assignment.Lhs) == 2 {
				assertion, asserted := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.TypeAssertExpr)
				if asserted && connection != nil && l8WorkerV2ExpressionObject(assertion.X, info) == connection && l8WorkerV2IsExactCloseWriteInterface(assertion.Type, info) {
					halfCloser = l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
					okObject = l8WorkerV2ExpressionObject(assignment.Lhs[1], info)
					assertionPos = assignment.Pos()
				}
			}
		}
		conditional, ok := statement.(*ast.IfStmt)
		if ok && okObject != nil && l8WorkerV2ExactNegatedObject(conditional.Cond, okObject, info) {
			unsupported = conditional
		}
	}
	if halfCloser == nil || okObject == nil {
		return false
	}

	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, selected := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
		if selected && selector.Sel.Name == "CloseWrite" {
			closeCalls++
			if l8WorkerV2ExpressionObject(selector.X, info) == halfCloser {
				closePos = call.Pos()
			}
		}
		return true
	})
	for _, statement := range function.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok || conditional.Init == nil {
			continue
		}
		ast.Inspect(conditional.Init, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && call.Pos() == closePos {
				closeConditional = conditional
			}
			return true
		})
	}
	if unsupported == nil {
		return false
	}
	return acquireCall.Pos() < exactJSONEncode.Pos() && exactJSONEncode.Pos() < assertionPos && assertionPos < unsupported.Pos() && unsupported.End() < closePos && closePos < decodeCall.Pos() && closeCalls == 1 &&
		l8WorkerV2ExactClientNilContextNormalization(function, ctx, acquireCall, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, connection, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, halfCloser, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, okObject, info) &&
		l8WorkerV2ExactContextThenConstantResponseError(unsupported.Body, ctx, "write worker request framing failed", info) &&
		closeConditional != nil && l8WorkerV2ExactCloseWriteErrorConditional(function, closeConditional, halfCloser, ctx, info)
}

func l8WorkerV2ExactClientConnectionHalfCloseAssertion(function *ast.FuncDecl, connection types.Object, info *types.Info) *ast.TypeAssertExpr {
	if function == nil || function.Body == nil || connection == nil {
		return nil
	}
	var result *ast.TypeAssertExpr
	matches := 0
	aliases := l8WorkerV2ValueAliases(function, connection, info)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		assertion, ok := node.(*ast.TypeAssertExpr)
		if !ok || !l8WorkerV2IsExactCloseWriteInterface(assertion.Type, info) {
			return true
		}
		asserted := l8WorkerV2ExpressionObject(assertion.X, info)
		if asserted == connection || aliases[asserted] {
			result = assertion
			matches++
		}
		return true
	})
	if matches != 1 {
		return nil
	}
	return result
}

func l8WorkerV2ExactClientRequestEncoderCalls(function *ast.FuncDecl, info *types.Info) (*ast.CallExpr, *ast.CallExpr, bool) {
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if function == nil || function.Body == nil || len(parameters) < 2 {
		return nil, nil, false
	}
	request := parameters[1]
	for _, statement := range function.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok || conditional.Init == nil {
			continue
		}
		assignment, ok := conditional.Init.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			continue
		}
		encodeCall, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
		if !ok || len(encodeCall.Args) != 1 {
			continue
		}
		encodeSelector, ok := l8WorkerV2UnparenExpression(encodeCall.Fun).(*ast.SelectorExpr)
		if !ok || encodeSelector.Sel.Name != "Encode" {
			continue
		}
		selection := info.Selections[encodeSelector]
		if selection == nil || selection.Obj() == nil || selection.Obj().Pkg() == nil || selection.Obj().Pkg().Path() != "encoding/json" || selection.Obj().Name() != "Encode" {
			continue
		}
		newEncoder, ok := l8WorkerV2UnparenExpression(encodeSelector.X).(*ast.CallExpr)
		if !ok || !l8WorkerV2IsPackageCall(newEncoder, "encoding/json", "NewEncoder", 1, info) {
			continue
		}
		connection := l8WorkerV2ExpressionObject(newEncoder.Args[0], info)
		if connection == nil || !l8WorkerV2ObjectIsAcquiredCallResult(function, connection, "", nil, info) {
			continue
		}
		withDefaults, ok := l8WorkerV2UnparenExpression(encodeCall.Args[0]).(*ast.CallExpr)
		if !ok || len(withDefaults.Args) != 0 {
			continue
		}
		defaultsSelector, ok := l8WorkerV2UnparenExpression(withDefaults.Fun).(*ast.SelectorExpr)
		if !ok || defaultsSelector.Sel.Name != "WithDefaults" || l8WorkerV2ExpressionObject(defaultsSelector.X, info) != request {
			continue
		}
		exactCalls := 0
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			candidate, ok := node.(*ast.CallExpr)
			if !ok || len(candidate.Args) != 1 {
				return true
			}
			candidateSelector, ok := l8WorkerV2UnparenExpression(candidate.Fun).(*ast.SelectorExpr)
			if !ok || candidateSelector.Sel.Name != "Encode" {
				return true
			}
			candidateSelection := info.Selections[candidateSelector]
			if candidateSelection == nil || candidateSelection.Obj() == nil || candidateSelection.Obj().Pkg() == nil || candidateSelection.Obj().Pkg().Path() != "encoding/json" || candidateSelection.Obj().Name() != "Encode" {
				return true
			}
			candidateEncoder, ok := l8WorkerV2UnparenExpression(candidateSelector.X).(*ast.CallExpr)
			if !ok || !l8WorkerV2IsPackageCall(candidateEncoder, "encoding/json", "NewEncoder", 1, info) || l8WorkerV2ExpressionObject(candidateEncoder.Args[0], info) != connection {
				return true
			}
			candidateDefaults, ok := l8WorkerV2UnparenExpression(candidate.Args[0]).(*ast.CallExpr)
			if !ok || len(candidateDefaults.Args) != 0 {
				return true
			}
			candidateDefaultsSelector, ok := l8WorkerV2UnparenExpression(candidateDefaults.Fun).(*ast.SelectorExpr)
			if ok && candidateDefaultsSelector.Sel.Name == "WithDefaults" && l8WorkerV2ExpressionObject(candidateDefaultsSelector.X, info) == request {
				exactCalls++
			}
			return false
		})
		if exactCalls != 1 {
			return nil, nil, false
		}
		return newEncoder, encodeCall, true
	}
	return nil, nil, false
}

func l8WorkerV2IsExactCloseWriteInterface(expression ast.Expr, info *types.Info) bool {
	interfaceType, ok := types.Unalias(info.TypeOf(expression)).(*types.Interface)
	if !ok {
		return false
	}
	interfaceType.Complete()
	if interfaceType.NumMethods() != 1 {
		return false
	}
	method := interfaceType.Method(0)
	signature, ok := method.Type().(*types.Signature)
	return ok && method.Name() == "CloseWrite" && signature.Params().Len() == 0 && signature.Results().Len() == 1 &&
		types.Identical(signature.Results().At(0).Type(), types.Universe.Lookup("error").Type())
}

func l8WorkerV2ExactNegatedObject(expression ast.Expr, object types.Object, info *types.Info) bool {
	negation, ok := l8WorkerV2UnparenExpression(expression).(*ast.UnaryExpr)
	return ok && negation.Op == token.NOT && l8WorkerV2ExpressionObject(negation.X, info) == object
}

func l8WorkerV2ExactCloseWriteErrorConditional(function *ast.FuncDecl, conditional *ast.IfStmt, halfCloser, ctx types.Object, info *types.Info) bool {
	if conditional == nil || conditional.Else != nil || conditional.Init == nil {
		return false
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	errObject := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, selected := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	return errObject != nil && selected && selector.Sel.Name == "CloseWrite" && l8WorkerV2ExpressionObject(selector.X, info) == halfCloser &&
		l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, errObject, info) &&
		l8WorkerV2ExactContextThenConstantResponseError(conditional.Body, ctx, "write worker request framing failed", info)
}

func l8WorkerV2ExactContextThenConstantResponseError(block *ast.BlockStmt, ctx types.Object, message string, info *types.Info) bool {
	if block == nil || len(block.List) != 2 || ctx == nil {
		return false
	}
	conditional, ok := block.List[0].(*ast.IfStmt)
	if !ok || conditional.Init == nil || conditional.Else != nil || len(conditional.Body.List) != 1 {
		return false
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	ctxErr := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	selector, selected := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if ctxErr == nil || !ok || !selected || selector.Sel.Name != "Err" || len(call.Args) != 0 || l8WorkerV2ExpressionObject(selector.X, info) != ctx ||
		!l8WorkerV2IsErrorComparison(conditional.Cond, ctxErr, nil, info) || !l8WorkerV2IsZeroStructAndObjectReturn(conditional.Body.List[0], "Response", ctxErr, info) {
		return false
	}
	return l8WorkerV2IsZeroStructAndConstantErrorReturn(block.List[1], "Response", message, info)
}

func l8WorkerV2IsZeroStructAndConstantErrorReturn(statement ast.Stmt, structName, message string, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 {
		return false
	}
	literal, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.CompositeLit)
	if !ok || len(literal.Elts) != 0 || !l8WorkerV2IsExactNamedStruct(info.TypeOf(literal), structName) {
		return false
	}
	call, ok := l8WorkerV2UnparenExpression(returned.Results[1]).(*ast.CallExpr)
	if !ok || !l8WorkerV2IsConstantErrorsNewCall(call, info) {
		return false
	}
	value := info.Types[call.Args[0]].Value
	return value != nil && constant.StringVal(value) == message
}

func l8WorkerV2ExactClientCodecErrorBranch(function *ast.FuncDecl, call *ast.CallExpr, ctx types.Object, acquireCall *ast.CallExpr, info *types.Info) bool {
	return l8WorkerV2ExactCallContextErrorBranch(function, call, ctx, acquireCall, "read worker response failed", info)
}

func l8WorkerV2ExactClientSafeBranches(function *ast.FuncDecl, connection types.Object, acquireCall *ast.CallExpr, acquireErr types.Object, acquisitionErrorBranch *ast.IfStmt, info *types.Info) bool {
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	matchedCall, matchedErr := l8WorkerV2TopLevelAcquisitionForObject(function, connection, info)
	if len(parameters) != 2 || acquireCall == nil || acquireErr == nil || matchedCall != acquireCall || matchedErr != acquireErr ||
		acquisitionErrorBranch == nil || acquisitionErrorBranch.Init != nil || acquisitionErrorBranch.Else != nil ||
		!l8WorkerV2IsErrorComparison(acquisitionErrorBranch.Cond, acquireErr, nil, info) ||
		l8WorkerV2ObjectUseCount(function, acquireErr, info) != 1 {
		return false
	}
	ctx := parameters[0]
	if !l8WorkerV2ExactContextThenConstantResponseError(acquisitionErrorBranch.Body, ctx, "open worker connection failed", info) {
		return false
	}
	if l8WorkerV2HasCall(function, "encodeWorkerRequest", info) {
		return false
	}
	_, encodeCall, exact := l8WorkerV2ExactClientRequestEncoderCalls(function, info)
	return exact && l8WorkerV2ExactCallContextErrorBranch(function, encodeCall, ctx, acquireCall, "write worker request failed", info)
}

func l8WorkerV2HasCall(function *ast.FuncDecl, name string, info *types.Info) bool {
	found := false
	if function == nil || function.Body == nil {
		return false
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		object := l8WorkerV2CalledObject(call.Fun, info)
		found = object != nil && object.Name() == name
		return !found
	})
	return found
}

func l8WorkerV2ExactStoreSafeBranches(function *ast.FuncDecl, codecCall *ast.CallExpr, acquireErr types.Object, acquisitionErrorBranch *ast.IfStmt, info *types.Info) bool {
	if acquireErr == nil || acquisitionErrorBranch == nil || acquisitionErrorBranch.Init != nil || acquisitionErrorBranch.Else != nil ||
		!l8WorkerV2IsErrorComparison(acquisitionErrorBranch.Cond, acquireErr, nil, info) ||
		l8WorkerV2ObjectUseCount(function, acquireErr, info) != 1 || len(acquisitionErrorBranch.Body.List) != 1 ||
		!l8WorkerV2IsZeroStructAndConstantErrorReturn(acquisitionErrorBranch.Body.List[0], "storedJobStateV2", "stored job state could not be opened", info) {
		return false
	}
	return l8WorkerV2ExactCallConstantStateErrorBranch(function, codecCall, "stored job state is malformed", info)
}

func l8WorkerV2TopLevelAcquisitionForObject(function *ast.FuncDecl, acquired types.Object, info *types.Info) (*ast.CallExpr, types.Object) {
	if function == nil || function.Body == nil || acquired == nil {
		return nil, nil
	}
	var result *ast.CallExpr
	var errObject types.Object
	matches := 0
	for _, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 || l8WorkerV2ExpressionObject(assignment.Lhs[0], info) != acquired {
			continue
		}
		call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
		if !ok {
			continue
		}
		candidateErr := l8WorkerV2ExpressionObject(assignment.Lhs[1], info)
		if candidateErr == nil || !types.Identical(candidateErr.Type(), types.Universe.Lookup("error").Type()) {
			continue
		}
		result = call
		errObject = candidateErr
		matches++
	}
	if matches != 1 {
		return nil, nil
	}
	return result, errObject
}

func l8WorkerV2ObjectUseCount(function *ast.FuncDecl, object types.Object, info *types.Info) int {
	if function == nil || function.Body == nil || object == nil {
		return 0
	}
	uses := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && info.Uses[identifier] == object {
			uses++
		}
		return true
	})
	return uses
}

func l8WorkerV2NoUnconditionalTerminalBefore(function *ast.FuncDecl, target ast.Node, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if function == nil || function.Body == nil || target == nil {
		return false
	}
	for _, statement := range function.Body.List {
		if statement.Pos() >= target.Pos() {
			continue
		}
		if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, true) {
			return false
		}
	}
	return true
}

func l8WorkerV2StaticallyUnconditionalTerminal(statement ast.Stmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis, returnIsTerminal bool) bool {
	switch statement := statement.(type) {
	case *ast.ReturnStmt:
		if l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(statement.Results, info, analysis) {
			return true
		}
		return returnIsTerminal
	case *ast.DeferStmt:
		return l8WorkerV2CallOperandsCannotReturn(statement.Call, info, analysis)
	case *ast.GoStmt:
		return l8WorkerV2CallOperandsCannotReturn(statement.Call, info, analysis)
	case *ast.LabeledStmt:
		return l8WorkerV2StaticallyUnconditionalTerminal(statement.Stmt, info, analysis, returnIsTerminal)
	case *ast.BlockStmt:
		return l8WorkerV2StatementListStaticallyTerminal(statement.List, info, analysis, returnIsTerminal)
	case *ast.ExprStmt:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.X, info, analysis)
	case *ast.AssignStmt:
		return l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(statement.Lhs, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(statement.Rhs, info, analysis)
	case *ast.DeclStmt:
		declaration, ok := statement.Decl.(*ast.GenDecl)
		if !ok {
			return false
		}
		for _, specification := range declaration.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if ok && l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(value.Values, info, analysis) {
				return true
			}
		}
		return false
	case *ast.IfStmt:
		if (statement.Init != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, returnIsTerminal)) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Cond, info, analysis) {
			return true
		}
		value := info.Types[statement.Cond].Value
		if value != nil && value.Kind() == constant.Bool && constant.BoolVal(value) {
			return l8WorkerV2StaticallyUnconditionalTerminal(statement.Body, info, analysis, returnIsTerminal)
		}
		if value != nil && value.Kind() == constant.Bool {
			return statement.Else != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Else, info, analysis, returnIsTerminal)
		}
		return statement.Else != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Body, info, analysis, returnIsTerminal) && l8WorkerV2StaticallyUnconditionalTerminal(statement.Else, info, analysis, returnIsTerminal)
	case *ast.SwitchStmt:
		if (statement.Init != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, returnIsTerminal)) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Tag, info, analysis) {
			return true
		}
		if l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(l8WorkerV2EvaluatedSwitchCaseExpressions(statement, info), info, analysis) {
			return true
		}
		return l8WorkerV2AllCaseClausesStaticallyTerminal(statement.Body, info, analysis, returnIsTerminal)
	case *ast.TypeSwitchStmt:
		if (statement.Init != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, returnIsTerminal)) ||
			(statement.Assign != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Assign, info, analysis, returnIsTerminal)) {
			return true
		}
		return l8WorkerV2AllCaseClausesStaticallyTerminal(statement.Body, info, analysis, returnIsTerminal)
	case *ast.SelectStmt:
		if statement.Body == nil || len(statement.Body.List) == 0 {
			return true
		}
		for _, rawClause := range statement.Body.List {
			clause, ok := rawClause.(*ast.CommClause)
			if !ok {
				return false
			}
			if clause.Comm != nil && l8WorkerV2StaticallyUnconditionalTerminal(clause.Comm, info, analysis, returnIsTerminal) {
				return true
			}
			if !l8WorkerV2ClauseStatementListStaticallyTerminal(clause.Body, info, analysis, returnIsTerminal) {
				return false
			}
		}
		return true
	case *ast.ForStmt:
		if (statement.Init != nil && l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, returnIsTerminal)) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Cond, info, analysis) {
			return true
		}
		if statement.Cond != nil {
			value := info.Types[statement.Cond].Value
			if value == nil || value.Kind() != constant.Bool || !constant.BoolVal(value) {
				return false
			}
		}
		return !l8WorkerV2StatementMayExitEnclosingClause(statement.Body)
	case *ast.RangeStmt:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.X, info, analysis)
	case *ast.SendStmt:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Chan, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Value, info, analysis)
	case *ast.IncDecStmt:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.X, info, analysis)
	default:
		return false
	}
}

func l8WorkerV2StatementListStaticallyTerminal(statements []ast.Stmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis, returnIsTerminal bool) bool {
	for _, statement := range statements {
		if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, returnIsTerminal) {
			return true
		}
	}
	return false
}

func l8WorkerV2AllCaseClausesStaticallyTerminal(body *ast.BlockStmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis, returnIsTerminal bool) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}
	defaultFound := false
	for _, rawClause := range body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok || !l8WorkerV2ClauseStatementListStaticallyTerminal(clause.Body, info, analysis, returnIsTerminal) {
			return false
		}
		if len(clause.List) == 0 {
			defaultFound = true
		}
	}
	return defaultFound
}

func l8WorkerV2EvaluatedSwitchCaseExpressions(statement *ast.SwitchStmt, info *types.Info) []ast.Expr {
	if statement == nil || statement.Body == nil {
		return nil
	}
	tag := constant.MakeBool(true)
	if statement.Tag != nil {
		tag = info.Types[statement.Tag].Value
	}
	var evaluated []ast.Expr
	for _, rawClause := range statement.Body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expression := range clause.List {
			evaluated = append(evaluated, expression)
			candidate := info.Types[expression].Value
			if tag == nil || candidate == nil || constant.Compare(tag, token.EQL, candidate) {
				return evaluated
			}
		}
	}
	return evaluated
}

func l8WorkerV2ClauseStatementListStaticallyTerminal(statements []ast.Stmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis, returnIsTerminal bool) bool {
	for _, statement := range statements {
		if l8WorkerV2StatementMayExitEnclosingClause(statement) {
			return false
		}
		if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, returnIsTerminal) {
			return true
		}
	}
	return false
}

func l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(expressions []ast.Expr, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	for _, expression := range expressions {
		if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression, info, analysis) {
			return true
		}
	}
	return false
}

func l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression ast.Expr, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if expression == nil {
		return false
	}
	switch expression := expression.(type) {
	case *ast.ParenExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis)
	case *ast.CallExpr:
		if l8WorkerV2CallOperandsCannotReturn(expression, info, analysis) {
			return true
		}
		if l8WorkerV2CalledObject(expression.Fun, info) == types.Universe.Lookup("panic") {
			return true
		}
		return l8WorkerV2DirectSamePackageFunctionCannotReturn(expression, info, analysis)
	case *ast.BinaryExpr:
		if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis) {
			return true
		}
		if expression.Op == token.LAND || expression.Op == token.LOR {
			value := info.Types[expression.X].Value
			if value == nil || value.Kind() != constant.Bool {
				return false
			}
			left := constant.BoolVal(value)
			if (expression.Op == token.LAND && !left) || (expression.Op == token.LOR && left) {
				return false
			}
		}
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.Y, info, analysis)
	case *ast.UnaryExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis)
	case *ast.SelectorExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis)
	case *ast.IndexExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.Index, info, analysis)
	case *ast.IndexListExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(expression.Indices, info, analysis)
	case *ast.SliceExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.Low, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.High, info, analysis) ||
			l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.Max, info, analysis)
	case *ast.TypeAssertExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis)
	case *ast.StarExpr:
		return l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(expression.X, info, analysis)
	case *ast.CompositeLit:
		for _, element := range expression.Elts {
			switch element := element.(type) {
			case *ast.KeyValueExpr:
				if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(element.Key, info, analysis) ||
					l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(element.Value, info, analysis) {
					return true
				}
			case ast.Expr:
				if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(element, info, analysis) {
					return true
				}
			}
		}
	}
	return false
}

func l8WorkerV2CallOperandsCannotReturn(call *ast.CallExpr, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if call == nil {
		return false
	}
	if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(call.Fun, info, analysis) {
		return true
	}
	return l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(call.Args, info, analysis)
}

func l8WorkerV2DirectSamePackageFunctionCannotReturn(call *ast.CallExpr, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if call == nil || analysis == nil {
		return false
	}
	if literal, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.FuncLit); ok {
		return l8WorkerV2FunctionLiteralCannotReturn(literal, info, analysis)
	}
	called := l8WorkerV2CalledObject(call.Fun, info)
	if literal := l8WorkerV2ResolveImmutableFunctionLiteral(called, analysis); literal != nil {
		return l8WorkerV2FunctionLiteralCannotReturn(literal, info, analysis)
	}
	function, ok := called.(*types.Func)
	if !ok || function.Pkg() == nil || function.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" {
		return false
	}
	declaration := analysis.declarations[function]
	if declaration == nil || declaration.Body == nil {
		return false
	}
	if terminal, known := analysis.memo[function]; known {
		return terminal
	}
	if analysis.visiting[function] {
		return true
	}
	analysis.visiting[function] = true
	if l8WorkerV2FunctionHasConservativeReturnEscape(declaration, info, analysis) {
		delete(analysis.visiting, function)
		analysis.memo[function] = false
		return false
	}
	terminal := l8WorkerV2StatementListStaticallyTerminal(declaration.Body.List, info, analysis, false)
	delete(analysis.visiting, function)
	analysis.memo[function] = terminal
	return terminal
}

func l8WorkerV2ResolveImmutableFunctionLiteral(object types.Object, analysis *l8WorkerV2TerminalAnalysis) *ast.FuncLit {
	if object == nil || analysis == nil {
		return nil
	}
	visited := make(map[types.Object]bool)
	for object != nil && !visited[object] {
		visited[object] = true
		if analysis.mutableLocals[object] {
			return nil
		}
		if literal := analysis.localLiterals[object]; literal != nil {
			return literal
		}
		object = analysis.literalAliases[object]
	}
	return nil
}

func l8WorkerV2FunctionLiteralCannotReturn(literal *ast.FuncLit, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if literal == nil || literal.Body == nil {
		return false
	}
	if terminal, known := analysis.literalMemo[literal]; known {
		return terminal
	}
	if analysis.literalVisit[literal] {
		return true
	}
	analysis.literalVisit[literal] = true
	if l8WorkerV2StatementListHasReachableReturnEscape(literal.Body.List, info, analysis) {
		delete(analysis.literalVisit, literal)
		analysis.literalMemo[literal] = false
		return false
	}
	terminal := l8WorkerV2StatementListStaticallyTerminal(literal.Body.List, info, analysis, false)
	delete(analysis.literalVisit, literal)
	analysis.literalMemo[literal] = terminal
	return terminal
}

func l8WorkerV2FunctionHasConservativeReturnEscape(function *ast.FuncDecl, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if function == nil || function.Body == nil {
		return false
	}
	return l8WorkerV2StatementListHasReachableReturnEscape(function.Body.List, info, analysis)
}

func l8WorkerV2StatementListHasReachableReturnEscape(statements []ast.Stmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	recoveringDefer := false
	for _, statement := range statements {
		if deferred, ok := statement.(*ast.DeferStmt); ok {
			if l8WorkerV2CallOperandsCannotReturn(deferred.Call, info, analysis) {
				return false
			}
			recoveringDefer = recoveringDefer || l8WorkerV2DeferredCallMayRecover(deferred.Call, info, analysis)
			continue
		}
		if l8WorkerV2StatementHasReachableReturnEscape(statement, info, analysis) {
			return true
		}
		if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, false) {
			if recoveringDefer && l8WorkerV2StatementIsDirectRecoverablePanic(statement, info) {
				return true
			}
			return false
		}
	}
	return false
}

func l8WorkerV2StatementHasReachableReturnEscape(statement ast.Stmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	switch statement := statement.(type) {
	case nil, *ast.EmptyStmt, *ast.BranchStmt:
		return false
	case *ast.ReturnStmt:
		return !l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(statement.Results, info, analysis)
	case *ast.DeferStmt:
		return false
	case *ast.GoStmt:
		return false
	case *ast.LabeledStmt:
		return l8WorkerV2StatementHasReachableReturnEscape(statement.Stmt, info, analysis)
	case *ast.BlockStmt:
		return l8WorkerV2StatementListHasReachableReturnEscape(statement.List, info, analysis)
	case *ast.IfStmt:
		if statement.Init != nil {
			if l8WorkerV2StatementHasReachableReturnEscape(statement.Init, info, analysis) {
				return true
			}
			if l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, false) {
				return false
			}
		}
		if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Cond, info, analysis) {
			return false
		}
		value := info.Types[statement.Cond].Value
		if value != nil && value.Kind() == constant.Bool {
			if constant.BoolVal(value) {
				return l8WorkerV2StatementListHasReachableReturnEscape(statement.Body.List, info, analysis)
			}
			return statement.Else != nil && l8WorkerV2StatementHasReachableReturnEscape(statement.Else, info, analysis)
		}
		return l8WorkerV2StatementListHasReachableReturnEscape(statement.Body.List, info, analysis) ||
			(statement.Else != nil && l8WorkerV2StatementHasReachableReturnEscape(statement.Else, info, analysis))
	case *ast.ForStmt:
		if statement.Init != nil {
			if l8WorkerV2StatementHasReachableReturnEscape(statement.Init, info, analysis) {
				return true
			}
			if l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, false) {
				return false
			}
		}
		if statement.Cond != nil {
			if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Cond, info, analysis) {
				return false
			}
			value := info.Types[statement.Cond].Value
			if value != nil && value.Kind() == constant.Bool && !constant.BoolVal(value) {
				return false
			}
		}
		if l8WorkerV2StatementListHasReachableReturnEscape(statement.Body.List, info, analysis) {
			return true
		}
		if l8WorkerV2StaticallyUnconditionalTerminal(statement.Body, info, analysis, false) {
			return false
		}
		return statement.Post != nil && l8WorkerV2StatementHasReachableReturnEscape(statement.Post, info, analysis)
	case *ast.RangeStmt:
		return !l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.X, info, analysis) &&
			l8WorkerV2StatementListHasReachableReturnEscape(statement.Body.List, info, analysis)
	case *ast.SwitchStmt:
		if statement.Init != nil {
			if l8WorkerV2StatementHasReachableReturnEscape(statement.Init, info, analysis) {
				return true
			}
			if l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, false) {
				return false
			}
		}
		if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Tag, info, analysis) {
			return false
		}
		if l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(l8WorkerV2EvaluatedSwitchCaseExpressions(statement, info), info, analysis) {
			return false
		}
		for _, rawClause := range statement.Body.List {
			clause, ok := rawClause.(*ast.CaseClause)
			if !ok {
				continue
			}
			if l8WorkerV2StatementListHasReachableReturnEscape(clause.Body, info, analysis) {
				return true
			}
		}
		return false
	case *ast.TypeSwitchStmt:
		if statement.Init != nil {
			if l8WorkerV2StatementHasReachableReturnEscape(statement.Init, info, analysis) {
				return true
			}
			if l8WorkerV2StaticallyUnconditionalTerminal(statement.Init, info, analysis, false) {
				return false
			}
		}
		if statement.Assign != nil {
			if l8WorkerV2StatementHasReachableReturnEscape(statement.Assign, info, analysis) {
				return true
			}
			if l8WorkerV2StaticallyUnconditionalTerminal(statement.Assign, info, analysis, false) {
				return false
			}
		}
		for _, rawClause := range statement.Body.List {
			clause, ok := rawClause.(*ast.CaseClause)
			if ok && l8WorkerV2StatementListHasReachableReturnEscape(clause.Body, info, analysis) {
				return true
			}
		}
		return false
	case *ast.SelectStmt:
		for _, rawClause := range statement.Body.List {
			clause, ok := rawClause.(*ast.CommClause)
			if !ok {
				continue
			}
			if clause.Comm != nil && l8WorkerV2StatementHasReachableReturnEscape(clause.Comm, info, analysis) {
				return true
			}
			if clause.Comm != nil && l8WorkerV2StaticallyUnconditionalTerminal(clause.Comm, info, analysis, false) {
				return false
			}
		}
		for _, rawClause := range statement.Body.List {
			clause, ok := rawClause.(*ast.CommClause)
			if !ok {
				continue
			}
			if l8WorkerV2StatementListHasReachableReturnEscape(clause.Body, info, analysis) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func l8WorkerV2StatementIsDirectRecoverablePanic(statement ast.Stmt, info *types.Info) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := l8WorkerV2UnparenExpression(expression.X).(*ast.CallExpr)
	return ok && l8WorkerV2CalledObject(call.Fun, info) == types.Universe.Lookup("panic")
}

func l8WorkerV2NodeHasSynchronousRecover(node ast.Node, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if found {
			return false
		}
		switch candidate.(type) {
		case *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt:
			return false
		}
		call, ok := candidate.(*ast.CallExpr)
		found = ok && l8WorkerV2CalledObject(call.Fun, info) == types.Universe.Lookup("recover")
		return !found
	})
	return found
}

func l8WorkerV2DeferredCallMayRecover(call *ast.CallExpr, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	if call == nil || analysis == nil {
		return true
	}
	if l8WorkerV2CalledObject(call.Fun, info) == types.Universe.Lookup("recover") {
		return true
	}
	if literal, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.FuncLit); ok {
		return l8WorkerV2StatementListCanRecoverAndReturn(literal.Body.List, info, analysis)
	}
	called := l8WorkerV2CalledObject(call.Fun, info)
	if literal := l8WorkerV2ResolveImmutableFunctionLiteral(called, analysis); literal != nil {
		return l8WorkerV2StatementListCanRecoverAndReturn(literal.Body.List, info, analysis)
	}
	function, ok := called.(*types.Func)
	if !ok || function.Pkg() == nil || function.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" {
		return true
	}
	declaration := analysis.declarations[function]
	return declaration == nil || declaration.Body == nil || l8WorkerV2StatementListCanRecoverAndReturn(declaration.Body.List, info, analysis)
}

func l8WorkerV2StatementListCanRecoverAndReturn(statements []ast.Stmt, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) bool {
	flow := l8WorkerV2RecoveryFlowForStatementList(statements, l8WorkerV2RecoveryBefore, info, analysis)
	return flow.canReturnAfterRecovery || flow.continuing&l8WorkerV2RecoveryAfter != 0
}

const (
	l8WorkerV2RecoveryBefore uint8 = 1 << iota
	l8WorkerV2RecoveryAfter
)

type l8WorkerV2RecoveryFlow struct {
	canReturnAfterRecovery bool
	continuing             uint8
}

func l8WorkerV2RecoveryFlowForStatementList(statements []ast.Stmt, states uint8, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) l8WorkerV2RecoveryFlow {
	result := l8WorkerV2RecoveryFlow{continuing: states}
	for _, statement := range statements {
		if result.continuing == 0 {
			break
		}
		flow := l8WorkerV2RecoveryFlowForStatement(statement, result.continuing, info, analysis)
		result.canReturnAfterRecovery = result.canReturnAfterRecovery || flow.canReturnAfterRecovery
		result.continuing = flow.continuing
	}
	return result
}

func l8WorkerV2RecoveryFlowForStatement(statement ast.Stmt, states uint8, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) l8WorkerV2RecoveryFlow {
	if states == 0 || statement == nil {
		return l8WorkerV2RecoveryFlow{continuing: states}
	}
	switch statement := statement.(type) {
	case *ast.ReturnStmt:
		return l8WorkerV2RecoveryFlow{
			canReturnAfterRecovery: states&l8WorkerV2RecoveryAfter != 0 && !l8WorkerV2UnconditionallyEvaluatedExpressionsCannotReturn(statement.Results, info, analysis),
		}
	case *ast.BlockStmt:
		return l8WorkerV2RecoveryFlowForStatementList(statement.List, states, info, analysis)
	case *ast.LabeledStmt:
		return l8WorkerV2RecoveryFlowForStatement(statement.Stmt, states, info, analysis)
	case *ast.IfStmt:
		prefix := l8WorkerV2RecoveryFlow{continuing: states}
		if statement.Init != nil {
			prefix = l8WorkerV2RecoveryFlowForStatement(statement.Init, states, info, analysis)
			if prefix.continuing == 0 {
				return prefix
			}
		}
		branchStates := l8WorkerV2RecoveryStatesAfterExpression(prefix.continuing, statement.Cond, info)
		if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Cond, info, analysis) {
			return l8WorkerV2RecoveryFlow{canReturnAfterRecovery: prefix.canReturnAfterRecovery}
		}
		value := info.Types[statement.Cond].Value
		if value != nil && value.Kind() == constant.Bool {
			if constant.BoolVal(value) {
				body := l8WorkerV2RecoveryFlowForStatementList(statement.Body.List, branchStates, info, analysis)
				body.canReturnAfterRecovery = body.canReturnAfterRecovery || prefix.canReturnAfterRecovery
				return body
			}
			if statement.Else == nil {
				return l8WorkerV2RecoveryFlow{canReturnAfterRecovery: prefix.canReturnAfterRecovery, continuing: branchStates}
			}
			alternate := l8WorkerV2RecoveryFlowForStatement(statement.Else, branchStates, info, analysis)
			alternate.canReturnAfterRecovery = alternate.canReturnAfterRecovery || prefix.canReturnAfterRecovery
			return alternate
		}
		body := l8WorkerV2RecoveryFlowForStatementList(statement.Body.List, branchStates, info, analysis)
		alternate := l8WorkerV2RecoveryFlow{continuing: branchStates}
		if statement.Else != nil {
			alternate = l8WorkerV2RecoveryFlowForStatement(statement.Else, branchStates, info, analysis)
		}
		return l8WorkerV2RecoveryFlow{
			canReturnAfterRecovery: prefix.canReturnAfterRecovery || body.canReturnAfterRecovery || alternate.canReturnAfterRecovery,
			continuing:             body.continuing | alternate.continuing,
		}
	case *ast.SwitchStmt:
		return l8WorkerV2RecoveryFlowForSwitch(statement, states, info, analysis)
	case *ast.ForStmt, *ast.RangeStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, false) {
			return l8WorkerV2RecoveryFlow{}
		}
		return l8WorkerV2RecoveryFlow{continuing: states}
	}
	next := states
	if l8WorkerV2NodeHasSynchronousRecover(statement, info) {
		next = l8WorkerV2RecoveryAfter
	}
	if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, false) {
		next = 0
	}
	return l8WorkerV2RecoveryFlow{continuing: next}
}

func l8WorkerV2RecoveryFlowForSwitch(statement *ast.SwitchStmt, states uint8, info *types.Info, analysis *l8WorkerV2TerminalAnalysis) l8WorkerV2RecoveryFlow {
	prefix := l8WorkerV2RecoveryFlow{continuing: states}
	if statement.Init != nil {
		prefix = l8WorkerV2RecoveryFlowForStatement(statement.Init, states, info, analysis)
		if prefix.continuing == 0 {
			return prefix
		}
	}
	if l8WorkerV2UnconditionallyEvaluatedExpressionCannotReturn(statement.Tag, info, analysis) {
		return l8WorkerV2RecoveryFlow{canReturnAfterRecovery: prefix.canReturnAfterRecovery}
	}
	selected, exact := l8WorkerV2ExactSelectedSwitchClause(statement, info)
	if !exact {
		if l8WorkerV2StaticallyUnconditionalTerminal(statement, info, analysis, false) {
			return l8WorkerV2RecoveryFlow{canReturnAfterRecovery: prefix.canReturnAfterRecovery}
		}
		return prefix
	}
	if selected == nil {
		return prefix
	}
	result := l8WorkerV2RecoveryFlowForStatementList(selected.Body, prefix.continuing, info, analysis)
	result.canReturnAfterRecovery = result.canReturnAfterRecovery || prefix.canReturnAfterRecovery
	return result
}

func l8WorkerV2ExactSelectedSwitchClause(statement *ast.SwitchStmt, info *types.Info) (*ast.CaseClause, bool) {
	if statement == nil || statement.Body == nil {
		return nil, false
	}
	tag := constant.MakeBool(true)
	if statement.Tag != nil {
		tag = info.Types[statement.Tag].Value
	}
	if tag == nil {
		return nil, false
	}
	var defaultClause *ast.CaseClause
	for _, rawClause := range statement.Body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok {
			return nil, false
		}
		if len(clause.List) == 0 {
			defaultClause = clause
			continue
		}
		for _, expression := range clause.List {
			candidate := info.Types[expression].Value
			if candidate == nil {
				return nil, false
			}
			if constant.Compare(tag, token.EQL, candidate) {
				return clause, true
			}
		}
	}
	return defaultClause, true
}

func l8WorkerV2RecoveryStatesAfterExpression(states uint8, expression ast.Expr, info *types.Info) uint8 {
	if expression != nil && l8WorkerV2NodeHasSynchronousRecover(expression, info) {
		return l8WorkerV2RecoveryAfter
	}
	return states
}

func l8WorkerV2StatementMayExitEnclosingClause(statement ast.Stmt) bool {
	found := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if l8WorkerV2OwnsUnlabeledBreak(node) {
			// An unlabeled break belongs to this nested loop/switch/select, while
			// a label may name an enclosing clause owner and is therefore treated
			// conservatively as a possible exit from the clause being analyzed.
			ast.Inspect(node, func(nested ast.Node) bool {
				branch, ok := nested.(*ast.BranchStmt)
				if ok && branch.Label != nil && (branch.Tok == token.BREAK || branch.Tok == token.FALLTHROUGH) {
					found = true
					return false
				}
				return !found
			})
			return false
		}
		branch, ok := node.(*ast.BranchStmt)
		if ok && (branch.Tok == token.BREAK || branch.Tok == token.FALLTHROUGH) {
			found = true
			return false
		}
		return true
	})
	return found
}

func l8WorkerV2OwnsUnlabeledBreak(node ast.Node) bool {
	switch node.(type) {
	case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		return true
	default:
		return false
	}
}

func l8WorkerV2ExactCallContextErrorBranch(function *ast.FuncDecl, call *ast.CallExpr, ctx types.Object, acquireCall *ast.CallExpr, message string, info *types.Info) bool {
	conditional := l8WorkerV2TopLevelIfContainingCall(function, call)
	if conditional == nil {
		return false
	}
	errObject := l8WorkerV2IfInitializerErrorObject(conditional, call, info)
	return errObject != nil && l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, errObject, info) &&
		l8WorkerV2ExactClientNilContextNormalization(function, ctx, acquireCall, info) &&
		l8WorkerV2ExactContextThenConstantResponseError(conditional.Body, ctx, message, info)
}

func l8WorkerV2ExactCallConstantStateErrorBranch(function *ast.FuncDecl, call *ast.CallExpr, message string, info *types.Info) bool {
	conditional := l8WorkerV2TopLevelIfContainingCall(function, call)
	if conditional == nil || conditional.Else != nil || len(conditional.Body.List) != 1 {
		return false
	}
	errObject := l8WorkerV2IfInitializerErrorObject(conditional, call, info)
	return errObject != nil && l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, errObject, info) &&
		l8WorkerV2IsZeroStructAndConstantErrorReturn(conditional.Body.List[0], "storedJobStateV2", message, info)
}

func l8WorkerV2TopLevelIfContainingCall(function *ast.FuncDecl, target *ast.CallExpr) *ast.IfStmt {
	if function == nil || function.Body == nil || target == nil {
		return nil
	}
	for _, statement := range function.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok {
			continue
		}
		found := false
		if conditional.Init == nil {
			continue
		}
		ast.Inspect(conditional.Init, func(node ast.Node) bool {
			if node == target {
				found = true
				return false
			}
			return true
		})
		if found {
			return conditional
		}
	}
	return nil
}

func l8WorkerV2IfInitializerCalls(conditional *ast.IfStmt, target *ast.CallExpr, info *types.Info) bool {
	return l8WorkerV2IfInitializerErrorObject(conditional, target, info) != nil
}

func l8WorkerV2IfInitializerErrorObject(conditional *ast.IfStmt, target *ast.CallExpr, info *types.Info) types.Object {
	if conditional == nil || conditional.Init == nil || target == nil {
		return nil
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return nil
	}
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok || call != target {
		return nil
	}
	return l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
}

func l8WorkerV2IsNilExpression(expression ast.Expr, info *types.Info) bool {
	return l8WorkerV2ExpressionObject(expression, info) == types.Universe.Lookup("nil")
}

func l8WorkerV2DirectAddressedObject(expression ast.Expr, info *types.Info) types.Object {
	unary, ok := l8WorkerV2UnparenExpression(expression).(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return nil
	}
	return l8WorkerV2ExpressionObject(unary.X, info)
}

func l8WorkerV2ObjectHasPointerType(object types.Object) bool {
	if object == nil || object.Type() == nil {
		return false
	}
	_, ok := object.Type().Underlying().(*types.Pointer)
	return ok
}

func l8WorkerV2ResolveImmutablePointerTarget(object types.Object, aliases map[types.Object]types.Object, mutable map[types.Object]bool) types.Object {
	visited := make(map[types.Object]bool)
	traversed := false
	for object != nil && !visited[object] {
		if mutable[object] {
			return nil
		}
		visited[object] = true
		target, ok := aliases[object]
		if !ok {
			if traversed {
				return object
			}
			return nil
		}
		object = target
		traversed = true
	}
	return nil
}

func l8WorkerV2ValidateDecoderCallerComposition(files []*l8WorkerV2ParsedFile, info *types.Info) error {
	declared := make(map[string]bool)
	pointerAliases := make(map[types.Object]types.Object)
	mutablePointers := make(map[types.Object]bool)
	terminalAnalysis := &l8WorkerV2TerminalAnalysis{
		declarations:   make(map[*types.Func]*ast.FuncDecl),
		memo:           make(map[*types.Func]bool),
		visiting:       make(map[*types.Func]bool),
		localLiterals:  make(map[types.Object]*ast.FuncLit),
		literalAliases: make(map[types.Object]types.Object),
		mutableLocals:  make(map[types.Object]bool),
		literalMemo:    make(map[*ast.FuncLit]bool),
		literalVisit:   make(map[*ast.FuncLit]bool),
	}
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if object, ok := info.Defs[function.Name].(*types.Func); ok {
				terminalAnalysis.declarations[object] = function
			}
			if function.Recv != nil {
				continue
			}
			switch function.Name.Name {
			case "decodeWorkerRequestInto", "decodeWorkerResponseInto", "decodeStoredJobStateV2Into":
				declared[function.Name.Name] = true
			}
		}
		ast.Inspect(file.parsed, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for index, left := range node.Lhs {
					if _, indirect := l8WorkerV2UnparenExpression(left).(*ast.StarExpr); indirect {
						continue
					}
					object := l8WorkerV2ExpressionObject(left, info)
					if object == nil {
						continue
					}
					identifier, isIdentifier := l8WorkerV2UnparenExpression(left).(*ast.Ident)
					newDefinition := node.Tok == token.DEFINE && isIdentifier && info.Defs[identifier] == object
					if newDefinition && index < len(node.Rhs) {
						if addressed := l8WorkerV2DirectAddressedObject(node.Rhs[index], info); addressed != nil && l8WorkerV2ObjectHasPointerType(object) {
							pointerAliases[object] = addressed
						} else if alias := l8WorkerV2ExpressionObject(node.Rhs[index], info); alias != nil && l8WorkerV2ObjectHasPointerType(object) && l8WorkerV2ObjectHasPointerType(alias) {
							pointerAliases[object] = alias
						} else if literal, ok := l8WorkerV2UnparenExpression(node.Rhs[index]).(*ast.FuncLit); ok {
							terminalAnalysis.localLiterals[object] = literal
						} else if alias := l8WorkerV2ExpressionObject(node.Rhs[index], info); alias != nil {
							terminalAnalysis.literalAliases[object] = alias
						}
					}
					if newDefinition {
						continue
					}
					if l8WorkerV2ObjectHasPointerType(object) {
						mutablePointers[object] = true
					} else {
						terminalAnalysis.mutableLocals[object] = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range node.Names {
					if index >= len(node.Values) {
						continue
					}
					object := info.Defs[name]
					if object == nil {
						continue
					}
					if addressed := l8WorkerV2DirectAddressedObject(node.Values[index], info); addressed != nil && l8WorkerV2ObjectHasPointerType(object) {
						pointerAliases[object] = addressed
					} else if alias := l8WorkerV2ExpressionObject(node.Values[index], info); alias != nil && l8WorkerV2ObjectHasPointerType(object) && l8WorkerV2ObjectHasPointerType(alias) {
						pointerAliases[object] = alias
					} else if literal, ok := l8WorkerV2UnparenExpression(node.Values[index]).(*ast.FuncLit); ok {
						terminalAnalysis.localLiterals[object] = literal
					} else if alias := l8WorkerV2ExpressionObject(node.Values[index], info); alias != nil {
						terminalAnalysis.literalAliases[object] = alias
					}
				}
			}
			return true
		})
	}
	for _, file := range files {
		ast.Inspect(file.parsed, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, left := range assignment.Lhs {
				star, ok := l8WorkerV2UnparenExpression(left).(*ast.StarExpr)
				if !ok {
					continue
				}
				target := l8WorkerV2DirectAddressedObject(star.X, info)
				if target == nil {
					pointer := l8WorkerV2ExpressionObject(star.X, info)
					target = l8WorkerV2ResolveImmutablePointerTarget(pointer, pointerAliases, mutablePointers)
				}
				if target != nil {
					terminalAnalysis.mutableLocals[target] = true
				}
			}
			return true
		})
	}
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			expected := l8WorkerV2DecoderBoundaryInnerName(file.path, function, info)
			if expected == "" || !declared[expected] {
				continue
			}
			if l8WorkerV2FunctionHasGoto(function) {
				return fmt.Errorf("worker-v2 production path in %s declaration %s violates exact decoder caller composition", file.path, function.Name.Name)
			}
			scope := l8WorkerV2GuardScope{file: file, node: function, terminalAnalysis: terminalAnalysis}
			exactCalls := 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				object := l8WorkerV2CalledObject(call.Fun, info)
				if object != nil && object.Pkg() != nil && object.Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" && object.Name() == expected && l8WorkerV2AllowedExactDecoderCallerCall(scope, call, info) {
					exactCalls++
				}
				return true
			})
			if exactCalls != 1 {
				return fmt.Errorf("worker-v2 production path in %s declaration %s violates exact decoder caller composition", file.path, function.Name.Name)
			}
		}
	}
	return nil
}

func l8WorkerV2FunctionHasGoto(function *ast.FuncDecl) bool {
	found := false
	if function == nil || function.Body == nil {
		return false
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		branch, ok := node.(*ast.BranchStmt)
		found = ok && branch.Tok == token.GOTO
		return !found
	})
	return found
}

func l8WorkerV2DecoderBoundaryInnerName(path string, function *ast.FuncDecl, info *types.Info) string {
	switch filepath.Base(path) {
	case "server.go":
		if function.Name.Name == "readRequest" && l8WorkerV2ReceiverNamed(function, "Server", info) {
			return "decodeWorkerRequestInto"
		}
	case "client.go":
		if function.Name.Name == "RoundTrip" && l8WorkerV2ReceiverNamed(function, "unixSocketClientTransport", info) {
			return "decodeWorkerResponseInto"
		}
	case "job_store_v2.go":
		if function.Name.Name == "load" && l8WorkerV2ReceiverNamed(function, "jobStoreV2", info) {
			return "decodeStoredJobStateV2Into"
		}
	case "protocol_decode.go":
		if function.Name.Name == "decodeWorkerResponse" && function.Recv == nil {
			return "decodeWorkerResponseInto"
		}
	}
	return ""
}

func l8WorkerV2ReceiverNamed(function *ast.FuncDecl, name string, info *types.Info) bool {
	if function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return false
	}
	receiver := info.Defs[function.Recv.List[0].Names[0]]
	if receiver == nil {
		return false
	}
	typ := types.Unalias(receiver.Type())
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(pointer.Elem())
	}
	named, ok := typ.(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" && named.Obj().Name() == name
}

func l8WorkerV2AllowedBoundedStrictDecoderCall(scope l8WorkerV2GuardScope, candidate *ast.CallExpr, info *types.Info) bool {
	if filepath.Base(scope.file.path) != "protocol_decode.go" || candidate == nil {
		return false
	}
	if bounded, ok := l8WorkerV2ExactBoundedJSONReader(scope, info); ok {
		return candidate == bounded.readAll || candidate == bounded.readFull
	}
	shape, ok := l8WorkerV2ExactBoundedRawStrictDecoder(scope, info)
	return ok && (candidate == shape.newReader || candidate == shape.newDecoder || candidate == shape.primaryDecode || candidate == shape.trailingDecode)
}

type l8WorkerV2BoundedRawStrictDecoder struct {
	boundedRead    *ast.CallExpr
	newReader      *ast.CallExpr
	newDecoder     *ast.CallExpr
	primaryDecode  *ast.CallExpr
	trailingDecode *ast.CallExpr
}

type l8WorkerV2BoundedJSONReader struct {
	readAll  *ast.CallExpr
	readFull *ast.CallExpr
}

func l8WorkerV2ExactBoundedJSONReader(scope l8WorkerV2GuardScope, info *types.Info) (l8WorkerV2BoundedJSONReader, bool) {
	var zero l8WorkerV2BoundedJSONReader
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || filepath.Base(scope.file.path) != "protocol_decode.go" || function.Name.Name != "readWorkerJSONBoundedV2" || function.Recv != nil || function.Body == nil || len(function.Body.List) != 6 {
		return zero, false
	}
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if len(parameters) != 2 || !l8WorkerV2IsExactIOReader(parameters[0].Type()) || !types.Identical(parameters[1].Type(), types.Universe.Lookup("int64").Type()) || !l8WorkerV2ExactBytesErrorResults(function, info) {
		return zero, false
	}
	reader, limit := parameters[0], parameters[1]
	if !l8WorkerV2ExactPositiveLimitValidation(function.Body.List[0], limit, info) {
		return zero, false
	}
	limitedAssignment, ok := function.Body.List[1].(*ast.AssignStmt)
	if !ok || limitedAssignment.Tok != token.DEFINE || len(limitedAssignment.Lhs) != 1 || len(limitedAssignment.Rhs) != 1 {
		return zero, false
	}
	limited := l8WorkerV2ExpressionObject(limitedAssignment.Lhs[0], info)
	limitedPointer, ok := l8WorkerV2UnparenExpression(limitedAssignment.Rhs[0]).(*ast.UnaryExpr)
	if limited == nil || !ok || limitedPointer.Op != token.AND || !l8WorkerV2ExactLimitedReaderLiteral(limitedPointer.X, reader, limit, info) {
		return zero, false
	}
	readAssignment, ok := function.Body.List[2].(*ast.AssignStmt)
	if !ok || readAssignment.Tok != token.DEFINE || len(readAssignment.Lhs) != 2 || len(readAssignment.Rhs) != 1 {
		return zero, false
	}
	raw := l8WorkerV2ExpressionObject(readAssignment.Lhs[0], info)
	readErr := l8WorkerV2ExpressionObject(readAssignment.Lhs[1], info)
	readAll, ok := l8WorkerV2UnparenExpression(readAssignment.Rhs[0]).(*ast.CallExpr)
	if raw == nil || readErr == nil || !ok || !l8WorkerV2IsPackageCall(readAll, "io", "ReadAll", 1, info) || l8WorkerV2ExpressionObject(readAll.Args[0], info) != limited || !l8WorkerV2ExactNilErrorReturnIf(function.Body.List[3], readErr, info) {
		return zero, false
	}
	readFull, ok := l8WorkerV2ExactLimitProbe(function.Body.List[4], reader, limited, raw, info)
	if !ok || !l8WorkerV2IsBareTwoValueReturn(function.Body.List[5], raw, nil, info) {
		return zero, false
	}
	return l8WorkerV2BoundedJSONReader{readAll: readAll, readFull: readFull}, true
}

func l8WorkerV2ExactBoundedRawStrictDecoder(scope l8WorkerV2GuardScope, info *types.Info) (l8WorkerV2BoundedRawStrictDecoder, bool) {
	var zero l8WorkerV2BoundedRawStrictDecoder
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || function.Body == nil || len(function.Body.List) != 9 {
		return zero, false
	}
	reader, limit, output, ok := l8WorkerV2ExactRawDecoderParameters(function, info)
	if !ok {
		return zero, false
	}
	readAssignment, ok := function.Body.List[0].(*ast.AssignStmt)
	if !ok || readAssignment.Tok != token.DEFINE || len(readAssignment.Lhs) != 2 || len(readAssignment.Rhs) != 1 {
		return zero, false
	}
	raw := l8WorkerV2ExpressionObject(readAssignment.Lhs[0], info)
	readErr := l8WorkerV2ExpressionObject(readAssignment.Lhs[1], info)
	boundedRead, ok := l8WorkerV2UnparenExpression(readAssignment.Rhs[0]).(*ast.CallExpr)
	if raw == nil || readErr == nil || !ok || !l8WorkerV2IsExactBoundedJSONReadCall(boundedRead, reader, limit, info) {
		return zero, false
	}
	if !l8WorkerV2ExactErrorReturnIf(function.Body.List[1], readErr, info) || !l8WorkerV2ExactPreflightIf(scope, function.Body.List[2], raw, info) {
		return zero, false
	}
	decoderAssignment, ok := function.Body.List[3].(*ast.AssignStmt)
	if !ok || decoderAssignment.Tok != token.DEFINE || len(decoderAssignment.Lhs) != 1 || len(decoderAssignment.Rhs) != 1 {
		return zero, false
	}
	decoder := l8WorkerV2ExpressionObject(decoderAssignment.Lhs[0], info)
	newDecoder, ok := l8WorkerV2UnparenExpression(decoderAssignment.Rhs[0]).(*ast.CallExpr)
	if decoder == nil || !ok || !l8WorkerV2IsPackageCall(newDecoder, "encoding/json", "NewDecoder", 1, info) {
		return zero, false
	}
	newReader, ok := l8WorkerV2UnparenExpression(newDecoder.Args[0]).(*ast.CallExpr)
	if !ok || !l8WorkerV2IsPackageCall(newReader, "bytes", "NewReader", 1, info) || l8WorkerV2ExpressionObject(newReader.Args[0], info) != raw {
		return zero, false
	}
	strictStatement, ok := function.Body.List[4].(*ast.ExprStmt)
	if !ok {
		return zero, false
	}
	strictCall, ok := l8WorkerV2DecoderMethodCall(strictStatement.X, decoder, "DisallowUnknownFields", info)
	if !ok || len(strictCall.Args) != 0 || !l8WorkerV2ExactPrimaryDecodeIf(function.Body.List[5], decoder, output, info) {
		return zero, false
	}
	trailing, ok := l8WorkerV2ExactTrailingDeclaration(function.Body.List[6], info)
	if !ok || !l8WorkerV2ExactTrailingDecodeIf(function.Body.List[7], decoder, trailing, info) || !l8WorkerV2IsBareReturn(function.Body.List[8], nil, info) {
		return zero, false
	}
	_, _, primaryDecode, primaryOK := l8WorkerV2ExactDecodeIf(function.Body.List[5], decoder, info)
	_, _, trailingDecode, trailingOK := l8WorkerV2ExactDecodeIf(function.Body.List[7], decoder, info)
	if !primaryOK || !trailingOK {
		return zero, false
	}
	return l8WorkerV2BoundedRawStrictDecoder{
		boundedRead: boundedRead, newReader: newReader, newDecoder: newDecoder,
		primaryDecode: primaryDecode, trailingDecode: trailingDecode,
	}, true
}

func l8WorkerV2ExactRawDecoderParameters(function *ast.FuncDecl, info *types.Info) (types.Object, types.Object, types.Object, bool) {
	if function == nil || function.Recv != nil || function.Type.TypeParams != nil || function.Type.Params == nil || function.Type.Results == nil || len(function.Type.Results.List) != 1 {
		return nil, nil, nil, false
	}
	var parameters []types.Object
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			parameters = append(parameters, info.Defs[name])
		}
	}
	if len(parameters) != 3 || parameters[0] == nil || parameters[1] == nil || parameters[2] == nil || !l8WorkerV2IsExactIOReader(parameters[0].Type()) {
		return nil, nil, nil, false
	}
	int64Type := types.Universe.Lookup("int64").Type()
	if parameters[1].Type() != int64Type || info.TypeOf(function.Type.Results.List[0].Type) != types.Universe.Lookup("error").Type() {
		return nil, nil, nil, false
	}
	expectedOutput := map[string]string{
		"decodeWorkerRequestInto":    "Request",
		"decodeWorkerResponseInto":   "Response",
		"decodeStoredJobStateV2Into": "storedJobStateV2",
	}[function.Name.Name]
	if expectedOutput == "" || !l8WorkerV2IsExactNamedStructPointer(parameters[2].Type(), expectedOutput) || l8WorkerV2TypeMayInvokeJSONDecodeCallback(parameters[2].Type(), make(map[types.Type]bool)) {
		return nil, nil, nil, false
	}
	return parameters[0], parameters[1], parameters[2], true
}

func l8WorkerV2IsExactNamedStructPointer(typ types.Type, name string) bool {
	pointer, ok := types.Unalias(typ).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(pointer.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || named.Obj().Name() != name {
		return false
	}
	_, ok = named.Underlying().(*types.Struct)
	return ok
}

func l8WorkerV2FunctionParameterObjects(function *ast.FuncDecl, info *types.Info) []types.Object {
	if function == nil || function.Type.Params == nil {
		return nil
	}
	var parameters []types.Object
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			parameters = append(parameters, info.Defs[name])
		}
	}
	return parameters
}

func l8WorkerV2ExactBytesErrorResults(function *ast.FuncDecl, info *types.Info) bool {
	if function.Type.Results == nil || len(function.Type.Results.List) != 2 {
		return false
	}
	bytesType, ok := types.Unalias(info.TypeOf(function.Type.Results.List[0].Type)).(*types.Slice)
	return ok && types.Identical(bytesType.Elem(), types.Universe.Lookup("byte").Type()) && types.Identical(info.TypeOf(function.Type.Results.List[1].Type), types.Universe.Lookup("error").Type())
}

func l8WorkerV2ExactPositiveLimitValidation(statement ast.Stmt, limit types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	return ok && conditional.Init == nil && conditional.Else == nil && len(conditional.Body.List) == 1 &&
		l8WorkerV2ExactObjectIntegerComparison(conditional.Cond, limit, token.LEQ, 0, info) && l8WorkerV2IsNilAndConstantErrorReturn(conditional.Body.List[0], info)
}

func l8WorkerV2ExactLimitedReaderLiteral(expression ast.Expr, reader, limit types.Object, info *types.Info) bool {
	literal, ok := l8WorkerV2UnparenExpression(expression).(*ast.CompositeLit)
	if !ok || len(literal.Elts) != 2 {
		return false
	}
	named, ok := types.Unalias(info.TypeOf(literal)).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "io" || named.Obj().Name() != "LimitedReader" {
		return false
	}
	return l8WorkerV2ExactKeyedObjectElement(literal.Elts[0], "R", reader, info) && l8WorkerV2ExactKeyedObjectElement(literal.Elts[1], "N", limit, info)
}

func l8WorkerV2ExactKeyedObjectElement(expression ast.Expr, key string, value types.Object, info *types.Info) bool {
	pair, ok := expression.(*ast.KeyValueExpr)
	if !ok || l8WorkerV2ExpressionObject(pair.Value, info) != value {
		return false
	}
	identifier, ok := l8WorkerV2UnparenExpression(pair.Key).(*ast.Ident)
	return ok && identifier.Name == key
}

func l8WorkerV2ExactLimitProbe(statement ast.Stmt, reader, limited, raw types.Object, info *types.Info) (*ast.CallExpr, bool) {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 6 || !l8WorkerV2ExactSelectorIntegerComparison(conditional.Cond, limited, "N", token.EQL, 0, info) {
		return nil, false
	}
	declaration, ok := conditional.Body.List[0].(*ast.DeclStmt)
	if !ok {
		return nil, false
	}
	generated, ok := declaration.Decl.(*ast.GenDecl)
	if !ok || generated.Tok != token.VAR || len(generated.Specs) != 1 {
		return nil, false
	}
	spec, ok := generated.Specs[0].(*ast.ValueSpec)
	if !ok || len(spec.Names) != 1 || len(spec.Values) != 0 {
		return nil, false
	}
	probe := info.Defs[spec.Names[0]]
	if probe == nil {
		return nil, false
	}
	array, ok := types.Unalias(probe.Type()).(*types.Array)
	if !ok || array.Len() != 1 || !types.Identical(array.Elem(), types.Universe.Lookup("byte").Type()) {
		return nil, false
	}
	assignment, ok := conditional.Body.List[1].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return nil, false
	}
	n, probeErr := l8WorkerV2ExpressionObject(assignment.Lhs[0], info), l8WorkerV2ExpressionObject(assignment.Lhs[1], info)
	readFull, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if n == nil || probeErr == nil || !ok || !l8WorkerV2IsPackageCall(readFull, "io", "ReadFull", 2, info) || l8WorkerV2ExpressionObject(readFull.Args[0], info) != reader || !l8WorkerV2ExactWholeSliceOf(readFull.Args[1], probe, info) {
		return nil, false
	}
	if !l8WorkerV2ExactIntegerErrorIf(conditional.Body.List[2], n, token.GTR, 0, info) || !l8WorkerV2ExactProbeEOFIf(conditional.Body.List[3], n, probeErr, raw, info) || !l8WorkerV2ExactProbeErrorIf(conditional.Body.List[4], probeErr, info) || !l8WorkerV2IsNilAndConstantErrorReturn(conditional.Body.List[5], info) {
		return nil, false
	}
	return readFull, true
}

func l8WorkerV2ExactSelectorIntegerComparison(expression ast.Expr, root types.Object, field string, operation token.Token, value int64, info *types.Info) bool {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || !l8WorkerV2ExactSelectorRoot(comparison.X, root, field, info) {
		return false
	}
	constantValue := info.Types[comparison.Y].Value
	if constantValue == nil {
		return false
	}
	got, exact := constant.Int64Val(constantValue)
	return exact && got == value
}

func l8WorkerV2ExactSelectorRoot(expression ast.Expr, root types.Object, field string, info *types.Info) bool {
	selector, ok := l8WorkerV2UnparenExpression(expression).(*ast.SelectorExpr)
	return ok && selector.Sel.Name == field && l8WorkerV2ExpressionObject(selector.X, info) == root
}

func l8WorkerV2ExactWholeSliceOf(expression ast.Expr, object types.Object, info *types.Info) bool {
	slice, ok := l8WorkerV2UnparenExpression(expression).(*ast.SliceExpr)
	return ok && slice.Low == nil && slice.High == nil && slice.Max == nil && l8WorkerV2ExpressionObject(slice.X, info) == object
}

func l8WorkerV2ExactIntegerErrorIf(statement ast.Stmt, object types.Object, operation token.Token, value int64, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	return ok && conditional.Init == nil && conditional.Else == nil && len(conditional.Body.List) == 1 &&
		l8WorkerV2ExactObjectIntegerComparison(conditional.Cond, object, operation, value, info) && l8WorkerV2IsNilAndConstantErrorReturn(conditional.Body.List[0], info)
}

func l8WorkerV2ExactProbeEOFIf(statement ast.Stmt, n, probeErr, raw types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 1 || !l8WorkerV2IsBareTwoValueReturn(conditional.Body.List[0], raw, nil, info) {
		return false
	}
	and, ok := l8WorkerV2UnparenExpression(conditional.Cond).(*ast.BinaryExpr)
	return ok && and.Op == token.LAND && l8WorkerV2ExactObjectIntegerComparison(and.X, n, token.EQL, 0, info) && l8WorkerV2ExactObjectComparison(and.Y, probeErr, token.EQL, "io", "EOF", info)
}

func l8WorkerV2ExactProbeErrorIf(statement ast.Stmt, probeErr types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	return ok && conditional.Init == nil && conditional.Else == nil && len(conditional.Body.List) == 1 && l8WorkerV2IsErrorComparison(conditional.Cond, probeErr, nil, info) && l8WorkerV2IsNilAndObjectReturn(conditional.Body.List[0], probeErr, info)
}

func l8WorkerV2ExactObjectComparison(expression ast.Expr, left types.Object, operation token.Token, packagePath, name string, info *types.Info) bool {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || l8WorkerV2ExpressionObject(comparison.X, info) != left {
		return false
	}
	right := l8WorkerV2ExpressionObject(comparison.Y, info)
	return right != nil && right.Pkg() != nil && right.Pkg().Path() == packagePath && right.Name() == name
}

func l8WorkerV2IsBareTwoValueReturn(statement ast.Stmt, first, second types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && l8WorkerV2ExpressionMatchesObject(returned.Results[0], first, info) && l8WorkerV2ExpressionMatchesObject(returned.Results[1], second, info)
}

func l8WorkerV2ExpressionMatchesObject(expression ast.Expr, expected types.Object, info *types.Info) bool {
	object := l8WorkerV2ExpressionObject(expression, info)
	if expected == nil {
		return object == types.Universe.Lookup("nil")
	}
	return object == expected
}

func l8WorkerV2IsNilAndObjectReturn(statement ast.Stmt, object types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && l8WorkerV2ExpressionObject(returned.Results[0], info) == types.Universe.Lookup("nil") && l8WorkerV2ExpressionObject(returned.Results[1], info) == object
}

func l8WorkerV2IsNilAndConstantErrorReturn(statement ast.Stmt, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 || l8WorkerV2ExpressionObject(returned.Results[0], info) != types.Universe.Lookup("nil") {
		return false
	}
	call, ok := l8WorkerV2UnparenExpression(returned.Results[1]).(*ast.CallExpr)
	return ok && l8WorkerV2IsConstantErrorsNewCall(call, info)
}

func l8WorkerV2IsConstantErrorsNewCall(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || len(call.Args) != 1 {
		return false
	}
	object := l8WorkerV2CalledObject(call.Fun, info)
	value := info.Types[call.Args[0]].Value
	return object != nil && object.Pkg() != nil && object.Pkg().Path() == "errors" && object.Name() == "New" && value != nil && value.Kind() == constant.String
}

func l8WorkerV2IsExactBoundedJSONReadCall(call *ast.CallExpr, reader, limit types.Object, info *types.Info) bool {
	if call == nil || len(call.Args) != 2 || l8WorkerV2ExpressionObject(call.Args[0], info) != reader || l8WorkerV2ExpressionObject(call.Args[1], info) != limit {
		return false
	}
	function, ok := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
	if !ok || !l8WorkerV2IsExactPackageFunctionObject(function, "readWorkerJSONBoundedV2") {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.TypeParams() != nil || signature.Params().Len() != 2 || signature.Results().Len() != 2 ||
		!l8WorkerV2IsExactIOReader(signature.Params().At(0).Type()) ||
		!types.Identical(signature.Params().At(1).Type(), types.Universe.Lookup("int64").Type()) ||
		!types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("error").Type()) {
		return false
	}
	bytesType, ok := types.Unalias(signature.Results().At(0).Type()).(*types.Slice)
	return ok && types.Identical(bytesType.Elem(), types.Universe.Lookup("byte").Type())
}

func l8WorkerV2ExactObjectIntegerComparison(expression ast.Expr, object types.Object, operation token.Token, value int64, info *types.Info) bool {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != operation || l8WorkerV2ExpressionObject(comparison.X, info) != object {
		return false
	}
	constantValue := info.Types[comparison.Y].Value
	if constantValue == nil {
		return false
	}
	got, exact := constant.Int64Val(constantValue)
	return exact && got == value
}

func l8WorkerV2ExactErrorReturnIf(statement ast.Stmt, errObject types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	return ok && conditional.Init == nil && conditional.Else == nil && len(conditional.Body.List) == 1 &&
		l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) && l8WorkerV2IsBareReturn(conditional.Body.List[0], errObject, info)
}

func l8WorkerV2ExactNilErrorReturnIf(statement ast.Stmt, errObject types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	return ok && conditional.Init == nil && conditional.Else == nil && len(conditional.Body.List) == 1 &&
		l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) && l8WorkerV2IsNilAndObjectReturn(conditional.Body.List[0], errObject, info)
}

func l8WorkerV2ExactPreflightIf(scope l8WorkerV2GuardScope, statement ast.Stmt, raw types.Object, info *types.Info) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init == nil || conditional.Else != nil || len(conditional.Body.List) != 1 {
		return false
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	errObject := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if errObject == nil || !ok || len(call.Args) != 1 || !l8WorkerV2IsExactStringConversionOf(call.Args[0], raw, info) || !l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) || !l8WorkerV2IsBareReturn(conditional.Body.List[0], errObject, info) {
		return false
	}
	called, ok := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
	if !ok || called.Pkg() == nil || called.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || called.Name() != "validateWorkerJSONPreflightV2" {
		return false
	}
	signature, ok := called.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.TypeParams() != nil || signature.Params().Len() != 1 || signature.Results().Len() != 1 || signature.Variadic() {
		return false
	}
	if signature.Params().At(0).Type() != types.Universe.Lookup("string").Type() || signature.Results().At(0).Type() != types.Universe.Lookup("error").Type() {
		return false
	}
	for _, declaration := range scope.file.parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && info.Defs[function.Name] == called {
			return function.Recv == nil && function.Name.Name == "validateWorkerJSONPreflightV2"
		}
	}
	return false
}

func l8WorkerV2IsExactStringConversionOf(expression ast.Expr, object types.Object, info *types.Info) bool {
	conversion, ok := l8WorkerV2UnparenExpression(expression).(*ast.CallExpr)
	if !ok || len(conversion.Args) != 1 || l8WorkerV2ExpressionObject(conversion.Args[0], info) != object {
		return false
	}
	name, ok := l8WorkerV2UnparenExpression(conversion.Fun).(*ast.Ident)
	return ok && info.Uses[name] == types.Universe.Lookup("string")
}

func l8WorkerV2IsPackageCall(call *ast.CallExpr, packagePath, name string, argumentCount int, info *types.Info) bool {
	if call == nil || len(call.Args) != argumentCount {
		return false
	}
	object := l8WorkerV2CalledObject(call.Fun, info)
	return object != nil && object.Pkg() != nil && object.Pkg().Path() == packagePath && object.Name() == name
}

func l8WorkerV2IsExactIOReader(typ types.Type) bool {
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "io" && named.Obj().Name() == "Reader"
}

func l8WorkerV2DecoderMethodCall(expression ast.Expr, decoder types.Object, methodName string, info *types.Info) (*ast.CallExpr, bool) {
	call, ok := l8WorkerV2UnparenExpression(expression).(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	selector, ok := l8WorkerV2UnparenExpression(call.Fun).(*ast.SelectorExpr)
	if !ok || l8WorkerV2ExpressionObject(selector.X, info) != decoder {
		return nil, false
	}
	selection := info.Selections[selector]
	if selection == nil || selection.Obj() == nil || selection.Obj().Pkg() == nil || selection.Obj().Pkg().Path() != "encoding/json" || selection.Obj().Name() != methodName {
		return nil, false
	}
	return call, true
}

func l8WorkerV2TypeMayInvokeJSONDecodeCallback(typ types.Type, seen map[types.Type]bool) bool {
	if typ == nil {
		return false
	}
	resolved := types.Unalias(typ)
	if seen[resolved] {
		return false
	}
	seen[resolved] = true
	if l8WorkerV2IsAllowedAuditedJSONDecodeType(resolved) {
		return false
	}
	if l8WorkerV2IsInterfaceType(resolved) || l8WorkerV2HasUnsafeJSONDecodeMethod(resolved) {
		return true
	}
	switch underlying := resolved.Underlying().(type) {
	case *types.Array:
		return l8WorkerV2TypeMayInvokeJSONDecodeCallback(underlying.Elem(), seen)
	case *types.Slice:
		return l8WorkerV2TypeMayInvokeJSONDecodeCallback(underlying.Elem(), seen)
	case *types.Map:
		return l8WorkerV2TypeMayInvokeJSONDecodeCallback(underlying.Key(), seen) ||
			l8WorkerV2TypeMayInvokeJSONDecodeCallback(underlying.Elem(), seen)
	case *types.Pointer:
		return l8WorkerV2TypeMayInvokeJSONDecodeCallback(underlying.Elem(), seen)
	case *types.Struct:
		for index := 0; index < underlying.NumFields(); index++ {
			if l8WorkerV2TypeMayInvokeJSONDecodeCallback(underlying.Field(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func l8WorkerV2HasUnsafeJSONDecodeMethod(typ types.Type) bool {
	candidates := []types.Type{typ}
	if _, pointer := types.Unalias(typ).(*types.Pointer); !pointer {
		candidates = append(candidates, types.NewPointer(typ))
	}
	for _, candidate := range candidates {
		methods := types.NewMethodSet(candidate)
		for index := 0; index < methods.Len(); index++ {
			switch methods.At(index).Obj().Name() {
			case "UnmarshalJSON", "UnmarshalText":
				return !l8WorkerV2IsAllowedAuditedJSONDecodeType(typ)
			}
		}
	}
	return false
}

func l8WorkerV2IsAllowedAuditedJSONDecodeType(typ types.Type) bool {
	resolved := types.Unalias(typ)
	if pointer, ok := resolved.(*types.Pointer); ok {
		resolved = types.Unalias(pointer.Elem())
	}
	named, ok := resolved.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	packagePath, name := named.Obj().Pkg().Path(), named.Obj().Name()
	if packagePath == "time" && name == "Time" {
		return true
	}
	// The unchanged V1 outer envelopes contain RuntimeMetadata. Its sanitizing
	// JSON methods are AST-hash locked by the L8 command source guard, so this is
	// the only repository-owned custom decoder allowed through the V2 seam.
	return packagePath == "github.com/jywlabs/hal/internal/sandboxruntime" && name == "RuntimeMetadata"
}

func l8WorkerV2AllowedExactJSONMarshalCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	if !l8WorkerV2IsPackageCall(call, "encoding/json", "Marshal", 1, info) {
		return false
	}
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok {
		return false
	}
	base := filepath.Base(scope.file.path)
	requiredType := ""
	switch {
	case base == "job_v2_helpers.go" && function.Name.Name == "jobRequestKeyV2":
		requiredType = "jobRequestIdentityV2"
	case base == "job_store_v2.go" && (function.Name.Name == "encodeStoredJobStateV2" || function.Name.Name == "save"):
		requiredType = "storedJobStateV2"
	default:
		return false
	}
	argumentType := info.TypeOf(call.Args[0])
	exactSchema := false
	switch requiredType {
	case "jobRequestIdentityV2":
		exactSchema = l8WorkerV2IsExactJobRequestIdentitySchema(argumentType) && l8WorkerV2ExactJobRequestIdentityInitializer(scope, call, info)
	case "storedJobStateV2":
		exactSchema = l8WorkerV2IsExactStoredJobStateSchema(argumentType)
	}
	callbacks := l8WorkerV2TypeMayInvokeJSONEncodeCallback(argumentType, make(map[types.Type]bool))
	return exactSchema && !callbacks
}

func l8WorkerV2AllowedExactJSONEncoderCall(scope l8WorkerV2GuardScope, candidate *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if ok && filepath.Base(scope.file.path) == "client.go" && function.Name.Name == "RoundTrip" && l8WorkerV2ReceiverNamed(function, "unixSocketClientTransport", info) {
		newEncoder, encodeCall, exact := l8WorkerV2ExactClientRequestEncoderCalls(function, info)
		if exact && (candidate == newEncoder || candidate == encodeCall) {
			return true
		}
	}
	if !ok || filepath.Base(scope.file.path) != "protocol_decode.go" || function.Name.Name != "encodeWorkerResponse" || function.Recv != nil || function.Body == nil || len(function.Body.List) != 2 {
		return false
	}
	var parameters []types.Object
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			parameters = append(parameters, info.Defs[name])
		}
	}
	if len(parameters) != 2 || parameters[0] == nil || parameters[1] == nil || !l8WorkerV2IsExactIOWriter(parameters[0].Type()) || !l8WorkerV2IsExactNamedStruct(parameters[1].Type(), "Response") || l8WorkerV2TypeMayInvokeJSONEncodeCallback(parameters[1].Type(), make(map[types.Type]bool)) {
		return false
	}
	if function.Type.Results == nil || len(function.Type.Results.List) != 1 || info.TypeOf(function.Type.Results.List[0].Type) != types.Universe.Lookup("error").Type() {
		return false
	}
	assignment, ok := function.Body.List[0].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	encoder := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
	newEncoder, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if encoder == nil || !ok || !l8WorkerV2IsPackageCall(newEncoder, "encoding/json", "NewEncoder", 1, info) || l8WorkerV2ExpressionObject(newEncoder.Args[0], info) != parameters[0] {
		return false
	}
	returned, ok := function.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	encodeCall, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.CallExpr)
	if !ok || len(encodeCall.Args) != 1 || l8WorkerV2ExpressionObject(encodeCall.Args[0], info) != parameters[1] {
		return false
	}
	selector, ok := l8WorkerV2UnparenExpression(encodeCall.Fun).(*ast.SelectorExpr)
	if !ok || l8WorkerV2ExpressionObject(selector.X, info) != encoder {
		return false
	}
	selection := info.Selections[selector]
	if selection == nil || selection.Obj() == nil || selection.Obj().Pkg() == nil || selection.Obj().Pkg().Path() != "encoding/json" || selection.Obj().Name() != "Encode" {
		return false
	}
	return candidate == newEncoder || candidate == encodeCall
}

func l8WorkerV2IsExactIOWriter(typ types.Type) bool {
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "io" && named.Obj().Name() == "Writer"
}

func l8WorkerV2IsExactNamedStruct(typ types.Type, name string) bool {
	named, ok := types.Unalias(typ).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || named.Obj().Name() != name {
		return false
	}
	_, ok = named.Underlying().(*types.Struct)
	return ok
}

func l8WorkerV2IsExactJobRequestIdentitySchema(typ types.Type) bool {
	structure, ok := l8WorkerV2ExactNamedStructUnderlying(typ, "jobRequestIdentityV2")
	if !ok || structure.NumFields() != 4 {
		return false
	}
	return l8WorkerV2IsExactStructField(structure, 0, "DriverID", types.Universe.Lookup("string").Type(), `json:"driverId"`) &&
		l8WorkerV2IsExactStructField(structure, 1, "PrincipalID", types.Universe.Lookup("string").Type(), `json:"principalId"`) &&
		l8WorkerV2IsExactStructField(structure, 2, "DaemonGeneration", types.Universe.Lookup("string").Type(), `json:"daemonGeneration"`) &&
		l8WorkerV2IsExactNamedStructField(structure, 3, "Request", "JobStartRequestV2", `json:"request"`)
}

func l8WorkerV2ExactJobRequestIdentityInitializer(scope l8WorkerV2GuardScope, marshal *ast.CallExpr, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || function.Name.Name != "jobRequestKeyV2" || function.Recv != nil || function.Body == nil || len(function.Body.List) != 6 || len(marshal.Args) != 1 {
		return false
	}
	parameters := l8WorkerV2FunctionParameterObjects(function, info)
	if len(parameters) != 4 || !types.Identical(parameters[0].Type(), types.Universe.Lookup("string").Type()) || !types.Identical(parameters[1].Type(), types.Universe.Lookup("string").Type()) || !types.Identical(parameters[2].Type(), types.Universe.Lookup("string").Type()) || !l8WorkerV2IsExactNamedStruct(parameters[3].Type(), "JobStartRequestV2") {
		return false
	}
	identity := l8WorkerV2ExpressionObject(marshal.Args[0], info)
	if identity == nil {
		return false
	}
	matches := 0
	var initializer *ast.AssignStmt
	initializerIndex := -1
	var bindings map[string]*ast.Ident
	var canonicalObjects []types.Object
	var canonicalUses []*ast.Ident
	for index, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || l8WorkerV2ExpressionObject(assignment.Lhs[0], info) != identity {
			continue
		}
		if index == 0 {
			continue
		}
		candidateCanonicalObjects, candidateCanonicalUses, exactCanonicalization := l8WorkerV2ExactCanonicalIdentityInputsCall(scope, function.Body.List[index-1], parameters, info)
		literal, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CompositeLit)
		candidateBindings, exactBindings := l8WorkerV2ExactIdentityLiteralBindings(literal, candidateCanonicalObjects, info)
		if ok && exactCanonicalization && l8WorkerV2IsExactNamedStruct(info.TypeOf(literal), "jobRequestIdentityV2") && exactBindings {
			matches++
			initializer = assignment
			initializerIndex = index
			bindings = candidateBindings
			canonicalObjects = candidateCanonicalObjects
			canonicalUses = candidateCanonicalUses
		}
	}
	marshalIdentity, ok := l8WorkerV2UnparenExpression(marshal.Args[0]).(*ast.Ident)
	return matches == 1 && initializer != nil && initializerIndex == 1 && initializer.End() < marshal.Pos() && ok &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, parameters[0], []*ast.Ident{canonicalUses[0]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, parameters[1], []*ast.Ident{canonicalUses[1]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, parameters[2], []*ast.Ident{canonicalUses[2]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, parameters[3], []*ast.Ident{canonicalUses[3]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, canonicalObjects[0], []*ast.Ident{bindings["DriverID"]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, canonicalObjects[1], []*ast.Ident{bindings["PrincipalID"]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, canonicalObjects[2], []*ast.Ident{bindings["DaemonGeneration"]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, canonicalObjects[3], []*ast.Ident{bindings["Request"]}, info) &&
		l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, identity, []*ast.Ident{marshalIdentity}, info) &&
		l8WorkerV2ObjectHasNoReassignments(function, canonicalObjects[0], info) &&
		l8WorkerV2ObjectHasNoReassignments(function, canonicalObjects[1], info) &&
		l8WorkerV2ObjectHasNoReassignments(function, canonicalObjects[2], info) &&
		l8WorkerV2ObjectHasNoReassignments(function, canonicalObjects[3], info) &&
		l8WorkerV2ObjectHasNoReassignments(function, identity, info) &&
		l8WorkerV2ObjectHasNoWholeValueEscapes(function, identity, []*ast.CallExpr{marshal}, nil, false, info) &&
		l8WorkerV2ExactIdentityMarshalDigestPipeline(function, marshal, info)
}

func l8WorkerV2ExactCanonicalIdentityInputsCall(scope l8WorkerV2GuardScope, statement ast.Stmt, parameters []types.Object, info *types.Info) ([]types.Object, []*ast.Ident, bool) {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 4 || len(assignment.Rhs) != 1 || len(parameters) != 4 {
		return nil, nil, false
	}
	call, ok := l8WorkerV2UnparenExpression(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok || len(call.Args) != 4 {
		return nil, nil, false
	}
	called, ok := l8WorkerV2CalledObject(call.Fun, info).(*types.Func)
	if !ok || called.Pkg() == nil || called.Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || called.Name() != "canonicalJobRequestIdentityInputsV2" {
		return nil, nil, false
	}
	signature, ok := called.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.TypeParams() != nil || signature.Variadic() || signature.Params().Len() != 4 || signature.Results().Len() != 4 ||
		!types.Identical(signature.Params().At(0).Type(), types.Universe.Lookup("string").Type()) ||
		!types.Identical(signature.Params().At(1).Type(), types.Universe.Lookup("string").Type()) ||
		!types.Identical(signature.Params().At(2).Type(), types.Universe.Lookup("string").Type()) ||
		!l8WorkerV2IsExactNamedStruct(signature.Params().At(3).Type(), "JobStartRequestV2") ||
		!types.Identical(signature.Results().At(0).Type(), types.Universe.Lookup("string").Type()) ||
		!types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("string").Type()) ||
		!types.Identical(signature.Results().At(2).Type(), types.Universe.Lookup("string").Type()) ||
		!l8WorkerV2IsExactNamedStruct(signature.Results().At(3).Type(), "JobStartRequestV2") {
		return nil, nil, false
	}
	declaredInGuardedFile := false
	for _, declaration := range scope.file.parsed.Decls {
		candidate, ok := declaration.(*ast.FuncDecl)
		if ok && candidate.Recv == nil && info.Defs[candidate.Name] == called {
			declaredInGuardedFile = true
			break
		}
	}
	if !declaredInGuardedFile {
		return nil, nil, false
	}
	canonicalObjects := make([]types.Object, 4)
	parameterUses := make([]*ast.Ident, 4)
	for index := range parameters {
		argument, argumentIsIdentifier := l8WorkerV2UnparenExpression(call.Args[index]).(*ast.Ident)
		canonicalObjects[index] = l8WorkerV2ExpressionObject(assignment.Lhs[index], info)
		if !argumentIsIdentifier || info.Uses[argument] != parameters[index] || canonicalObjects[index] == nil || !types.Identical(canonicalObjects[index].Type(), signature.Results().At(index).Type()) {
			return nil, nil, false
		}
		parameterUses[index] = argument
	}
	return canonicalObjects, parameterUses, true
}

func l8WorkerV2ExactIdentityLiteralBindings(literal *ast.CompositeLit, parameters []types.Object, info *types.Info) (map[string]*ast.Ident, bool) {
	if literal == nil || len(literal.Elts) != 4 || len(parameters) != 4 {
		return nil, false
	}
	want := map[string]types.Object{
		"DriverID":         parameters[0],
		"PrincipalID":      parameters[1],
		"DaemonGeneration": parameters[2],
		"Request":          parameters[3],
	}
	bindings := make(map[string]*ast.Ident, len(want))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return nil, false
		}
		key, ok := l8WorkerV2UnparenExpression(pair.Key).(*ast.Ident)
		if !ok {
			return nil, false
		}
		expected, exists := want[key.Name]
		value, valueIsIdentifier := l8WorkerV2UnparenExpression(pair.Value).(*ast.Ident)
		if !exists || bindings[key.Name] != nil || !valueIsIdentifier || info.Uses[value] != expected {
			return nil, false
		}
		bindings[key.Name] = value
	}
	return bindings, len(bindings) == len(want)
}

func l8WorkerV2ObjectUsedOnlyAtIdentifiers(function *ast.FuncDecl, object types.Object, allowed []*ast.Ident, info *types.Info) bool {
	if function == nil || function.Body == nil || object == nil {
		return false
	}
	allowedSet := make(map[*ast.Ident]bool, len(allowed))
	for _, identifier := range allowed {
		if identifier == nil || info.Uses[identifier] != object {
			return false
		}
		allowedSet[identifier] = true
	}
	uses := 0
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if !ok || info.Uses[identifier] != object {
			return true
		}
		uses++
		if !allowedSet[identifier] {
			valid = false
			return false
		}
		return true
	})
	return valid && uses == len(allowedSet)
}

func l8WorkerV2ExactIdentityMarshalDigestPipeline(function *ast.FuncDecl, marshal *ast.CallExpr, info *types.Info) bool {
	if function == nil || function.Body == nil || marshal == nil {
		return false
	}
	for index, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 || assignment.Rhs[0] != marshal || index+3 != len(function.Body.List)-1 {
			continue
		}
		payload := l8WorkerV2ExpressionObject(assignment.Lhs[0], info)
		marshalErr := l8WorkerV2ExpressionObject(assignment.Lhs[1], info)
		errorBranch, branchOK := function.Body.List[index+1].(*ast.IfStmt)
		digestAssignment, digestOK := function.Body.List[index+2].(*ast.AssignStmt)
		finalReturn, returnOK := function.Body.List[index+3].(*ast.ReturnStmt)
		if payload == nil || marshalErr == nil || !branchOK || errorBranch.Init != nil || errorBranch.Else != nil || len(errorBranch.Body.List) != 1 ||
			!l8WorkerV2IsErrorComparison(errorBranch.Cond, marshalErr, nil, info) || !l8WorkerV2ExactEmptyStringAndObjectReturn(errorBranch.Body.List[0], marshalErr, info) ||
			!digestOK || digestAssignment.Tok != token.DEFINE || len(digestAssignment.Lhs) != 1 || len(digestAssignment.Rhs) != 1 || !returnOK || len(finalReturn.Results) != 2 || !l8WorkerV2IsNilExpression(finalReturn.Results[1], info) {
			return false
		}
		digest := l8WorkerV2ExpressionObject(digestAssignment.Lhs[0], info)
		sumCall, ok := l8WorkerV2UnparenExpression(digestAssignment.Rhs[0]).(*ast.CallExpr)
		if digest == nil || !ok || !l8WorkerV2IsPackageCall(sumCall, "crypto/sha256", "Sum256", 1, info) {
			return false
		}
		payloadArgument, ok := l8WorkerV2UnparenExpression(sumCall.Args[0]).(*ast.Ident)
		digestUse, exactReturn := l8WorkerV2ExactCanonicalRequestKeyReturn(finalReturn.Results[0], digest, info)
		return ok && info.Uses[payloadArgument] == payload && exactReturn && l8WorkerV2ObjectUseCount(function, marshalErr, info) == 2 &&
			l8WorkerV2ObjectHasNoReassignments(function, marshalErr, info) &&
			l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, payload, []*ast.Ident{payloadArgument}, info) &&
			l8WorkerV2ObjectHasNoReassignments(function, payload, info) &&
			l8WorkerV2ObjectUsedOnlyAtIdentifiers(function, digest, []*ast.Ident{digestUse}, info) &&
			l8WorkerV2ObjectHasNoReassignments(function, digest, info)
	}
	return false
}

func l8WorkerV2ExactCanonicalRequestKeyReturn(expression ast.Expr, digest types.Object, info *types.Info) (*ast.Ident, bool) {
	concatenation, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || concatenation.Op != token.ADD {
		return nil, false
	}
	prefix := info.Types[concatenation.X].Value
	encodeCall, ok := l8WorkerV2UnparenExpression(concatenation.Y).(*ast.CallExpr)
	if prefix == nil || prefix.Kind() != constant.String || constant.StringVal(prefix) != "request-v2-" || !ok || !l8WorkerV2IsPackageCall(encodeCall, "encoding/hex", "EncodeToString", 1, info) {
		return nil, false
	}
	slice, ok := l8WorkerV2UnparenExpression(encodeCall.Args[0]).(*ast.SliceExpr)
	if !ok || slice.Slice3 || slice.Low != nil || slice.High != nil || slice.Max != nil {
		return nil, false
	}
	identifier, ok := l8WorkerV2UnparenExpression(slice.X).(*ast.Ident)
	return identifier, ok && info.Uses[identifier] == digest
}

func l8WorkerV2ExactEmptyStringAndObjectReturn(statement ast.Stmt, object types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 || l8WorkerV2ExpressionObject(returned.Results[1], info) != object {
		return false
	}
	value := info.Types[returned.Results[0]].Value
	return value != nil && value.Kind() == constant.String && constant.StringVal(value) == ""
}

func l8WorkerV2IsExactStoredJobStateSchema(typ types.Type) bool {
	structure, ok := l8WorkerV2ExactNamedStructUnderlying(typ, "storedJobStateV2")
	if !ok || structure.NumFields() != 4 {
		return false
	}
	return l8WorkerV2IsExactNamedStructField(structure, 0, "JobV2", "JobV2", "") &&
		l8WorkerV2IsExactStructField(structure, 1, "RequestKey", types.Universe.Lookup("string").Type(), `json:"requestKey"`) &&
		l8WorkerV2IsExactStructField(structure, 2, "PrincipalID", types.Universe.Lookup("string").Type(), `json:"principalId"`) &&
		l8WorkerV2IsExactStructField(structure, 3, "DaemonGeneration", types.Universe.Lookup("string").Type(), `json:"daemonGeneration"`)
}

func l8WorkerV2ExactNamedStructUnderlying(typ types.Type, name string) (*types.Struct, bool) {
	named, ok := types.Unalias(typ).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" || named.Obj().Name() != name {
		return nil, false
	}
	structure, ok := named.Underlying().(*types.Struct)
	return structure, ok
}

func l8WorkerV2IsExactStructField(structure *types.Struct, index int, name string, typ types.Type, tag string) bool {
	field := structure.Field(index)
	return field.Name() == name && !field.Embedded() && types.Identical(field.Type(), typ) && structure.Tag(index) == tag
}

func l8WorkerV2IsExactNamedStructField(structure *types.Struct, index int, name, typeName, tag string) bool {
	field := structure.Field(index)
	return field.Name() == name && !field.Embedded() && l8WorkerV2IsExactNamedStruct(field.Type(), typeName) && structure.Tag(index) == tag
}

func l8WorkerV2TypeMayInvokeJSONEncodeCallback(typ types.Type, seen map[types.Type]bool) bool {
	if typ == nil {
		return false
	}
	resolved := types.Unalias(typ)
	if seen[resolved] {
		return false
	}
	seen[resolved] = true
	if l8WorkerV2IsAllowedAuditedJSONEncodeType(resolved) {
		return false
	}
	if l8WorkerV2IsInterfaceType(resolved) || l8WorkerV2HasUnsafeJSONEncodeMethod(resolved) {
		return true
	}
	switch underlying := resolved.Underlying().(type) {
	case *types.Array:
		return l8WorkerV2TypeMayInvokeJSONEncodeCallback(underlying.Elem(), seen)
	case *types.Slice:
		return l8WorkerV2TypeMayInvokeJSONEncodeCallback(underlying.Elem(), seen)
	case *types.Map:
		return l8WorkerV2TypeMayInvokeJSONEncodeCallback(underlying.Key(), seen) || l8WorkerV2TypeMayInvokeJSONEncodeCallback(underlying.Elem(), seen)
	case *types.Pointer:
		return l8WorkerV2TypeMayInvokeJSONEncodeCallback(underlying.Elem(), seen)
	case *types.Struct:
		for index := 0; index < underlying.NumFields(); index++ {
			if l8WorkerV2TypeMayInvokeJSONEncodeCallback(underlying.Field(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func l8WorkerV2HasUnsafeJSONEncodeMethod(typ types.Type) bool {
	candidates := []types.Type{typ}
	if _, pointer := types.Unalias(typ).(*types.Pointer); !pointer {
		candidates = append(candidates, types.NewPointer(typ))
	}
	for _, candidate := range candidates {
		methods := types.NewMethodSet(candidate)
		for index := 0; index < methods.Len(); index++ {
			switch methods.At(index).Obj().Name() {
			case "MarshalJSON", "MarshalText":
				return !l8WorkerV2IsAllowedAuditedJSONEncodeType(typ)
			}
		}
	}
	return false
}

func l8WorkerV2IsAllowedAuditedJSONEncodeType(typ types.Type) bool {
	resolved := types.Unalias(typ)
	if pointer, ok := resolved.(*types.Pointer); ok {
		resolved = types.Unalias(pointer.Elem())
	}
	named, ok := resolved.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	packagePath, name := named.Obj().Pkg().Path(), named.Obj().Name()
	if packagePath == "time" && name == "Time" {
		return true
	}
	// RuntimeMetadata's sanitizing JSON methods are AST-hash locked by the L8
	// command source guard. No adjacent repository-owned marshaler is allowed.
	return packagePath == "github.com/jywlabs/hal/internal/sandboxruntime" && name == "RuntimeMetadata"
}

func l8WorkerV2ExactPrimaryDecodeIf(statement ast.Stmt, decoder, output types.Object, info *types.Info) bool {
	conditional, errObject, decodeCall, ok := l8WorkerV2ExactDecodeIf(statement, decoder, info)
	if !ok || len(decodeCall.Args) != 1 {
		return false
	}
	argument, ok := l8WorkerV2UnparenExpression(decodeCall.Args[0]).(*ast.Ident)
	if !ok || info.Uses[argument] != output {
		return false
	}
	if !l8WorkerV2IsErrorComparison(conditional.Cond, errObject, nil, info) {
		return false
	}
	return conditional.Else == nil && len(conditional.Body.List) == 1 && l8WorkerV2IsBareReturn(conditional.Body.List[0], errObject, info)
}

func l8WorkerV2ExactTrailingDeclaration(statement ast.Stmt, info *types.Info) (types.Object, bool) {
	declaration, ok := statement.(*ast.DeclStmt)
	if !ok {
		return nil, false
	}
	generated, ok := declaration.Decl.(*ast.GenDecl)
	if !ok || generated.Tok != token.VAR || len(generated.Specs) != 1 {
		return nil, false
	}
	spec, ok := generated.Specs[0].(*ast.ValueSpec)
	if !ok || len(spec.Names) != 1 || len(spec.Values) != 0 {
		return nil, false
	}
	structure, ok := spec.Type.(*ast.StructType)
	if !ok || structure.Fields == nil || len(structure.Fields.List) != 0 {
		return nil, false
	}
	object := info.Defs[spec.Names[0]]
	return object, object != nil
}

func l8WorkerV2ExactTrailingDecodeIf(statement ast.Stmt, decoder, trailing types.Object, info *types.Info) bool {
	conditional, errObject, decodeCall, ok := l8WorkerV2ExactDecodeIf(statement, decoder, info)
	if !ok || len(decodeCall.Args) != 1 {
		return false
	}
	address, ok := l8WorkerV2UnparenExpression(decodeCall.Args[0]).(*ast.UnaryExpr)
	if !ok || address.Op != token.AND || l8WorkerV2ExpressionObject(address.X, info) != trailing {
		return false
	}
	eof := l8WorkerV2PackageObjectExpression(conditional.Cond, "io", "EOF", info)
	if eof == nil || !l8WorkerV2IsErrorComparison(conditional.Cond, errObject, eof, info) {
		return false
	}
	return conditional.Else == nil && len(conditional.Body.List) == 1 && l8WorkerV2IsConstantErrorsNewReturn(conditional.Body.List[0], info)
}

func l8WorkerV2ExactDecodeIf(statement ast.Stmt, decoder types.Object, info *types.Info) (*ast.IfStmt, types.Object, *ast.CallExpr, bool) {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init == nil {
		return nil, nil, nil, false
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return nil, nil, nil, false
	}
	errName, ok := assignment.Lhs[0].(*ast.Ident)
	if !ok {
		return nil, nil, nil, false
	}
	errObject := info.Defs[errName]
	decodeCall, ok := l8WorkerV2DecoderMethodCall(assignment.Rhs[0], decoder, "Decode", info)
	if errObject == nil || !ok {
		return nil, nil, nil, false
	}
	return conditional, errObject, decodeCall, true
}

func l8WorkerV2IsErrorComparison(expression ast.Expr, errObject, expected types.Object, info *types.Info) bool {
	comparison, ok := l8WorkerV2UnparenExpression(expression).(*ast.BinaryExpr)
	if !ok || comparison.Op != token.NEQ || l8WorkerV2ExpressionObject(comparison.X, info) != errObject {
		return false
	}
	if expected == nil {
		identifier, ok := l8WorkerV2UnparenExpression(comparison.Y).(*ast.Ident)
		return ok && identifier.Name == "nil" && info.Uses[identifier] == types.Universe.Lookup("nil")
	}
	return l8WorkerV2ExpressionObject(comparison.Y, info) == expected
}

func l8WorkerV2PackageObjectExpression(expression ast.Expr, packagePath, name string, info *types.Info) types.Object {
	var result types.Object
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		object := info.Uses[identifier]
		if object != nil && object.Pkg() != nil && object.Pkg().Path() == packagePath && object.Name() == name {
			result = object
			return false
		}
		return true
	})
	return result
}

func l8WorkerV2IsBareReturn(statement ast.Stmt, expected types.Object, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	if expected != nil {
		return l8WorkerV2ExpressionObject(returned.Results[0], info) == expected
	}
	identifier, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.Ident)
	return ok && identifier.Name == "nil" && info.Uses[identifier] == types.Universe.Lookup("nil")
}

func l8WorkerV2IsConstantErrorsNewReturn(statement ast.Stmt, info *types.Info) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	call, ok := l8WorkerV2UnparenExpression(returned.Results[0]).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil || object.Pkg().Path() != "errors" || object.Name() != "New" {
		return false
	}
	value := info.Types[call.Args[0]].Value
	return value != nil && value.Kind() == constant.String
}

func l8WorkerV2CallMayInvokeImplicitInterface(call *ast.CallExpr, info *types.Info) bool {
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil || object.Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" {
		return false
	}
	// Imports with their own stronger dynamic-runtime guard retain that stable
	// evidence instead of being reported through the more general callback rule.
	if object.Pkg().Path() == "reflect" {
		return false
	}
	signature, ok := object.Type().Underlying().(*types.Signature)
	if !ok || signature.Params() == nil || signature.Params().Len() == 0 {
		return false
	}
	for index, argument := range call.Args {
		parameterIndex := index
		if parameterIndex >= signature.Params().Len() {
			if !signature.Variadic() {
				break
			}
			parameterIndex = signature.Params().Len() - 1
		}
		if call.Ellipsis.IsValid() && index == len(call.Args)-1 {
			if l8WorkerV2VariadicExpansionMayCallback(argument, info) {
				return true
			}
			continue
		}
		parameterType := signature.Params().At(parameterIndex).Type()
		if signature.Variadic() && parameterIndex == signature.Params().Len()-1 {
			if slice, ok := parameterType.(*types.Slice); ok {
				parameterType = slice.Elem()
			}
		}
		if !l8WorkerV2IsInterfaceType(parameterType) {
			continue
		}
		if l8WorkerV2InterfaceCapableArgument(info.TypeOf(argument)) {
			return true
		}
	}
	return false
}

func l8WorkerV2VariadicExpansionMayCallback(argument ast.Expr, info *types.Info) bool {
	typ := info.TypeOf(argument)
	if typ == nil {
		return false
	}
	slice, ok := types.Unalias(typ).Underlying().(*types.Slice)
	if !ok {
		return l8WorkerV2InterfaceCapableArgument(typ)
	}
	if !l8WorkerV2IsInterfaceType(slice.Elem()) {
		return l8WorkerV2InterfaceCapableArgument(slice.Elem())
	}
	literal, ok := argument.(*ast.CompositeLit)
	if !ok {
		return true
	}
	for _, rawElement := range literal.Elts {
		if keyed, ok := rawElement.(*ast.KeyValueExpr); ok {
			rawElement = keyed.Value
		}
		expression := rawElement
		if l8WorkerV2InterfaceCapableArgument(info.TypeOf(expression)) {
			return true
		}
	}
	return false
}

func l8WorkerV2CalledObject(expression ast.Expr, info *types.Info) types.Object {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.Ident:
			return info.Uses[typed]
		case *ast.SelectorExpr:
			if selection := info.Selections[typed]; selection != nil {
				return selection.Obj()
			}
			return info.Uses[typed.Sel]
		default:
			return nil
		}
	}
}

func l8WorkerV2InterfaceCapableArgument(typ types.Type) bool {
	return l8WorkerV2TypeMayInvokeFormattingCallback(typ, make(map[types.Type]bool))
}

func l8WorkerV2TypeMayInvokeFormattingCallback(typ types.Type, seen map[types.Type]bool) bool {
	if typ == nil || seen[typ] {
		return false
	}
	seen[typ] = true
	if l8WorkerV2IsInterfaceType(typ) || types.NewMethodSet(typ).Len() > 0 {
		return true
	}
	switch underlying := types.Unalias(typ).Underlying().(type) {
	case *types.Array:
		return l8WorkerV2TypeMayInvokeFormattingCallback(underlying.Elem(), seen)
	case *types.Slice:
		return l8WorkerV2TypeMayInvokeFormattingCallback(underlying.Elem(), seen)
	case *types.Map:
		return l8WorkerV2TypeMayInvokeFormattingCallback(underlying.Key(), seen) ||
			l8WorkerV2TypeMayInvokeFormattingCallback(underlying.Elem(), seen)
	case *types.Pointer:
		return l8WorkerV2TypeMayInvokeFormattingCallback(underlying.Elem(), seen)
	case *types.Struct:
		for index := 0; index < underlying.NumFields(); index++ {
			if l8WorkerV2TypeMayInvokeFormattingCallback(underlying.Field(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func l8RejectWorkerV2SemanticExternalSurfaces(scope l8WorkerV2GuardScope, info *types.Info) error {
	selectorIdentifiers := make(map[*ast.Ident]bool)
	directCallSelectors := make(map[*ast.SelectorExpr]bool)
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			selectorIdentifiers[selector.Sel] = true
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if selector := l8WorkerV2CalledSelector(call.Fun); selector != nil {
				directCallSelectors[selector] = true
			}
		}
		return true
	})

	var inspectionErr error
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		if inspectionErr != nil {
			return false
		}
		var surface string
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			if selection := info.Selections[typed]; selection != nil {
				surface = l8WorkerV2ForbiddenSelectionSurface(selection, directCallSelectors[typed])
			} else {
				surface = l8WorkerV2ForbiddenObjectSurface(info.Uses[typed.Sel])
			}
		case *ast.Ident:
			if selectorIdentifiers[typed] {
				return true
			}
			surface = l8WorkerV2ForbiddenObjectSurface(info.Uses[typed])
		}
		if surface != "" {
			inspectionErr = fmt.Errorf("worker-v2 production path in %s uses forbidden external live surface %q", scope.file.path, surface)
			return false
		}
		return true
	})
	return inspectionErr
}

func l8WorkerV2CalledSelector(expression ast.Expr) *ast.SelectorExpr {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.SelectorExpr:
			return typed
		default:
			return nil
		}
	}
}

func l8WorkerV2ForbiddenSelectionSurface(selection *types.Selection, directCall bool) string {
	if selection == nil {
		return ""
	}
	if !directCall && l8WorkerV2SelectionUsesInterface(selection) {
		return "interface method-value"
	}
	receiver := l8WorkerV2NamedTypeObject(selection.Recv())
	if receiver != nil && receiver.Pkg() != nil {
		path := receiver.Pkg().Path()
		if path == "os" && (receiver.Name() == "Process" || receiver.Name() == "ProcessState") {
			return path + "." + selection.Obj().Name()
		}
		if selection.Kind() == types.FieldVal && l8WorkerV2RawSyscallPackage(path) && receiver.Name() == "Stat_t" {
			return ""
		}
	}
	return l8WorkerV2ForbiddenObjectSurface(selection.Obj())
}

func l8WorkerV2NamedTypeObject(typ types.Type) *types.TypeName {
	if typ == nil {
		return nil
	}
	typ = types.Unalias(typ)
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(pointer.Elem())
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return nil
	}
	return named.Obj()
}

func l8WorkerV2ForbiddenObjectSurface(object types.Object) string {
	if object == nil || object.Pkg() == nil {
		return ""
	}
	path := object.Pkg().Path()
	name := object.Name()
	switch {
	case path == "unsafe", path == "plugin":
		return path + "." + name
	case l8WorkerV2RawSyscallPackage(path):
		if l8WorkerV2AllowedRawSyscallObject(name) {
			return ""
		}
		return path + "." + name
	case path == "os" && l8WorkerV2ForbiddenOSObject(name):
		return path + "." + name
	case path == "log" && l8WorkerV2ForbiddenLogObject(name):
		return path + "." + name
	default:
		return ""
	}
}

func l8WorkerV2RawSyscallPackage(path string) bool {
	return path == "syscall" || path == "golang.org/x/sys/unix"
}

func l8WorkerV2AllowedRawSyscallObject(name string) bool {
	switch name {
	case "Flock", "Stat_t", "LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN", "EINTR", "EAGAIN", "EWOULDBLOCK":
		return true
	default:
		return false
	}
}

func l8WorkerV2ForbiddenOSObject(name string) bool {
	switch name {
	case "Args", "Stdin", "Stdout", "Stderr", "Interrupt", "Kill", "Chdir",
		"Process", "ProcessState", "ProcAttr", "Signal", "StartProcess", "FindProcess", "Exit",
		"Getenv", "LookupEnv", "Environ", "ExpandEnv", "Setenv", "Unsetenv", "Clearenv",
		"Getpid", "Getppid", "Getuid", "Geteuid", "Getgid", "Getegid", "Getgroups",
		"Executable", "Hostname", "UserHomeDir", "UserCacheDir", "UserConfigDir", "Pipe", "NewFile":
		return true
	default:
		return false
	}
}

func l8WorkerV2ForbiddenLogObject(name string) bool {
	switch name {
	case "Fatal", "Fatalf", "Fatalln":
		return true
	default:
		return false
	}
}

func l8WorkerV2DynamicCallKind(expression ast.Expr, info *types.Info) string {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			if !l8WorkerV2IsGenericInstantiation(typed, typed.X, info) {
				return "function-value"
			}
			expression = typed.X
		case *ast.IndexListExpr:
			if !l8WorkerV2IsGenericInstantiation(typed, typed.X, info) {
				return "function-value"
			}
			expression = typed.X
		default:
			goto unwrapped
		}
	}

unwrapped:
	switch typed := expression.(type) {
	case *ast.Ident:
		switch info.Uses[typed].(type) {
		case *types.Builtin, *types.Func, *types.TypeName:
			return ""
		}
	case *ast.SelectorExpr:
		if selection := info.Selections[typed]; selection != nil {
			if l8WorkerV2SelectionUsesInterface(selection) {
				return "interface"
			}
			if _, ok := selection.Obj().(*types.Func); ok {
				return ""
			}
		} else if _, ok := info.Uses[typed.Sel].(*types.Func); ok {
			return ""
		}
	}
	if _, ok := info.TypeOf(expression).Underlying().(*types.Signature); ok {
		return "function-value"
	}
	return ""
}

func l8WorkerV2SelectionUsesInterface(selection *types.Selection) bool {
	if selection == nil {
		return false
	}
	if l8WorkerV2IsInterfaceType(selection.Recv()) {
		return true
	}
	method, ok := selection.Obj().(*types.Func)
	if !ok {
		return false
	}
	signature, _ := method.Type().(*types.Signature)
	return signature != nil && signature.Recv() != nil && l8WorkerV2IsInterfaceType(signature.Recv().Type())
}

func l8WorkerV2IsGenericInstantiation(indexed ast.Expr, base ast.Expr, info *types.Info) bool {
	// Type information distinguishes a semantic generic instantiation from an
	// ordinary map, slice, or array lookup whose result happens to be callable.
	if _, ok := info.Types[indexed]; !ok {
		return false
	}
	for {
		switch typed := base.(type) {
		case *ast.ParenExpr:
			base = typed.X
		case *ast.Ident:
			_, ok := info.Instances[typed]
			return ok
		case *ast.SelectorExpr:
			_, ok := info.Instances[typed.Sel]
			return ok
		default:
			return false
		}
	}
}

func l8WorkerV2IsInterfaceType(typ types.Type) bool {
	for typ != nil {
		if pointer, ok := typ.(*types.Pointer); ok {
			typ = pointer.Elem()
			continue
		}
		if pointer, ok := typ.Underlying().(*types.Pointer); ok {
			typ = pointer.Elem()
			continue
		}
		_, ok := typ.Underlying().(*types.Interface)
		return ok
	}
	return false
}

func l8RejectWorkerV2ForbiddenSurface(scope l8WorkerV2GuardScope) error {
	if !scope.initializerEvaluation {
		buffer := &bytes.Buffer{}
		renderedNode := scope.node
		if field, ok := scope.node.(*ast.Field); ok {
			renderedNode = &ast.StructType{
				Struct: field.Pos(),
				Fields: &ast.FieldList{Opening: field.Pos(), List: []*ast.Field{field}, Closing: field.End()},
			}
		}
		if err := format.Node(buffer, scope.file.fileSet, renderedNode); err != nil {
			return fmt.Errorf("render worker-v2 declaration in %s: %w", scope.file.path, err)
		}
		source := buffer.String()
		for _, forbidden := range []string{
			`json:"value`,
			`json:"secret`,
			`json:"callback`,
			`json:"ticket`,
			`json:"socket`,
			`json:"endpoint`,
			`json:"hostPath`,
			`json:"path`,
			`json:"keySerial`,
			`json:"execBinding`,
			`json:"authenticatedPrincipal`,
			"RawValue",
			"SecretValue",
			"Callback",
			"Ticket",
			"Socket",
			"Endpoint",
			"HostPath",
			"KeySerial",
			"LiveSecretSource",
			"JobCredentialExecBinding",
			"keyctl_read",
			"tls.Conn",
			"net.Listen",
			"os/exec",
		} {
			if strings.Contains(source, forbidden) {
				name := "declaration"
				switch typed := scope.node.(type) {
				case *ast.FuncDecl:
					name = typed.Name.Name
				case *ast.TypeSpec:
					name = typed.Name.Name
				}
				return fmt.Errorf("v2 protocol production file %s declaration %s contains forbidden live/secret marker %q", scope.file.path, name, forbidden)
			}
		}
	}

	usedImports := make(map[string]bool)
	for _, importPath := range scope.file.alwaysImports {
		usedImports[importPath] = true
	}
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if ok {
			if importPath, exists := scope.file.imports[qualifier.Name]; exists {
				usedImports[importPath] = true
			}
		}
		return true
	})
	orderedImports := make([]string, 0, len(usedImports))
	for importPath := range usedImports {
		orderedImports = append(orderedImports, importPath)
	}
	sort.Strings(orderedImports)
	for _, importPath := range orderedImports {
		if l8WorkerV2ForbiddenImportPath(importPath) {
			return fmt.Errorf("v2 protocol production file %s imports live/provider dependency %q", scope.file.path, importPath)
		}
	}
	return nil
}

func l8RejectWorkerV2PackageGlobalForbiddenImports(files []*l8WorkerV2ParsedFile) error {
	type forbiddenImport struct {
		path       string
		importPath string
	}
	var forbidden []forbiddenImport
	for _, file := range files {
		for _, importPath := range file.globalImports {
			if l8WorkerV2ForbiddenImportPath(importPath) {
				forbidden = append(forbidden, forbiddenImport{path: file.path, importPath: importPath})
			}
		}
	}
	if len(forbidden) == 0 {
		return nil
	}
	sort.Slice(forbidden, func(left, right int) bool {
		if forbidden[left].path != forbidden[right].path {
			return forbidden[left].path < forbidden[right].path
		}
		return forbidden[left].importPath < forbidden[right].importPath
	})
	first := forbidden[0]
	return fmt.Errorf("v2 protocol production file %s imports live/provider dependency %q", first.path, first.importPath)
}

func l8WorkerV2ForbiddenImportPath(importPath string) bool {
	for _, forbidden := range []string{
		"github.com/jywlabs/hal/internal/credentialmemory",
		"github.com/jywlabs/hal/internal/credentialsource",
		"github.com/jywlabs/hal/internal/credentialproxy",
		"github.com/jywlabs/hal/internal/factory",
		"crypto/tls",
		"net",
		"net/http",
		"os/exec",
		"os/signal",
		"plugin",
		"reflect",
		"runtime",
		"runtime/debug",
		"runtime/pprof",
		"runtime/trace",
		"unsafe",
	} {
		if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
			return true
		}
	}
	return false
}

func l8WorkerV2DeclarationUnits(declaration ast.Decl) []ast.Decl {
	generated, ok := declaration.(*ast.GenDecl)
	if !ok || len(generated.Specs) <= 1 {
		return []ast.Decl{declaration}
	}
	units := make([]ast.Decl, 0, len(generated.Specs))
	for _, spec := range generated.Specs {
		unit := *generated
		unit.Lparen = token.NoPos
		unit.Rparen = token.NoPos
		unit.Specs = []ast.Spec{spec}
		units = append(units, &unit)
	}
	return units
}

func l8WorkerV2ASTContainsMarker(node ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if found {
			return false
		}
		switch typed := candidate.(type) {
		case *ast.Ident:
			found = strings.Contains(strings.ToLower(typed.Name), "v2")
		case *ast.BasicLit:
			found = strings.Contains(strings.ToLower(typed.Value), "v2")
		}
		return !found
	})
	return found
}

func TestL8WorkerV2GuardMixedFunctionsAreNarrowAndTransitive(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"client.go": true}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"client.go": `package sandboxworker
import httpalias "net/http"
func JobStartV2Fixture() {}
func unrelatedV1() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"client.go": `package sandboxworker
import httpalias "net/http"
func JobStartV2Fixture() { liveHelper() }
func liveHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")
}

func TestL8WorkerV2GuardSemanticAliasesTaintConsumers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
type JobStartRequestV2 struct{}`
	aliases := `package sandboxworker
const selectedOperation = OperationJobStartV2
const routedOperation, legacyOperation = selectedOperation, "job_start"
type selectedRequest = JobStartRequestV2
type routedRequest = selectedRequest`

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation string, request routedRequest) {
	switch operation {
	case routedOperation:
		safeHelper(request)
	}
}
func unrelatedLegacyDispatch() {
	_ = legacyOperation
	_, _ = httpalias.Get("https://legacy.example.invalid")
}`,
		"shared.go": `package sandboxworker
func safeHelper(routedRequest) {}`,
	}, policy)

	for _, fixture := range []struct {
		name    string
		handler string
	}{
		{name: "const alias chain", handler: `package sandboxworker
func dispatch(operation string) {
	switch operation {
	case routedOperation:
		forbiddenHelper()
	}
}`},
		{name: "type alias chain", handler: `package sandboxworker
func dispatch(request routedRequest) { forbiddenHelperWithRequest(request) }`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   aliases,
				"handler.go":   fixture.handler,
				"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }
func forbiddenHelperWithRequest(routedRequest) { _, _ = httpalias.Get("https://authority.example.invalid") }`,
			}, policy, "net/http")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"unlisted_handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == routedOperation {}
}`,
	}, policy, "outside the exact allowlist")
}

func TestL8WorkerV2GuardRecognizesExactOperationConstantValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`
	for _, fixture := range []struct {
		name       string
		definition string
	}{
		{name: "start escaped literal", definition: `const hiddenOperation = "job_start_v\u0032"`},
		{name: "resolve concatenation", definition: `const hiddenOperation = "job_" + "resolve_" + "v" + "2"`},
		{name: "status parenthesized conversion", definition: `const hiddenOperation = string((("job_status_" + "v" + "2")))`},
		{name: "logs alias conversion", definition: "type operationAlias = string\nconst hiddenOperation = operationAlias((\"job_logs_\" + \"v\" + \"2\"))"},
		{name: "cancel named conversion", definition: "type operationValue string\nconst hiddenOperation = operationValue(\"job_cancel_\" + string('v') + string('2'))"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   "package sandboxworker\n" + fixture.definition,
				"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == string(hiddenOperation) { forbiddenRoutedHelper() }
}`,
				"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
			}, policy, "net/http")
		})
	}
}

func TestL8WorkerV2GuardRecognizesRuntimeBuiltExactOperationValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
type JobStartRequestV2 struct{}`
	for _, fixture := range []struct {
		name       string
		definition string
	}{
		{
			name:       "byte slice conversion",
			definition: `var hiddenOperation = string([]byte{106, 111, 98, 95, 115, 116, 97, 114, 116, 95, 118, 50})`,
		},
		{
			name:       "keyed byte slice conversion",
			definition: `var hiddenOperation = string([]byte{9: 95, 10: 118, 11: 50, 0: 106, 1: 111, 2: 98, 3: 95, 4: 115, 5: 116, 6: 97, 7: 114, 8: 116})`,
		},
		{
			name: "named byte slice conversion",
			definition: `type operationBytes []byte
var hiddenOperation = string(operationBytes{106, 111, 98, 95, 115, 116, 97, 116, 117, 115, 95, 118, 50})`,
		},
		{
			name: "local builder wrapper",
			definition: `func hiddenOperation() string {
	return string([]rune{106, 111, 98, 95, 114, 101, 115, 111, 108, 118, 101, 95, 118, 50})
}`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			operation := "hiddenOperation"
			if strings.Contains(fixture.definition, "func hiddenOperation") {
				operation += "()"
			}
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   "package sandboxworker\n" + fixture.definition,
				"handler.go": `package sandboxworker
func dispatch(operation string) hiddenSchema {
	if operation == ` + operation + ` { forbiddenRoutedHelper() }
	return hiddenSchema{}
}`,
				"shared.go": `package sandboxworker
import processapi "os"
type hiddenSchema struct { Value string ` + "`json:\"value\"`" + ` }
func forbiddenRoutedHelper() { _, _ = processapi.StartProcess("worker", nil, nil) }`,
			}, policy, "runtime operation assembly")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
var hiddenLegacyOperation = string([]byte{106, 111, 98, 95, 115, 116, 97, 114, 116})`,
		"handler.go": `package sandboxworker
func legacyDispatch(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsUnboundedRuntimeOperationAssembly(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"aliases.go": true},
		mixed:     map[string]bool{"contracts.go": true},
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": `package sandboxworker
type JobStartRequestV2 struct{}`,
		"aliases.go": `package sandboxworker
var hiddenOperation = string([]byte{9223372036854775807: 50})`,
	}, policy, "runtime operation assembly")
}

func TestL8WorkerV2GuardRejectsDirectStdlibRuntimeOperationAssembly(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"contracts.go": true}}
	contracts := `package sandboxworker
type JobStartRequestV2 struct{}`
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			name: "strings join",
			source: `package sandboxworker
import text "strings"
var hiddenOperation = text.Join([]string{"job", "_start_", "v", "2"}, "")`,
		},
		{
			name: "fmt sprintf",
			source: `package sandboxworker
import formatting "fmt"
var hiddenOperation = formatting.Sprintf("%s%c%d", "job_status_", 'v', 2)`,
		},
		{
			name: "fmt sprintf recoverable string value",
			source: `package sandboxworker
import formatting "fmt"
var hiddenOperation = formatting.Sprintf("%s_%s_%v", "job", "start", string([]byte{118, 50}))`,
		},
		{
			name: "strings repeat",
			source: `package sandboxworker
import text "strings"
var hiddenOperation = "job_logs_" + text.Repeat("v", 1) + string([]byte{50})`,
		},
		{
			name: "strings join sliced array pointer",
			source: `package sandboxworker
import text "strings"
var hiddenOperation = text.Join((&[3]string{"job", "start", string([]byte{118, 50})})[:], "_")`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"unlisted.go":  fixture.source,
			}, policy, "outside the exact allowlist")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
func JobStartV2Fixture() string { return OperationJobStartV2 }`,
		"legacy.go": `package sandboxworker
import text "strings"
func unrelatedLegacyText(parts []string) string { return text.Join(parts, "") }`,
	}, l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"legacy.go":    true,
	}})
}

func TestL8WorkerV2GuardRecoversBoundedStaticPrecisionAndSliceIdentifiers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"contracts.go": true}}
	v2Root := `package sandboxworker
type JobStartRequestV2 struct{}`
	fixtures := []struct {
		name   string
		source string
	}{
		{
			name: "fixed string precision",
			source: `package sandboxworker
import formatting "fmt"
var hiddenOperation = formatting.Sprintf("%s_%s_%.2s", "job", "start", string([]byte{118, 50, 120}))`,
		},
		{
			name: "package string slice identifier",
			source: `package sandboxworker
import text "strings"
var fragments = []string{"job", "start", string([]byte{118, 50})}
var hiddenOperation = text.Join(fragments, "_")`,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": v2Root,
				"unlisted.go":  fixture.source,
			}, policy, "outside the exact allowlist")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": v2Root,
		"unlisted.go": `package sandboxworker
import (
	formatting "fmt"
	text "strings"
)
var dynamicPrecision = 2
var unrelatedDynamicFormat = formatting.Sprintf("%.*s", dynamicPrecision, "legacy")
var unrelatedIndexedFormat = formatting.Sprintf("%[1]s", "legacy")
var unrelatedOversizedFormat = formatting.Sprintf("%999s", "legacy")
var legacyFragments = []string{"job", "start"}
var unrelatedLegacyJoin = text.Join(legacyFragments, "_")
var oversizedFragments = []string{"", "", "", "", "", "", "", "", "", "", "", "", "", "", "legacy"}
var unrelatedOversizedJoin = text.Join(oversizedFragments, "")`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsIndexDerivedOperationDefinitions(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"state.go":     true,
	}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": `package sandboxworker
type JobStartRequestV2 struct{}`,
		"state.go": `package sandboxworker
var hiddenOperation = map[int]string{
	0: "job_start_" + string([]byte{118, 50}),
}[0]`,
	}, policy, "runtime operation assembly")
}

func TestL8WorkerV2GuardRejectsPositionalOperationFieldAssembly(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"state.go":     true,
	}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": `package sandboxworker
type JobResolveRequestV2 struct{}`,
		"state.go": `package sandboxworker
import text "strings"
type runtimeRequest struct {
	Operation string
	Payload   string
}
var hiddenRequest = runtimeRequest{
	text.Join([]string{"job", "_resolve_", "v", "2"}, ""),
	"safe",
}`,
	}, policy, "runtime operation assembly")
}

func TestL8WorkerV2GuardRejectsRuntimeOperationMatchExpressions(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
type JobStatusRequestV2 struct{}`
	shared := `package sandboxworker
import processapi "os"
type runtimeRequest struct { Operation string }
func forbiddenMatchedHelper() { _, _ = processapi.StartProcess("worker", nil, nil) }`
	for _, fixture := range []struct {
		name string
		body string
	}{
		{
			name: "comparison operand",
			body: `if request.Operation == text.Join([]string{"job_status_", "v", "2"}, "") {
		forbiddenMatchedHelper()
	}`,
		},
		{
			name: "switch case",
			body: `switch request.Operation {
	case text.Join([]string{"job_logs_", "v", "2"}, ""):
		forbiddenMatchedHelper()
	}`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"handler.go": `package sandboxworker
import text "strings"
func legacyDispatch(request runtimeRequest) {
	` + fixture.body + `
}`,
				"shared.go": shared,
			}, policy, "runtime operation assembly")
		})
	}
}

func TestL8WorkerV2GuardRejectsRuntimeOperationMatchAliases(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	for _, fixture := range []struct {
		name string
		body string
	}{
		{
			name: "comparison alias",
			body: `if current == text.Join([]string{"job_start_", "v", "2"}, "") {}`,
		},
		{
			name: "switch alias",
			body: `switch current {
	case text.Join([]string{"job_resolve_", "v", "2"}, ""):
	}`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": `package sandboxworker
import text "strings"
type runtimeAliasRequest struct { Operation string }
func JobStartV2Fixture(request runtimeAliasRequest) {
	current := request.Operation
	` + fixture.body + `
}`,
			}, policy, "runtime operation assembly")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import text "strings"
type Operation string
func JobResolveV2Fixture(op Operation) {
	if op == Operation(text.Join([]string{"job_resolve_", "v", "2"}, "")) {}
}`,
	}, policy, "runtime operation assembly")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
type safeAliasRequest struct { Operation string }
func JobStatusV2Fixture(request safeAliasRequest) {
	current := request.Operation
	_ = current
}`,
	}, policy)
}

func TestL8WorkerV2GuardRecognizesOperationTypeAliasesBeforeUnaliasing(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import text "strings"
type Operation = string
func JobStartV2Fixture(current Operation) {
	if current == text.Join([]string{"job_start_", "v", "2"}, "") {}
}`,
	}, policy, "runtime operation assembly")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import text "strings"
type Payload = string
func JobResolveV2Fixture(current Payload) {
	if current == text.Join([]string{"job_resolve_", "v", "2"}, "") {}
}`,
	}, policy)
}

func TestL8WorkerV2GuardTracksBoundedOperationStorageFlow(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
	}{
		{
			name: "helper return alias",
			source: `package sandboxworker
import text "strings"
type request struct{ Operation string }
func selectCurrent(req request) (string, bool) { return req.Operation, true }
func JobStartV2Fixture(req request) {
	current, ok := selectCurrent(req)
	_ = ok
	if current == text.Join([]string{"job_start_", "v", "2"}, "") {}
}`,
		},
		{
			name: "tuple component to explicit target",
			source: `package sandboxworker
import text "strings"
func runtimePair() (string, error) {
	return text.Join([]string{"job_start_", "v", "2"}, ""), nil
}
func JobStartV2Fixture() {
	operation, err := runtimePair()
	_, _ = operation, err
}`,
		},
		{
			name: "differently named field storage",
			source: `package sandboxworker
import text "strings"
type request struct{ Operation string }
type holder struct{ Current string }
func JobStartV2Fixture(req request) {
	var state holder
	state.Current = req.Operation
	switch state.Current {
	case text.Join([]string{"job_start_", "v", "2"}, ""):
	}
}`,
		},
		{
			name: "indexed slice storage",
			source: `package sandboxworker
import text "strings"
type request struct{ Operation string }
func JobStartV2Fixture(req request) {
	values := make([]string, 1)
	values[0] = req.Operation
	if values[0] == text.Join([]string{"job_start_", "v", "2"}, "") {}
}`,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{"job_v2_fixture.go": fixture.source}, policy, "runtime operation assembly")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import text "strings"
type request struct{ Operation string }
func JobResolveV2Fixture(req request) {
	safe, current := "safe", req.Operation
	_ = safe
	switch current {
	case text.Join([]string{"job_resolve_", "v", "2"}, ""):
	}
}`,
	}, policy, "runtime operation assembly")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
type request struct{ Operation string }
type holder struct{ Current string }
func selectCurrent(req request) (string, bool) { return req.Operation, true }
func runtimePair(req request) (string, error) { return req.Operation, nil }
func JobStatusV2Fixture(req request) {
	current, ok := selectCurrent(req)
	payload, err := runtimePair(req)
	var state holder
	state.Current = req.Operation
	values := make([]string, 1)
	values[0] = req.Operation
	_, _, _, _, _ = current, ok, payload, err, values
}`,
	}, policy)
}

func TestL8WorkerV2GuardConstantValueTaintClosesChainsAndUnlistedRoots(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"chain.go":     true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`
	shared := `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`

	t.Run("cross-file alias chain", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"contracts.go": contracts,
			"aliases.go": `package sandboxworker
const hiddenRoot = "job_resolve_" + "v" + "2"`,
			"chain.go": `package sandboxworker
const hiddenAlias = ((hiddenRoot))`,
			"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == hiddenAlias { forbiddenRoutedHelper() }
}`,
			"shared.go": shared,
		}, policy, "net/http")
	})

	t.Run("inherited constant", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"contracts.go": contracts,
			"aliases.go": `package sandboxworker
const (
	hiddenRoot = "job_cancel_" + "v" + "2"
	hiddenInherited
)`,
			"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == hiddenInherited { forbiddenRoutedHelper() }
}`,
			"shared.go": shared,
		}, policy, "net/http")
	})

	t.Run("unlisted semantic root", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"contracts.go": contracts,
			"unlisted.go": `package sandboxworker
const hiddenOperation = "job_logs_v\u0032"`,
		}, policy, "outside the exact allowlist")
	})

	t.Run("unlisted semantic root without visible root", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"unlisted.go": `package sandboxworker
const hiddenOperation = "job_start_" + "v" + "2"`,
		}, policy, "outside the exact allowlist")
	})
}

func TestL8WorkerV2GuardExactOperationValuesDoNotOvertaintV1Siblings(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`,
		"aliases.go": `package sandboxworker
const hiddenRoutedOperation, hiddenLegacyOperation = "job_status_" + "v" + "2", string(("job_" + "status"))`,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
}

func TestL8WorkerV2GuardGroupedValueSpecsRemainSemanticallyPrecise(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`
	aliases := `package sandboxworker
const routedOperation, legacyOperation = OperationJobStartV2, "job_start"`

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"handler.go": `package sandboxworker
func JobStartHandler(operation string) {
	if operation == routedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == legacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"handler.go": `package sandboxworker
func JobStartHandler(operation string) {
	if operation == routedOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	for _, fixture := range []struct {
		name    string
		aliases string
	}{
		{name: "one RHS returning multiple values", aliases: `package sandboxworker
var routedOperation, legacyOperation = groupedOperations()
func groupedOperations() (string, string) { return OperationJobStartV2, "job_start" }`},
		{name: "one explicit type for uninitialized names", aliases: `package sandboxworker
type routedOperationType = JobOperationV2
var routedOperation, legacyOperation routedOperationType`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			fixtureContracts := contracts
			if strings.Contains(fixture.aliases, "JobOperationV2") {
				fixtureContracts += "\ntype JobOperationV2 string"
			}
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": fixtureContracts,
				"aliases.go":   fixture.aliases,
				"handler.go": `package sandboxworker
func legacyHandler() { _ = legacyOperation; forbiddenHelper() }`,
				"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
			}, policy, "net/http")
		})
	}
}

func TestL8WorkerV2GuardNormalizesImplicitConstValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
type JobOperationV2 string`

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
const (
	routedOperation = OperationJobStartV2
	hiddenOperation
	chainedOperation
)`,
		"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == chainedOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
const (
	routedOperation JobOperationV2 = "job_start"
	hiddenOperation
)`,
		"handler.go": `package sandboxworker
func dispatch(operation JobOperationV2) {
	if operation == hiddenOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
const (
	routedOperation = OperationJobStartV2
	hiddenRoutedOperation
	legacyOperation = "job_start"
	hiddenLegacyOperation
)`,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	multiNameAliases := `package sandboxworker
const (
	routedOperation, legacyOperation = OperationJobStartV2, "job_start"
	hiddenRoutedOperation, hiddenLegacyOperation
)`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   multiNameAliases,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   multiNameAliases,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	for _, fixture := range []struct {
		name    string
		aliases string
		want    string
	}{
		{
			name: "implicit values before an expression list",
			aliases: `package sandboxworker
const (
	hiddenOperation
	routedOperation = OperationJobStartV2
)`,
			want: "before a preceding expression list",
		},
		{
			name: "inherited cardinality mismatch",
			aliases: `package sandboxworker
const (
	routedOperation, legacyOperation = OperationJobStartV2, "job_start"
	ambiguousOperation
)`,
			want: "ambiguous name/value cardinality",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   fixture.aliases,
			}, policy, fixture.want)
		})
	}
}

func TestL8WorkerV2GuardMixedSwitchesAuditCompleteReachableControlFlow(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"handler.go": true}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation string) {
	switch operation {
	case "job_start_v2":
		safeHelper()
	}
}
func safeHelper() {}
func unrelatedLegacyDispatch() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	initializers := []struct {
		name   string
		source string
	}{
		{name: "value switch init", source: `package sandboxworker
import httpalias "net/http"
func forbiddenInit() int { _, _ = httpalias.Get("https://authority.example.invalid"); return 1 }
func dispatch(operation string) {
	switch initialized := forbiddenInit(); operation {
	case "job_start_v2": _ = initialized
	}
}`},
		{name: "type switch init", source: `package sandboxworker
import httpalias "net/http"
type JobStartV2Fixture struct{}
func forbiddenInit() int { _, _ = httpalias.Get("https://authority.example.invalid"); return 1 }
func dispatch(value any) {
	switch initialized := forbiddenInit(); value.(type) {
	case JobStartV2Fixture: _ = initialized
	}
}`},
	}
	for _, fixture := range initializers {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{"handler.go": fixture.source}, policy, "net/http")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation string) {
	switch operation {
	case "job_start_v2":
		fallthrough
	case "job_start":
		_, _ = httpalias.Get("https://authority.example.invalid")
	}
}`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation, phase string) {
	switch operation {
	case "job_start_v2":
	}
	switch phase {
	case "legacy_phase":
		_, _ = httpalias.Get("https://authority.example.invalid")
	}
}`,
	}, policy, "net/http")
}

func TestL8WorkerV2GuardResolvesExactReceiverMethodObjects(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
import execalias "os/exec"
type safeReceiver struct{}
func (safeReceiver) dispatch() {}
type unsafeReceiver struct{}
func (unsafeReceiver) dispatch() { _ = execalias.Command("forbidden-live-helper") }`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() { safeReceiver{}.dispatch() }`,
		"shared.go": shared,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() { unsafeReceiver{}.dispatch() }`,
		"shared.go": shared,
	}, policy, "os/exec")
}

func TestL8WorkerV2GuardRejectsInterfaceAndFunctionValueDispatch(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
type dispatcher interface { dispatch() }
type concreteDispatcher struct{}
func (concreteDispatcher) dispatch() {}
type embeddedInterfaceDispatcher struct { dispatcher }
type embeddedConcreteDispatcher struct { concreteDispatcher }
func genericDispatch[T any]() {}
func genericDispatchPair[A, B any]() {}`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() {
	concreteDispatcher{}.dispatch()
	genericDispatch[int]()
	genericDispatchPair[int, string]()
}
func JobResolveV2Fixture(value embeddedConcreteDispatcher, pointer *embeddedConcreteDispatcher) {
	value.dispatch()
	pointer.dispatch()
}
func JobStatusV2Fixture(value concreteDispatcher) { concreteDispatcher.dispatch(value) }`,
		"shared.go": shared,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture(value dispatcher) { value.dispatch() }`,
		"shared.go": shared,
	}, policy, "interface dispatch")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
type processTerminator interface { Kill() error }
func JobStartV2Fixture(value processTerminator) { terminate := value.Kill; _ = terminate }`,
		"shared.go": shared,
	}, policy, "interface method-value")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture(value embeddedInterfaceDispatcher) { dispatch := value.dispatch; _ = dispatch }`,
		"shared.go": shared,
	}, policy, "interface method-value")
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{name: "promoted interface method on value", source: `package sandboxworker
func JobResolveV2Fixture(value embeddedInterfaceDispatcher) { value.dispatch() }`},
		{name: "promoted interface method on pointer", source: `package sandboxworker
func JobStatusV2Fixture(value *embeddedInterfaceDispatcher) { value.dispatch() }`},
		{name: "promoted interface method expression", source: `package sandboxworker
func JobLogsV2Fixture(value embeddedInterfaceDispatcher) { embeddedInterfaceDispatcher.dispatch(value) }`},
		{name: "type parameter interface dispatch", source: `package sandboxworker
func JobCancelV2Fixture[T dispatcher](value T) { value.dispatch() }`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
				"shared.go":         shared,
			}, policy, "interface dispatch")
		})
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobLogsV2Fixture() { fn := crossFileHelper; fn() }`,
		"shared.go": `package sandboxworker
func crossFileHelper() {}`,
	}, policy, "function-value dispatch")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobCancelV2Fixture() { genericForbidden[int]() }`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func genericForbidden[T any]() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")
}

func TestL8WorkerV2GuardRejectsImplicitInterfaceCallbacks(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
import (
	formatting "fmt"
	processapi "os"
)
type implicitRenderer struct{}
func (implicitRenderer) String() string {
	_, _ = processapi.StartProcess("worker", nil, nil)
	return ""
}
func renderThroughWrapper(value any) string { return formatting.Sprint(value) }`
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			name: "renamed fmt import invokes Stringer",
			source: `package sandboxworker
import formatting "fmt"
func JobStartV2Fixture() { _ = formatting.Sprint(implicitRenderer{}) }`,
		},
		{
			name: "local any wrapper invokes Stringer",
			source: `package sandboxworker
func JobResolveV2Fixture() { _ = renderThroughWrapper(implicitRenderer{}) }`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
				"shared.go":         shared,
			}, policy, "implicit interface callback")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
type inertRenderer struct{}
func JobStatusV2Fixture() { _ = formatting.Sprint("safe", inertRenderer{}) }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsPromotedCallbacksOnAnonymousValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
func JobStartV2Fixture() {
	_ = formatting.Sprint(struct{ promotedRenderer }{})
}`,
		"shared.go": `package sandboxworker
import processapi "os"
type promotedRenderer struct{}
func (promotedRenderer) String() string {
	_, _ = processapi.StartProcess("worker", nil, nil)
	return ""
}`,
	}, policy, "implicit interface callback")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
func JobResolveV2Fixture() { _ = formatting.Sprint(struct{ Value string }{Value: "safe"}) }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsCallbacksInVariadicSliceExpansion(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
func JobStatusV2Fixture() {
	_ = formatting.Sprint([]any{variadicRenderer{}}...)
}`,
		"shared.go": `package sandboxworker
import processapi "os"
type variadicRenderer struct{}
func (variadicRenderer) String() string {
	_, _ = processapi.StartProcess("worker", nil, nil)
	return ""
}`,
	}, policy, "implicit interface callback")
}

func TestL8WorkerV2GuardRejectsCallbacksNestedInFormattingContainers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
import processapi "os"
type containerRenderer struct{}
func (containerRenderer) String() string {
	_, _ = processapi.StartProcess("worker", nil, nil)
	return ""
}`
	for _, fixture := range []struct {
		name     string
		argument string
	}{
		{name: "slice element", argument: `[]containerRenderer{{}}`},
		{name: "array element", argument: `[1]containerRenderer{{}}`},
		{name: "map value", argument: `map[string]containerRenderer{"value": containerRenderer{}}`},
		{name: "pointer field", argument: `&struct{ Value containerRenderer }{}`},
		{name: "struct field", argument: `struct{ Value containerRenderer }{}`},
		{name: "interface slice element", argument: `[]any{containerRenderer{}}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
func JobCancelV2Fixture() { _ = formatting.Sprint(` + fixture.argument + `) }`,
				"shared.go": shared,
			}, policy, "implicit interface callback")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
type inertCycle struct { Next *inertCycle }
func JobLogsV2Fixture() {
	_ = formatting.Sprint(
		[]struct{ Value string }{{Value: "safe"}},
		map[string]int{"safe": 1},
		&inertCycle{},
	)
}`,
	}, policy)
}

func TestL8WorkerV2GuardAuditsPackageInitializers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"init.go": true},
		mixed:     map[string]bool{"handler.go": true},
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
func JobStartV2Fixture() {}`,
		"init.go": `package sandboxworker
import httpalias "net/http"
func init() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": `package sandboxworker
func JobResolveV2Fixture() {}`,
		"unlisted_init.go": `package sandboxworker
func init() {}`,
	}, policy)
}

func TestL8WorkerV2GuardAuditsUnlistedExecutedInitializers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"handler.go": true}}
	v2Root := `package sandboxworker
func JobStartV2Fixture() {}`

	t.Run("direct init body", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": v2Root,
			"unlisted_init.go": `package sandboxworker
import processapi "os"
func init() { processapi.Exit(1) }`,
		}, policy, "os.Exit")
	})

	t.Run("evaluated multi-name package variable", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": v2Root,
			"unlisted_state.go": `package sandboxworker
import processapi "os"
var initializedProcess, initializedProcessErr = processapi.StartProcess("worker", nil, nil)`,
		}, policy, "os.StartProcess")
	})

	t.Run("initializer helper dependency", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": v2Root,
			"unlisted_state.go": `package sandboxworker
import processapi "os"
var initializedProcessErr = startInitializedProcess()
func startInitializedProcess() error {
	_, err := processapi.StartProcess("worker", nil, nil)
	return err
}`,
		}, policy, "os.StartProcess")
	})

	t.Run("immediately invoked function literal", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": v2Root,
			"unlisted_state.go": `package sandboxworker
import processapi "os"
var initializedState = func() int {
	processapi.Exit(1)
	return 0
}()`,
		}, policy, "os.Exit")
	})

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": v2Root,
		"unlisted_state.go": `package sandboxworker
import processapi "os"
var deferredProcess = func() { processapi.Exit(1) }`,
	}, policy)
}

func TestL8WorkerV2GuardDistinguishesStoredAndInvokedNamedInitializers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"handler.go": true}}
	v2Root := `package sandboxworker
func JobStartV2Fixture() {}`

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": v2Root,
		"unlisted_state.go": `package sandboxworker
import processapi "os"
var deferredProcess = stopProcessLater
func stopProcessLater() { processapi.Exit(1) }`,
	}, policy)

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": v2Root,
		"unlisted_state.go": `package sandboxworker
import processapi "os"
var initializedState = startProcessNow()
func startProcessNow() int {
	processapi.Exit(1)
	return 0
}`,
	}, policy, "os.Exit")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": v2Root,
		"unlisted_state.go": `package sandboxworker
import processapi "os"
var processInitializer = startProcessThroughAlias
var initializedState = processInitializer()
func startProcessThroughAlias() int {
	processapi.Exit(1)
	return 0
}`,
	}, policy, "os.Exit")
}

func TestL8WorkerV2GuardAuditsPackageVariableInitializers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"state.go": true},
		mixed:     map[string]bool{"handler.go": true},
	}
	t.Run("reachable initializer", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": `package sandboxworker
func JobStartV2Fixture() {}`,
			"state.go": `package sandboxworker
import httpalias "net/http"
var initializedState = forbiddenInitializer()
func forbiddenInitializer() string {
	_, _ = httpalias.Get("https://authority.example.invalid")
	return ""
}`,
		}, policy, "net/http")
	})

	t.Run("unlisted initializer", func(t *testing.T) {
		l8AssertWorkerV2GuardAllows(t, map[string]string{
			"handler.go": `package sandboxworker
func JobResolveV2Fixture() {}`,
			"unlisted_state.go": `package sandboxworker
var initializedState = safeInitializer()
func safeInitializer() string { return "safe" }`,
		}, policy)
	})

	t.Run("grouped initializer", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": `package sandboxworker
func JobStatusV2Fixture() {}`,
			"state.go": `package sandboxworker
import httpalias "net/http"
var (
	safeState = "safe"
	firstState, secondState = "safe", forbiddenGroupedInitializer()
)
func forbiddenGroupedInitializer() string {
	_, _ = httpalias.Get("https://authority.example.invalid")
	return ""
}`,
		}, policy, "net/http")
	})

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": `package sandboxworker
func JobLogsV2Fixture() {}`,
		"state.go": `package sandboxworker
var (
	safeState = "safe"
	firstState, secondState = "safe", safeGroupedInitializer()
	uninitializedState string
)
func safeGroupedInitializer() string { return "safe" }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsReachedBodylessDeclarations(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			name: "bodyless function",
			source: `package sandboxworker
func hiddenLiveImplementation()
func JobStartV2Fixture() { hiddenLiveImplementation() }`,
		},
		{
			name: "bodyless method",
			source: `package sandboxworker
type hiddenLiveReceiver struct{}
func (hiddenLiveReceiver) dispatch()
func JobResolveV2Fixture() { hiddenLiveReceiver{}.dispatch() }`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, "bodyless declaration")
		})
	}
}

func TestL8WorkerV2GuardRejectsIndexedFunctionValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
	}{
		{name: "map index", source: `package sandboxworker
func indexedHelper() {}
func JobStartV2Fixture(key string) { map[string]func(){"run": indexedHelper}[key]() }`},
		{name: "slice index", source: `package sandboxworker
func indexedHelper() {}
func JobResolveV2Fixture(index int) { []func(){indexedHelper}[index]() }`},
		{name: "array index", source: `package sandboxworker
func indexedHelper() {}
func JobStatusV2Fixture(index int) { [1]func(){indexedHelper}[index]() }`},
		{name: "map alias index", source: `package sandboxworker
type functionMapAlias = map[string]func()
func JobLogsV2Fixture(functions functionMapAlias, key string) { functions[key]() }`},
		{name: "slice defined type index", source: `package sandboxworker
type functionSlice []func()
func JobCancelV2Fixture(functions functionSlice, index int) { functions[index]() }`},
		{name: "array defined type index", source: `package sandboxworker
type functionArray [1]func()
func JobStatusV2Fixture(functions functionArray, index int) { functions[index]() }`},
		{name: "indexed method value", source: `package sandboxworker
type indexedReceiver struct{}
func (indexedReceiver) dispatch() {}
func JobStartV2Fixture(value indexedReceiver) { []func(){value.dispatch}[0]() }`},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, "function-value dispatch")
		})
	}
}

func TestL8WorkerV2GuardRejectsReflectiveDispatch(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
	}{
		{name: "aliased function call", source: `package sandboxworker
import reflectalias "reflect"
func JobStartV2Fixture(function any) { reflectalias.ValueOf(function).Call(nil) }`},
		{name: "aliased method call slice", source: `package sandboxworker
import reflectalias "reflect"
func JobStatusV2Fixture(value any) { reflectalias.ValueOf(value).MethodByName("dispatch").CallSlice(nil) }`},
		{name: "dot imported call", source: `package sandboxworker
import . "reflect"
func JobLogsV2Fixture(function any) { ValueOf(function).Call(nil) }`},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, "reflect")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
type concreteReflectControl struct{}
func (concreteReflectControl) dispatch() {}
func JobCancelV2Fixture() { concreteReflectControl{}.dispatch() }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsSemanticProcessAndRawSyscallSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "renamed os start process capture",
			source: `package sandboxworker
import processapi "os"
func JobStartV2Fixture() { start := processapi.StartProcess; _ = start }`,
			want: "os.StartProcess",
		},
		{
			name: "dot imported os exit",
			source: `package sandboxworker
import . "os"
func JobResolveV2Fixture() { Exit(1) }`,
			want: "os.Exit",
		},
		{
			name: "os find process capture",
			source: `package sandboxworker
import processapi "os"
func JobStatusV2Fixture() { find := processapi.FindProcess; _ = find }`,
			want: "os.FindProcess",
		},
		{
			name: "os process kill method expression",
			source: `package sandboxworker
import processapi "os"
func JobLogsV2Fixture() { kill := (*processapi.Process).Kill; _ = kill }`,
			want: "os.Kill",
		},
		{
			name: "os process signal method expression",
			source: `package sandboxworker
import processapi "os"
func JobCancelV2Fixture() { signal := (*processapi.Process).Signal; _ = signal }`,
			want: "os.Signal",
		},
		{
			name: "os process wait method expression",
			source: `package sandboxworker
import processapi "os"
func JobStartV2Fixture() { wait := (*processapi.Process).Wait; _ = wait }`,
			want: "os.Wait",
		},
		{
			name: "os process release method expression",
			source: `package sandboxworker
import processapi "os"
func JobResolveV2Fixture() { release := (*processapi.Process).Release; _ = release }`,
			want: "os.Release",
		},
		{
			name: "os process interface method value",
			source: `package sandboxworker
import processapi "os"
type hiddenWaiter interface { Wait() (*processapi.ProcessState, error) }
func JobStatusV2Fixture(process hiddenWaiter) { wait := process.Wait; _ = wait }`,
			want: "os.ProcessState",
		},
		{
			name: "os environment capture",
			source: `package sandboxworker
import environment "os"
func JobLogsV2Fixture() { lookup := environment.LookupEnv; _ = lookup }`,
			want: "os.LookupEnv",
		},
		{
			name: "renamed syscall raw syscall capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.RawSyscall; _ = call }`,
			want: "syscall.RawSyscall",
		},
		{
			name: "syscall syscall capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.Syscall; _ = call }`,
			want: "syscall.Syscall",
		},
		{
			name: "syscall raw syscall six capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.RawSyscall6; _ = call }`,
			want: "syscall.RawSyscall6",
		},
		{
			name: "syscall syscall six capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.Syscall6; _ = call }`,
			want: "syscall.Syscall6",
		},
		{
			name: "dot imported syscall fork exec",
			source: `package sandboxworker
import . "syscall"
func JobStartV2Fixture() { start := ForkExec; _ = start }`,
			want: "syscall.ForkExec",
		},
		{
			name: "syscall network primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobResolveV2Fixture() { socket := kernel.Socket; _ = socket }`,
			want: "syscall.Socket",
		},
		{
			name: "syscall memory primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobStatusV2Fixture() { mapping := kernel.Mmap; _ = mapping }`,
			want: "syscall.Mmap",
		},
		{
			name: "syscall exec primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobStatusV2Fixture() { execute := kernel.Exec; _ = execute }`,
			want: "syscall.Exec",
		},
		{
			name: "syscall kill primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobStatusV2Fixture() { signal := kernel.Kill; _ = signal }`,
			want: "syscall.Kill",
		},
		{
			name: "renamed unix raw syscall capture",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobLogsV2Fixture() { call := kernel.RawSyscall; _ = call }`,
			want: "golang.org/x/sys/unix.RawSyscall",
		},
		{
			name: "unix syscall capture",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobLogsV2Fixture() { call := kernel.Syscall; _ = call }`,
			want: "golang.org/x/sys/unix.Syscall",
		},
		{
			name: "unix raw syscall six capture",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobLogsV2Fixture() { call := kernel.RawSyscall6; _ = call }`,
			want: "golang.org/x/sys/unix.RawSyscall6",
		},
		{
			name: "unix network primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobCancelV2Fixture() { socket := kernel.Socket; _ = socket }`,
			want: "golang.org/x/sys/unix.Socket",
		},
		{
			name: "unix memory primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { mapping := kernel.Mmap; _ = mapping }`,
			want: "golang.org/x/sys/unix.Mmap",
		},
		{
			name: "unix exec primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { execute := kernel.Exec; _ = execute }`,
			want: "golang.org/x/sys/unix.Exec",
		},
		{
			name: "unix kill primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { signal := kernel.Kill; _ = signal }`,
			want: "golang.org/x/sys/unix.Kill",
		},
		{
			name: "unix namespace mount primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { mount := kernel.Mount; _ = mount }`,
			want: "golang.org/x/sys/unix.Mount",
		},
		{
			name: "unsafe pointer conversion",
			source: `package sandboxworker
import memory "unsafe"
func JobResolveV2Fixture() { _ = memory.Pointer(nil) }`,
			want: "unsafe.Pointer",
		},
		{
			name: "dot imported unsafe size",
			source: `package sandboxworker
import . "unsafe"
func JobStatusV2Fixture(value int) { _ = Sizeof(value) }`,
			want: "unsafe.Sizeof",
		},
		{
			name: "blank unsafe linkname escape",
			source: `package sandboxworker
import _ "unsafe"
//go:linkname hiddenProcessStart runtime.fork
func hiddenProcessStart()
func JobStatusV2Fixture() { hiddenProcessStart() }`,
			want: "unsafe",
		},
		{
			name: "plugin open capture",
			source: `package sandboxworker
import dynamiccode "plugin"
func JobLogsV2Fixture() { open := dynamiccode.Open; _ = open }`,
			want: "plugin.Open",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, fixture.want)
		})
	}
}

func TestL8WorkerV2GuardRejectsProcessGlobalDirectoryAndFatalSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "os chdir",
			source: `package sandboxworker
import processapi "os"
func JobStartV2Fixture() { _ = processapi.Chdir("work") }`,
			want: "os.Chdir",
		},
		{
			name: "os file chdir",
			source: `package sandboxworker
import processapi "os"
func JobResolveV2Fixture(file *processapi.File) { _ = file.Chdir() }`,
			want: "os.Chdir",
		},
		{
			name: "log fatal",
			source: `package sandboxworker
import logging "log"
func JobStatusV2Fixture() { logging.Fatal("stop") }`,
			want: "log.Fatal",
		},
		{
			name: "log fatalf",
			source: `package sandboxworker
import logging "log"
func JobLogsV2Fixture() { logging.Fatalf("stop: %s", "now") }`,
			want: "log.Fatalf",
		},
		{
			name: "log fatalln",
			source: `package sandboxworker
import logging "log"
func JobCancelV2Fixture() { logging.Fatalln("stop") }`,
			want: "log.Fatalln",
		},
		{
			name: "logger fatal method",
			source: `package sandboxworker
import logging "log"
func JobStartV2Fixture(logger *logging.Logger) { logger.Fatal("stop") }`,
			want: "log.Fatal",
		},
		{
			name: "logger fatalf method expression",
			source: `package sandboxworker
import logging "log"
func JobResolveV2Fixture() { fatal := (*logging.Logger).Fatalf; _ = fatal }`,
			want: "log.Fatalf",
		},
		{
			name: "logger fatalln method",
			source: `package sandboxworker
import logging "log"
func JobStatusV2Fixture(logger *logging.Logger) { logger.Fatalln("stop") }`,
			want: "log.Fatalln",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, fixture.want)
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import (
	logging "log"
	filesystem "os"
	kernel "syscall"
)
func JobStartV2Store(path string, owner *kernel.Stat_t) error {
	logging.Print("opening durable state")
	_ = owner.Uid
	file, err := filesystem.OpenFile(path, filesystem.O_CREATE|filesystem.O_RDWR, 0o600)
	if err != nil { return err }
	defer file.Close()
	if err := kernel.Flock(int(file.Fd()), kernel.LOCK_EX|kernel.LOCK_NB); err != nil { return err }
	if err := file.Sync(); err != nil { return err }
	return kernel.Flock(int(file.Fd()), kernel.LOCK_UN)
}`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsImportOnlyDynamicRuntimeSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "blank unsafe import",
			source: `package sandboxworker
import _ "unsafe"
func JobStartV2Fixture() {}`,
			want: "unsafe",
		},
		{
			name: "blank plugin import",
			source: `package sandboxworker
import _ "plugin"
func JobResolveV2Fixture() {}`,
			want: "plugin",
		},
		{
			name: "blank signal import",
			source: `package sandboxworker
import _ "os/signal"
func JobStatusV2Fixture() {}`,
			want: "os/signal",
		},
		{
			name: "renamed signal import",
			source: `package sandboxworker
import notifications "os/signal"
func JobLogsV2Fixture() { stop := notifications.Stop; _ = stop }`,
			want: "os/signal",
		},
		{
			name: "renamed runtime import",
			source: `package sandboxworker
import processruntime "runtime"
func JobCancelV2Fixture() { exit := processruntime.Goexit; _ = exit }`,
			want: "runtime",
		},
		{
			name: "dot runtime debug import",
			source: `package sandboxworker
import . "runtime/debug"
func JobStartV2Fixture() { SetTraceback("all") }`,
			want: "runtime/debug",
		},
		{
			name: "blank runtime pprof import",
			source: `package sandboxworker
import _ "runtime/pprof"
func JobResolveV2Fixture() {}`,
			want: "runtime/pprof",
		},
		{
			name: "blank runtime trace import",
			source: `package sandboxworker
import _ "runtime/trace"
func JobStatusV2Fixture() {}`,
			want: "runtime/trace",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, fixture.want)
		})
	}
}

func TestL8WorkerV2GuardAuditsForbiddenImportsInUnlistedPackageGlobals(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"handler.go": true}}
	v2Root := `package sandboxworker
func JobStartV2Fixture() {}`

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": v2Root,
		"unlisted_plugin.go": `package sandboxworker
import _ "plugin"`,
	}, policy, "plugin")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": v2Root,
		"unlisted_legacy.go": `package sandboxworker
import (
	_ "image/png"
	httpalias "net/http"
)
func unrelatedLegacyRequest() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
}

func TestL8WorkerV2GuardReportsForbiddenImportsDeterministically(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	sources := map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import (
	_ "unsafe"
	_ "plugin"
)
func JobStartV2Fixture() {}`,
	}
	var first string
	for iteration := 0; iteration < 256; iteration++ {
		err := l8AuditWorkerV2Sources(sources, policy)
		if err == nil {
			t.Fatal("guard accepted forbidden import fixture")
		}
		if !strings.Contains(err.Error(), `"plugin"`) {
			t.Fatalf("iteration %d reported %q; want stable lexicographically first forbidden import plugin", iteration, err)
		}
		if iteration == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("iteration %d diagnostic = %q, first diagnostic = %q", iteration, err, first)
		}
	}
}

func TestL8WorkerV2GuardClosesSemanticExternalSurfaceDependencies(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"handler.go": true,
		"helper.go":  true,
		"capture.go": true,
	}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
func JobStartV2Fixture() { hiddenHelper() }`,
		"helper.go": `package sandboxworker
func hiddenHelper() { _ = hiddenKernelCall }`,
		"capture.go": `package sandboxworker
import kernel "syscall"
var hiddenKernelCall = kernel.RawSyscall`,
	}, policy, "syscall.RawSyscall")
}

func TestL8WorkerV2GuardAllowsExactDurableStoreFileAndLockSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{
		"job_v2_store.go":      true,
		"job_v2_unix_store.go": true,
	}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_store.go": `package sandboxworker
import (
	filesystem "os"
	kernel "syscall"
)
const semanticGuardDocumentation = "os.StartProcess syscall.RawSyscall unsafe.Pointer plugin.Open"
func JobStartV2Store(path string, owner *kernel.Stat_t) error {
	_ = semanticGuardDocumentation
	_ = owner.Uid
	file, err := filesystem.OpenFile(path, filesystem.O_CREATE|filesystem.O_RDWR, 0o600)
	if err != nil { return err }
	defer file.Close()
	if err := kernel.Flock(int(file.Fd()), kernel.LOCK_EX|kernel.LOCK_NB); err != nil && err != kernel.EINTR { return err }
	if err := file.Sync(); err != nil { return err }
	if err := kernel.Flock(int(file.Fd()), kernel.LOCK_UN); err != nil { return err }
	if _, err := filesystem.ReadFile(path); err != nil { return err }
	if err := filesystem.Rename(path, path+".json"); err != nil { return err }
	return filesystem.Remove(path+".json")
}`,
		"job_v2_unix_store.go": `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobResolveV2Store(fd int, owner *kernel.Stat_t) error {
	_ = owner.Uid
	if err := kernel.Flock(fd, kernel.LOCK_EX|kernel.LOCK_NB); err != nil { return err }
	return kernel.Flock(fd, kernel.LOCK_UN)
}`,
	}, policy)
}

func TestL8WorkerV2GuardKeepsSemanticLiveSurfaceChecksOutOfV1Siblings(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"mixed.go": true}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"mixed.go": `package sandboxworker
import (
	processapi "os"
	notifications "os/signal"
	kernel "syscall"
	dynamiccode "plugin"
	processruntime "runtime"
	memory "unsafe"
)
func JobStartV2Fixture() {}
func unrelatedV1() {
	_ = processapi.Exit
	_ = notifications.Stop
	_ = kernel.RawSyscall
	_ = dynamiccode.Open
	_ = processruntime.Gosched
	_ = memory.Pointer(nil)
}`,
	}, policy)
}

func TestL8WorkerV2GuardRequiresEveryReachedFileOnExactAllowlist(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStatusV2Fixture() { crossFileHelper() }`,
		"unlisted_helper.go": `package sandboxworker
func crossFileHelper() {}`,
	}, policy, "outside the exact allowlist")
}

func l8AssertWorkerV2GuardAllows(t *testing.T, sources map[string]string, policy l8WorkerV2GuardPolicy) {
	t.Helper()
	if err := l8AuditWorkerV2Sources(sources, policy); err != nil {
		t.Fatalf("guard rejected safe fixture: %v", err)
	}
}

func l8AssertWorkerV2GuardRejects(t *testing.T, sources map[string]string, policy l8WorkerV2GuardPolicy, want string) {
	t.Helper()
	err := l8AuditWorkerV2Sources(sources, policy)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("guard error = %v, want rejection containing %q", err, want)
	}
}

func TestL8WorkerV2SourceGuardsPrincipalCannotBeDecodedFromJSON(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		sources[path] = l8ReadWorkerSource(t, path)
	}
	if err := l8AuditWorkerV2PrivateJSONIdentityTags(sources); err != nil {
		t.Fatal(err)
	}
}

func TestL8WorkerV2PrivateJSONIdentityExceptionsAreExact(t *testing.T) {
	allowed := map[string]string{
		"job_v2_helpers.go": `package sandboxworker
type jobRequestIdentityV2 struct {
	DriverID string ` + "`json:\"driverId\"`" + `
	PrincipalID string ` + "`json:\"principalId\"`" + `
	DaemonGeneration string ` + "`json:\"daemonGeneration\"`" + `
}`,
		"job_store_v2.go": `package sandboxworker
type storedJobStateV2 struct {
	PrincipalID string ` + "`json:\"principalId\"`" + `
	DaemonGeneration string ` + "`json:\"daemonGeneration\"`" + `
}`,
	}
	if err := l8AuditWorkerV2PrivateJSONIdentityTags(allowed); err != nil {
		t.Fatalf("exact private identity exceptions were rejected: %v", err)
	}

	for _, tt := range []struct {
		name     string
		path     string
		typeName string
		field    string
		tag      string
		extra    string
	}{
		{name: "hash identity in wrong file", path: "job_v2_types.go", typeName: "jobRequestIdentityV2", field: "PrincipalID", tag: "principalId"},
		{name: "hash identity on wrong type", path: "job_v2_helpers.go", typeName: "jobRequestIdentityV2Alias", field: "PrincipalID", tag: "principalId"},
		{name: "hash identity on exported type", path: "job_v2_helpers.go", typeName: "JobRequestIdentityV2", field: "PrincipalID", tag: "principalId"},
		{name: "hash identity with wrong field", path: "job_v2_helpers.go", typeName: "jobRequestIdentityV2", field: "AuthenticatedPrincipal", tag: "principalId"},
		{name: "hash identity with wrong tag", path: "job_v2_helpers.go", typeName: "jobRequestIdentityV2", field: "PrincipalID", tag: "principalID"},
		{name: "daemon identity with wrong field", path: "job_v2_helpers.go", typeName: "jobRequestIdentityV2", field: "Generation", tag: "daemonGeneration"},
		{name: "daemon identity with wrong tag", path: "job_v2_helpers.go", typeName: "jobRequestIdentityV2", field: "DaemonGeneration", tag: "daemon_generation"},
		{name: "extra public response surface", path: "job_v2_helpers.go", typeName: "jobRequestIdentityV2", field: "PrincipalID", tag: "principalId", extra: "\ntype Response struct { PrincipalID string `json:\"principalId\"` }\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := "package sandboxworker\ntype " + tt.typeName + " struct { " + tt.field + " string `json:\"" + tt.tag + "\"` }\n" + tt.extra
			err := l8AuditWorkerV2PrivateJSONIdentityTags(map[string]string{tt.path: source})
			if err == nil || !strings.Contains(err.Error(), "private server identity") {
				t.Fatalf("identity tag audit error = %v, want private server identity rejection", err)
			}
		})
	}
}

func l8AuditWorkerV2PrivateJSONIdentityTags(sources map[string]string) error {
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		source := sources[path]
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		for _, declaration := range parsed.Decls {
			generated, ok := declaration.(*ast.GenDecl)
			if !ok || generated.Tok != token.TYPE {
				continue
			}
			for _, spec := range generated.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					tag, unquoteErr := strconv.Unquote(field.Tag.Value)
					if unquoteErr != nil {
						return fmt.Errorf("unquote field tag in %s: %w", path, unquoteErr)
					}
					jsonTag := reflectStructTagJSON(tag)
					normalizedTag := strings.ToLower(jsonTag)
					if strings.Contains(normalizedTag, "peeruid") || strings.Contains(normalizedTag, "peergid") {
						return fmt.Errorf("production field in %s exposes peer credential through JSON tag %q", path, jsonTag)
					}
					privateDurableIdentity := filepath.Base(path) == "job_store_v2.go" && typeSpec.Name.Name == "storedJobStateV2" && len(field.Names) == 1 &&
						(jsonTag == "principalId" && field.Names[0].Name == "PrincipalID" || jsonTag == "daemonGeneration" && field.Names[0].Name == "DaemonGeneration")
					privateHashIdentity := filepath.Base(path) == "job_v2_helpers.go" && typeSpec.Name.Name == "jobRequestIdentityV2" && len(field.Names) == 1 &&
						(jsonTag == "principalId" && field.Names[0].Name == "PrincipalID" || jsonTag == "daemonGeneration" && field.Names[0].Name == "DaemonGeneration")
					if privateDurableIdentity || privateHashIdentity {
						continue
					}
					if strings.Contains(normalizedTag, "principal") || strings.Contains(normalizedTag, "daemongeneration") || strings.Contains(normalizedTag, "daemon_generation") {
						return fmt.Errorf("production field in %s exposes private server identity outside exact private identity types through JSON tag %q", path, jsonTag)
					}
				}
			}
		}
	}
	return nil
}

func reflectStructTagJSON(tag string) string {
	for _, part := range strings.Fields(tag) {
		if strings.HasPrefix(part, `json:"`) {
			value := strings.TrimPrefix(part, `json:"`)
			return strings.TrimSuffix(value, `"`)
		}
	}
	return ""
}

func l8ReadWorkerSource(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
