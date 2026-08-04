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
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"protocol_decode.go": `package sandboxworker
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
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	if maxBytes <= 0 || maxBytes > 1<<20 { return errors.New("worker request limit is invalid") }
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil { return err }
	if int64(len(raw)) > maxBytes { return errors.New("worker request exceeds limit") }
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
func decodeWorkerRequest(reader io.Reader, maxBytes int64) (Request, error) {
	var output Request
	if err := decodeWorkerRequestInto(reader, maxBytes, &output); err != nil { return Request{}, err }
	return output, nil
}`,
	}, policy)
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
func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error {
	if maxBytes <= 0 || maxBytes > 1<<20 { return errors.New("worker response limit is invalid") }
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil { return err }
	if int64(len(raw)) > maxBytes { return errors.New("worker response exceeds limit") }
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
const defaultMaxResponseBytesV2 int64 = 1<<20
func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytesV2, &output); err != nil { return Response{}, err }
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
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	if maxBytes <= 0 || maxBytes > 1<<20 { return errors.New("worker request limit is invalid") }
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil { return err }
	if int64(len(raw)) > maxBytes { return errors.New("worker request exceeds limit") }
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
		{name: "unbounded read", path: "protocol_decode.go", source: strings.Replace(requestSource, "io.ReadAll(io.LimitReader(reader, maxBytes+1))", "io.ReadAll(reader)", 1)},
		{name: "missing sentinel byte", path: "protocol_decode.go", source: strings.Replace(requestSource, "maxBytes+1", "maxBytes", 1)},
		{name: "oversized read", path: "protocol_decode.go", source: strings.Replace(requestSource, "maxBytes+1", "maxBytes+2", 1)},
		{name: "mismatched accepted threshold", path: "protocol_decode.go", source: strings.Replace(requestSource, "int64(len(raw)) > maxBytes", "int64(len(raw)) > maxBytes+1", 1)},
		{name: "missing dynamic limit validation", path: "protocol_decode.go", source: strings.Replace(requestSource, "\tif maxBytes <= 0 || maxBytes > 1<<20 { return errors.New(\"worker request limit is invalid\") }\n", "", 1)},
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
		Request JobStartRequestV2 ` + "`json:\"request\"`" + `
	}
	func jobRequestKeyV2(driverID, principalID string, request JobStartRequestV2) (string, error) {
		identity := jobRequestIdentityV2{DriverID: driverID, PrincipalID: principalID, Request: request}
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
type storedJobStateV2 struct { JobV2 JobV2; RequestKey string ` + "`json:\"requestKey\"`" + `; PrincipalID string ` + "`json:\"principalId\"`" + ` }
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
		{name: "adjacent runtime metadata", path: "job_v2_helpers.go", source: strings.Replace(keySource, "RuntimeMetadata", "RuntimeTemplateStatusMetadata", 1)},
		{name: "missing request driver identity", path: "job_v2_helpers.go", source: strings.NewReplacer("\t\tDriverID string `json:\"driverId\"`\n", "", "DriverID: driverID, ", "").Replace(keySource)},
		{name: "missing request principal identity", path: "job_v2_helpers.go", source: strings.NewReplacer("\t\tPrincipalID string `json:\"principalId\"`\n", "", "PrincipalID: principalID, ", "").Replace(keySource)},
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
func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	if maxBytes <= 0 || maxBytes > 1<<20 { return errors.New("worker request limit is invalid") }
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil { return err }
	if int64(len(raw)) > maxBytes { return errors.New("worker request exceeds limit") }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}
func decodeWorkerRequest(reader io.Reader, maxBytes int64) (Request, error) {
	var output Request
	if err := decodeWorkerRequestInto(reader, maxBytes, &output); err != nil { return Request{}, err }
	return output, nil
}`,
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
func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error {
	if maxBytes <= 0 || maxBytes > 1<<20 { return errors.New("worker response limit is invalid") }
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil { return err }
	if int64(len(raw)) > maxBytes { return errors.New("worker response exceeds limit") }
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil { return err }
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}
const defaultMaxResponseBytesV2 int64 = 1<<20
func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytesV2, &output); err != nil { return Response{}, err }
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
				expression, ok := rawElement.(ast.Expr)
				if ok && l8WorkerV2ObjectIdentifiesOperationField(structType.Field(index)) && !l8WorkerV2OperationValueAt(expression, 0, info, operationAliases, analysis) {
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
				expression, ok := rawElement.(ast.Expr)
				if !ok {
					return "", false
				}
				return l8WorkerV2StaticString(expression, info, analysis)
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
		element, ok := rawElement.(ast.Expr)
		if !ok {
			return nil, false
		}
		value, ok := l8WorkerV2StaticString(element, info, analysis)
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
		expression, ok := rawElement.(ast.Expr)
		if !ok {
			return "", false
		}
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
		if l8WorkerV2CallMayInvokeImplicitInterface(call, info) && !l8WorkerV2AllowedBoundedStrictDecoderCall(scope, call, info) && !l8WorkerV2AllowedExactClientRoundTripFormatting(scope, call, info) && !l8WorkerV2AllowedExactClientContextClassification(scope, call, info) {
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
		if kind == "interface" && (l8WorkerV2AllowedExactClientTransportCall(scope, call, info) || l8WorkerV2AllowedExactClientContextErrCall(scope, call, info) || l8WorkerV2AllowedExactClientErrorStringCall(scope, call, info)) {
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

func l8WorkerV2IsExactClientTransportInterface(typ types.Type) bool {
	if signature, ok := typ.(*types.Signature); ok && signature.Recv() != nil {
		typ = signature.Recv().Type()
	}
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" && named.Obj().Name() == "ClientTransport"
}

func l8WorkerV2AllowedBoundedStrictDecoderCall(scope l8WorkerV2GuardScope, candidate *ast.CallExpr, info *types.Info) bool {
	if filepath.Base(scope.file.path) != "protocol_decode.go" || candidate == nil {
		return false
	}
	candidateObject := l8WorkerV2CalledObject(candidate.Fun, info)
	if candidateObject == nil || candidateObject.Pkg() == nil {
		return false
	}
	candidateName := candidateObject.Pkg().Path() + "." + candidateObject.Name()
	if candidateName != "io.LimitReader" && candidateName != "encoding/json.NewDecoder" && candidateName != "encoding/json.Decode" {
		return false
	}
	type decoderPair struct {
		newDecoder *ast.CallExpr
		limit      *ast.CallExpr
	}
	var pairs []decoderPair
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		object := l8WorkerV2CalledObject(call.Fun, info)
		if object == nil || object.Pkg() == nil || object.Pkg().Path() != "encoding/json" || object.Name() != "NewDecoder" {
			return true
		}
		limit, ok := l8WorkerV2UnparenExpression(call.Args[0]).(*ast.CallExpr)
		if !ok || len(limit.Args) != 2 {
			return true
		}
		limitObject := l8WorkerV2CalledObject(limit.Fun, info)
		if limitObject == nil || limitObject.Pkg() == nil || limitObject.Pkg().Path() != "io" || limitObject.Name() != "LimitReader" {
			return true
		}
		boundValue := info.Types[limit.Args[1]].Value
		if boundValue == nil {
			return true
		}
		bound, exact := constant.Int64Val(boundValue)
		if !exact || bound <= 0 || bound > 1<<20 || !l8WorkerV2IsExactIOReader(info.TypeOf(limit.Args[0])) {
			return true
		}
		pairs = append(pairs, decoderPair{newDecoder: call, limit: limit})
		return true
	})
	for _, pair := range pairs {
		decoderObject := l8WorkerV2AssignedObjectForValue(scope, pair.newDecoder, info)
		if decoderObject == nil || !l8WorkerV2ScopeUsesExactStrictDecoder(scope, pair.newDecoder, pair.limit, decoderObject, info) {
			continue
		}
		if l8WorkerV2IsExactStrictDecoderCall(scope, candidate, pair.newDecoder, pair.limit, decoderObject, info) {
			return true
		}
	}
	return false
}

func l8WorkerV2IsExactIOReader(typ types.Type) bool {
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "io" && named.Obj().Name() == "Reader"
}

func l8WorkerV2AssignedObjectForValue(scope l8WorkerV2GuardScope, value ast.Expr, info *types.Info) types.Object {
	var result types.Object
	l8WorkerV2InspectScopeAST(scope, func(node ast.Node) bool {
		if result != nil {
			return false
		}
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for index, expression := range typed.Rhs {
				if expression != value || index >= len(typed.Lhs) {
					continue
				}
				result = l8WorkerV2ExpressionObject(typed.Lhs[index], info)
				return false
			}
		case *ast.ValueSpec:
			for index, expression := range typed.Values {
				if expression != value || index >= len(typed.Names) {
					continue
				}
				result = info.Defs[typed.Names[index]]
				return false
			}
		}
		return true
	})
	return result
}

func l8WorkerV2ScopeUsesExactStrictDecoder(scope l8WorkerV2GuardScope, constructor ast.Expr, limit *ast.CallExpr, decoder types.Object, info *types.Info) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || function.Body == nil || len(function.Body.List) != 6 {
		return false
	}
	output, ok := l8WorkerV2ExactDecoderParameters(function, limit, info)
	if !ok {
		return false
	}
	assignment, ok := function.Body.List[0].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || assignment.Rhs[0] != constructor || l8WorkerV2ExpressionObject(assignment.Lhs[0], info) != decoder {
		return false
	}
	strictStatement, ok := function.Body.List[1].(*ast.ExprStmt)
	if !ok {
		return false
	}
	strictCall, ok := l8WorkerV2DecoderMethodCall(strictStatement.X, decoder, "DisallowUnknownFields", info)
	if !ok || len(strictCall.Args) != 0 {
		return false
	}
	if !l8WorkerV2ExactPrimaryDecodeIf(function.Body.List[2], decoder, output, info) {
		return false
	}
	trailingObject, ok := l8WorkerV2ExactTrailingDeclaration(function.Body.List[3], info)
	if !ok || !l8WorkerV2ExactTrailingDecodeIf(function.Body.List[4], decoder, trailingObject, info) {
		return false
	}
	return l8WorkerV2IsBareReturn(function.Body.List[5], nil, info)
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

func l8WorkerV2ExactDecoderParameters(function *ast.FuncDecl, limit *ast.CallExpr, info *types.Info) (types.Object, bool) {
	if function == nil || function.Recv != nil || function.Type.TypeParams != nil || function.Type.Params == nil || function.Type.Results == nil || len(limit.Args) != 2 {
		return nil, false
	}
	var parameters []types.Object
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			if object := info.Defs[name]; object != nil {
				parameters = append(parameters, object)
			}
		}
	}
	if len(parameters) != 2 || len(function.Type.Results.List) != 1 || len(function.Type.Results.List[0].Names) != 0 {
		return nil, false
	}
	if !l8WorkerV2IsExactIOReader(parameters[0].Type()) || l8WorkerV2ExpressionObject(limit.Args[0], info) != parameters[0] || !l8WorkerV2IsExactStrictDecodeOutputPointer(parameters[1].Type()) {
		return nil, false
	}
	resultType := info.TypeOf(function.Type.Results.List[0].Type)
	if resultType != types.Universe.Lookup("error").Type() {
		return nil, false
	}
	return parameters[1], true
}

func l8WorkerV2IsExactStrictDecodeOutputPointer(typ types.Type) bool {
	pointer, ok := types.Unalias(typ).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(pointer.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" {
		return false
	}
	name := named.Obj().Name()
	if name != "Request" && name != "Response" && !strings.HasSuffix(name, "V2") {
		return false
	}
	_, ok = named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	return !l8WorkerV2TypeMayInvokeJSONDecodeCallback(typ, make(map[types.Type]bool))
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

func l8WorkerV2IsExactStrictDecoderCall(scope l8WorkerV2GuardScope, candidate, constructor, limit *ast.CallExpr, decoder types.Object, info *types.Info) bool {
	if candidate == constructor || candidate == limit {
		return true
	}
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || function.Body == nil || len(function.Body.List) != 6 {
		return false
	}
	_, _, primary, primaryOK := l8WorkerV2ExactDecodeIf(function.Body.List[2], decoder, info)
	_, _, trailing, trailingOK := l8WorkerV2ExactDecodeIf(function.Body.List[4], decoder, info)
	return primaryOK && trailingOK && (candidate == primary || candidate == trailing)
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
		expression, ok := rawElement.(ast.Expr)
		if !ok || l8WorkerV2InterfaceCapableArgument(info.TypeOf(expression)) {
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
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := l8ReadWorkerSource(t, path)
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
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
						t.Fatalf("unquote field tag in %s: %v", path, unquoteErr)
					}
					jsonTag := strings.ToLower(reflectStructTagJSON(tag))
					if strings.Contains(jsonTag, "peeruid") || strings.Contains(jsonTag, "peergid") {
						t.Fatalf("production field in %s exposes peer credential through JSON tag %q", path, jsonTag)
					}
					if !strings.Contains(jsonTag, "principal") {
						continue
					}
					privateDurablePrincipal := filepath.Base(path) == "job_store_v2.go" && typeSpec.Name.Name == "storedJobStateV2" && jsonTag == "principalid"
					if privateDurablePrincipal && len(field.Names) == 1 && field.Names[0].Name == "PrincipalID" {
						continue
					}
					t.Fatalf("production field in %s exposes server-derived principal outside storedJobStateV2 through JSON tag %q", path, jsonTag)
				}
			}
		}
	}
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
