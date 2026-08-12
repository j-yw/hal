package credentialhelper

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestCoreCapabilitiesValidateCopyAndDestroy(t *testing.T) {
	path, err := NewRelativePathCapability("credentials/token")
	if err != nil {
		t.Fatal(err)
	}
	if path.Len() != 17 {
		t.Fatalf("Len() = %d", path.Len())
	}
	destination := make([]byte, path.Len(), path.Len()+8)
	for index := range destination[:cap(destination)] {
		destination[:cap(destination)][index] = 0xaa
	}
	if count, copyErr := path.CopyTo(destination); copyErr != nil || count != len(destination) || string(destination) != "credentials/token" {
		t.Fatalf("CopyTo() = %d, %v, %q", count, copyErr, destination)
	}
	short := make([]byte, path.Len()-1, path.Len()+8)
	for index := range short[:cap(short)] {
		short[:cap(short)][index] = 0xaa
	}
	if count, copyErr := path.CopyTo(short); !errors.Is(copyErr, ErrContractInvalidArgument) || count != 0 {
		t.Fatalf("short CopyTo() = %d, %v", count, copyErr)
	}
	for index, value := range short[:cap(short)] {
		if value != 0 {
			t.Fatalf("short destination byte %d was not wiped", index)
		}
	}
	if _, err := NewRelativePathCapability(""); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("empty path error = %v", err)
	}

	fileDigest := sha256.Sum256([]byte("secret"))
	bindings := []credentialprotocol.HelperBindingManifestRecord{
		{BindingID: "http", Mode: credentialprotocol.DeliveryModeHTTPProxy},
		{BindingID: "file", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "credentials/token", DeclaredFileBytes: 6, FileSHA256: fileDigest},
	}
	manifest, err := NewManifestCapability(bindings)
	if err != nil {
		t.Fatal(err)
	}
	bindings[0].BindingID = "changed"
	if manifest.Count() != 2 || manifest.SHA256() == ([32]byte{}) {
		t.Fatalf("manifest count/digest = %d/%x", manifest.Count(), manifest.SHA256())
	}
	id, mode, target, length, digest, ok := manifest.Binding(1)
	if !ok || id != "file" || mode != credentialprotocol.DeliveryModeFileTmpfs || target.Len() != 17 || length != 6 || digest != fileDigest {
		t.Fatalf("Binding(1) = %q/%v/%d/%d/%x/%v", id, mode, target.Len(), length, digest, ok)
	}
	if _, _, _, _, _, ok := manifest.Binding(2); ok {
		t.Fatal("out-of-range binding succeeded")
	}
	if _, err := NewManifestCapability([]credentialprotocol.HelperBindingManifestRecord{{BindingID: "token:broader", Mode: credentialprotocol.DeliveryModeSSHAgent}}); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("broader token manifest error = %v", err)
	}

	plan, err := NewExecPlanCapability(validCoreExecPlan())
	if err != nil {
		t.Fatal(err)
	}
	alias := plan
	lengthBefore := plan.EncodedLength()
	if lengthBefore == 0 || plan.SHA256() == ([32]byte{}) {
		t.Fatal("plan metadata is zero before destroy")
	}
	sink := &recordingCoreSink{maximum: int(lengthBefore)}
	if err := alias.CopyCanonicalTo(sink); err != nil || len(sink.payload) != int(lengthBefore) {
		t.Fatalf("CopyCanonicalTo() = %v, bytes = %d", err, len(sink.payload))
	}
	plan.destroy()
	if alias.EncodedLength() != 0 || alias.SHA256() != ([32]byte{}) {
		t.Fatal("alias retained metadata after destroy")
	}
	for index, value := range plan.state.canonical {
		if value != 0 {
			t.Fatalf("canonical byte %d was not wiped", index)
		}
	}
	sink = &recordingCoreSink{maximum: int(lengthBefore)}
	if err := alias.CopyCanonicalTo(sink); !errors.Is(err, ErrContractDestroyed) || sink.calls != 0 {
		t.Fatalf("destroyed copy = %v, calls = %d", err, sink.calls)
	}
}

func TestCoreRequestConstructorsAndAccessors(t *testing.T) {
	requestID, identity := coreRequestID(), coreDigest("identity")
	partial, err := NewCoreGenerations("boot", "helper", "job", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	all := coreAllGenerations(t)
	manifest := coreManifest(t)
	preparation, prepared := corePreparationCapability(), corePreparedCapability()
	execution, cleanup := coreExecutionCapability(), coreCleanupCapability()
	prepare, err := NewCorePrepareRequest(requestID, identity, 1, partial, 1, "helper-limits-v1", manifest, manifest.SHA256(), preparation, prepared, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	if prepare.RequestID() != requestID || prepare.IdentityDigest() != identity || prepare.Revision() != 1 || prepare.Generations().Job() != "job" || prepare.ExpiresUnixNano() != 1 || prepare.FixedLimitSetID() != "helper-limits-v1" || prepare.Manifest().Count() != 1 || prepare.ManifestSHA256() != manifest.SHA256() || prepare.Preparation() != preparation || prepare.Prepared() != prepared || prepare.Cleanup() != cleanup {
		t.Fatal("prepare accessors changed values")
	}
	if _, err := NewCorePrepareRequest(requestID, identity, 1, all, 1, "helper-limits-v1", manifest, manifest.SHA256(), preparation, prepared, cleanup); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("prepare with unused generations error = %v", err)
	}

	target, _ := NewRelativePathCapability("credential")
	fileDigest := coreDigest("file")
	file, err := NewCoreFileRequest(requestID, identity, 1, "job", preparation, "binding", 0, target, 1, fileDigest)
	if err != nil {
		t.Fatal(err)
	}
	if file.Job() != "job" || file.Preparation() != preparation || file.BindingID() != "binding" || file.BindingIndex() != 0 || file.Target().Len() != target.Len() || file.FileLength() != 1 || file.FileSHA256() != fileDigest {
		t.Fatal("file accessors changed values")
	}
	commit, err := NewCoreCommitRequest(requestID, identity, 1, "job", preparation, manifest.SHA256(), coreDigest("transaction"), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Job() != "job" || commit.TransactionSHA256() == ([32]byte{}) || commit.Prepared() != prepared {
		t.Fatal("commit accessors changed values")
	}

	plan := corePlan(t)
	execRequest, err := NewCoreExecRequest(requestID, identity, 1, all, "helper-limits-v1", "exec", 0, [32]byte{}, 1, coreDigest("exec-body"), plan, prepared, execution, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	if execRequest.ExecBindingID() != "exec" || execRequest.PrivateLength() != 0 || execRequest.PrivateSHA256() != ([32]byte{}) || execRequest.ExecBodyLength() != 1 || execRequest.ExecBodySHA256() == ([32]byte{}) || execRequest.Plan().EncodedLength() == 0 || execRequest.Execution() != execution {
		t.Fatal("exec accessors changed values")
	}
	renew, err := NewCoreRenewRequest(requestID, identity, 2, all, 2, prepared)
	if err != nil || renew.ExpiresUnixNano() != 2 || renew.Prepared() != prepared {
		t.Fatalf("renew = %#v, %v", renew, err)
	}
	revoke, err := NewCoreRevokeRequest(requestID, identity, 2, all, credentialprotocol.RevokeReasonRequested, prepared, cleanup)
	if err != nil || revoke.Reason() != credentialprotocol.RevokeReasonRequested || revoke.Cleanup() != cleanup {
		t.Fatalf("revoke = %#v, %v", revoke, err)
	}
	inspect, err := NewCoreInspectRequest(identity, 2, all, prepared)
	if err != nil || inspect.IdentityDigest() != identity || inspect.Revision() != 2 || inspect.Generations().Mount() != "mount" || inspect.Prepared() != prepared {
		t.Fatalf("inspect = %#v, %v", inspect, err)
	}
	output, err := NewCoreOutputRequest(requestID, identity, 2, "job", execution, credentialprotocol.HelperExecStreamStdout, 7, credentialprotocol.MaxHelperExecStreamPayloadBytes)
	if err != nil || output.Kind() != credentialprotocol.HelperExecStreamStdout || output.Offset() != 7 || output.Capacity() != credentialprotocol.MaxHelperExecStreamPayloadBytes {
		t.Fatalf("output = %#v, %v", output, err)
	}
}

func TestCoreResultValidationMatrices(t *testing.T) {
	all := coreAllGenerations(t)
	prepared, execution, cleanup := corePreparedCapability(), coreExecutionCapability(), coreCleanupCapability()
	manifestDigest, transactionDigest := coreDigest("manifest"), coreDigest("transaction")
	preparedResult, err := NewCorePreparedResult(prepared, all, 1, credentialprotocol.MaxHelperBindings, manifestDigest, transactionDigest)
	if err != nil || preparedResult.BindingCount() != credentialprotocol.MaxHelperBindings || preparedResult.Prepared() != prepared {
		t.Fatalf("prepared result = %#v, %v", preparedResult, err)
	}

	emptyDigest := sha256.Sum256(nil)
	for _, test := range []struct {
		name      string
		count     uint32
		digest    [32]byte
		eof       bool
		truncated bool
		valid     bool
	}{
		{name: "data", count: 1, digest: coreDigest("data"), valid: true},
		{name: "eof", digest: emptyDigest, eof: true, valid: true},
		{name: "truncated eof", digest: emptyDigest, eof: true, truncated: true, valid: true},
		{name: "empty non-eof", digest: emptyDigest},
		{name: "truncated data", count: 1, digest: coreDigest("data"), truncated: true},
		{name: "eof with data", count: 1, digest: coreDigest("data"), eof: true},
	} {
		t.Run("output "+test.name, func(t *testing.T) {
			result, gotErr := NewCoreOutputResult(execution, credentialprotocol.HelperExecStreamStdout, 4, test.count, test.digest, test.eof, test.truncated)
			if test.valid {
				if gotErr != nil || result.Execution() != execution || result.Offset() != 4 || result.ByteCount() != test.count || result.EOF() != test.eof || result.Truncated() != test.truncated {
					t.Fatalf("result = %#v, %v", result, gotErr)
				}
			} else if !errors.Is(gotErr, ErrContractResultMatrix) {
				t.Fatalf("error = %v", gotErr)
			}
		})
	}

	for _, test := range []struct {
		category CoreExecExitCategory
		code     int32
		valid    bool
	}{
		{CoreExecExitExited, 0, true}, {CoreExecExitExited, 255, true}, {CoreExecExitExited, 256, false},
		{CoreExecExitSignaled, 1, true}, {CoreExecExitSignaled, 64, true}, {CoreExecExitSignaled, 0, false},
		{CoreExecExitSetupFailed, 1, true}, {CoreExecExitSetupFailed, 2, false}, {0, 0, false},
	} {
		_, gotErr := NewCoreExecResult(execution, test.category, test.code, 0, emptyDigest, coreDigest("stdin-transcript"), 0, emptyDigest, false, 0, emptyDigest, false, coreDigest("exec-transaction"))
		if test.valid && gotErr != nil || !test.valid && !errors.Is(gotErr, ErrContractResultMatrix) {
			t.Errorf("exec category/code %d/%d error = %v", test.category, test.code, gotErr)
		}
	}

	for _, test := range []struct {
		category  CoreCleanupCategory
		authority bool
		resources bool
		valid     bool
	}{
		{CoreCleanupComplete, true, true, true},
		{CoreCleanupRetryRequired, true, false, true},
		{CoreCleanupStopVMRequired, false, false, true},
		{CoreCleanupStopVMRequired, false, true, true},
		{CoreCleanupStopVMRequired, true, false, true},
		{CoreCleanupComplete, false, false, false},
		{CoreCleanupRetryRequired, false, false, false},
		{CoreCleanupStopVMRequired, true, true, false},
	} {
		result, gotErr := NewCoreCleanupResult(cleanup, test.category, test.authority, test.resources)
		if test.valid {
			if gotErr != nil || result.Category() != test.category || result.AuthorityAbsent() != test.authority || result.ResourcesAbsent() != test.resources {
				t.Errorf("cleanup = %#v, %v", result, gotErr)
			}
		} else if !errors.Is(gotErr, ErrContractResultMatrix) {
			t.Errorf("cleanup error = %v", gotErr)
		}
	}

	for _, test := range []struct {
		state     CoreInspectionState
		expiry    int64
		active    uint16
		authority bool
		resources bool
	}{
		{CoreInspectionPreparing, 1, 0, false, true},
		{CoreInspectionPrepared, 1, 0, true, true},
		{CoreInspectionExecuting, 1, 1, true, true},
		{CoreInspectionRevoking, 1, 0, false, true},
		{CoreInspectionRevoking, 1, 1, false, true},
		{CoreInspectionAbsent, 0, 0, false, false},
	} {
		result, gotErr := NewCoreInspection(prepared, test.state, all, test.expiry, test.active, test.authority, test.resources)
		if gotErr != nil || result.State() != test.state || result.ActiveExecutions() != test.active {
			t.Errorf("inspection = %#v, %v", result, gotErr)
		}
	}
	if _, err := NewCoreInspection(prepared, CoreInspectionAbsent, all, 1, 0, false, false); !errors.Is(err, ErrContractResultMatrix) {
		t.Fatalf("invalid absent inspection error = %v", err)
	}
}

type recordingCoreSink struct {
	maximum int
	payload []byte
	calls   int
}

func (sink *recordingCoreSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *recordingCoreSink) WriteCredential(value []byte) error {
	sink.calls++
	sink.payload = append([]byte(nil), value...)
	return nil
}

func coreDigest(value string) [32]byte { return sha256.Sum256([]byte(value)) }

func coreRequestID() [16]byte {
	var value [16]byte
	copy(value[:], "request-id")
	return value
}

func coreAllGenerations(t *testing.T) CoreGenerations {
	t.Helper()
	value, err := NewCoreGenerations("boot", "helper", "job", "monitor", "mount", "cgroup")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func coreManifest(t *testing.T) ManifestCapability {
	t.Helper()
	value, err := NewManifestCapability([]credentialprotocol.HelperBindingManifestRecord{{BindingID: "ssh", Mode: credentialprotocol.DeliveryModeSSHAgent}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func validCoreExecPlan() credentialprotocol.HelperExecPlan {
	return credentialprotocol.HelperExecPlan{
		Arguments: []string{"/bin/true"}, WorkDirectory: "/",
		StdinMode: credentialprotocol.HelperExecStreamModePipe, StdoutMode: credentialprotocol.HelperExecStreamModePipe, StderrMode: credentialprotocol.HelperExecStreamModePipe,
		StdinMaxBytes: 1, StdoutMaxBytes: 1, StderrMaxBytes: 1,
		Timing: credentialprotocol.HelperExecTiming{Kind: credentialprotocol.HelperExecTimingTimeoutMillis, Value: 1},
	}
}

func corePlan(t *testing.T) ExecPlanCapability {
	t.Helper()
	value, err := NewExecPlanCapability(validCoreExecPlan())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func corePreparationCapability() CorePreparationCapability {
	return CorePreparationCapability{digest: coreDigest("preparation")}
}
func corePreparedCapability() CorePreparedCapability {
	return CorePreparedCapability{digest: coreDigest("prepared")}
}
func coreExecutionCapability() CoreExecutionCapability {
	return CoreExecutionCapability{digest: coreDigest("execution")}
}
func coreCleanupCapability() CoreCleanupCapability {
	return CoreCleanupCapability{digest: coreDigest("cleanup")}
}
