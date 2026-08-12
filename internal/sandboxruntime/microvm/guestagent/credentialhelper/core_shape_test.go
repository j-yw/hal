package credentialhelper

import (
	"reflect"
	"testing"
)

func TestCoreConcreteValuesHaveOnlyPrivateUntaggedFields(t *testing.T) {
	values := []any{
		requestCorrelation{}, CoreGenerations{}, RelativePathCapability{}, ManifestCapability{}, manifestRecord{},
		ExecPlanCapability{}, execPlanCapabilityState{}, CorePreparationCapability{}, CorePreparedCapability{},
		CoreExecutionCapability{}, CoreCleanupCapability{}, CorePrepareRequest{}, CoreFileRequest{}, CoreCommitRequest{},
		CorePreparedResult{}, CoreExecRequest{}, CoreRenewRequest{}, CoreRevokeRequest{}, CoreInspectRequest{},
		CoreOutputRequest{}, CoreOutputResult{}, CoreExecResult{}, CoreCleanupResult{}, CoreInspection{}, ContractError{},
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.IsExported() {
				t.Errorf("%s.%s is exported", typeOf.Name(), field.Name)
			}
			if field.Tag != "" {
				t.Errorf("%s.%s tag = %q", typeOf.Name(), field.Name, field.Tag)
			}
			if field.Type.Kind() == reflect.Map || field.Type.Kind() == reflect.Interface || field.Type.Kind() == reflect.Slice {
				t.Errorf("%s.%s has forbidden kind %s", typeOf.Name(), field.Name, field.Type.Kind())
			}
		}
	}
	if reflect.TypeOf(RelativePathCapability{}).Field(2).Type.Len() != 4096 {
		t.Fatal("relative path storage is not fixed at 4096 bytes")
	}
	if reflect.TypeOf(ManifestCapability{}).Field(2).Type.Len() != 16 {
		t.Fatal("manifest storage is not fixed at 16 records")
	}
	if reflect.TypeOf(execPlanCapabilityState{}).Field(2).Type.Len() != 64*1024 {
		t.Fatal("exec plan storage is not fixed at 64 KiB")
	}
}

func TestCoreConcreteFieldOrderAndCatalogValuesAreExact(t *testing.T) {
	fields := []struct {
		value any
		names []string
	}{
		{requestCorrelation{}, []string{"requestID", "identityDigest", "revision"}},
		{CoreGenerations{}, []string{"boot", "helper", "job", "monitor", "mount", "cgroup"}},
		{RelativePathCapability{}, []string{"liveValue", "length", "bytes"}},
		{ManifestCapability{}, []string{"liveValue", "count", "records"}},
		{manifestRecord{}, []string{"bindingID", "mode", "target", "declaredFileBytes", "fileSHA256"}},
		{ExecPlanCapability{}, []string{"liveValue", "state"}},
		{execPlanCapabilityState{}, []string{"encodedLength", "sha256", "canonical", "destroyed"}},
		{CorePrepareRequest{}, []string{"liveValue", "correlation", "generations", "expiresUnixNano", "fixedLimitSetID", "manifest", "manifestSHA256", "preparation", "prepared", "cleanup"}},
		{CoreFileRequest{}, []string{"liveValue", "correlation", "job", "preparation", "bindingID", "bindingIndex", "target", "fileLength", "fileSHA256"}},
		{CoreCommitRequest{}, []string{"liveValue", "correlation", "job", "preparation", "manifestSHA256", "transactionSHA256", "prepared"}},
		{CorePreparedResult{}, []string{"liveValue", "generations", "expiresUnixNano", "bindingCount", "manifestSHA256", "transactionSHA256", "prepared"}},
		{CoreExecRequest{}, []string{"liveValue", "correlation", "generations", "fixedLimitSetID", "execBindingID", "privateLength", "privateSHA256", "execBodyLength", "execBodySHA256", "plan", "prepared", "execution", "cleanup"}},
		{CoreRenewRequest{}, []string{"liveValue", "correlation", "generations", "expiresUnixNano", "prepared"}},
		{CoreRevokeRequest{}, []string{"liveValue", "correlation", "generations", "reason", "prepared", "cleanup"}},
		{CoreInspectRequest{}, []string{"liveValue", "identityDigest", "revision", "generations", "prepared"}},
		{CoreOutputRequest{}, []string{"liveValue", "correlation", "job", "execution", "kind", "offset", "capacity"}},
		{CoreOutputResult{}, []string{"liveValue", "execution", "kind", "offset", "byteCount", "sha256", "eof", "truncated"}},
		{CoreExecResult{}, []string{"liveValue", "execution", "exitCategory", "exitCode", "stdinBytes", "stdinSHA256", "stdinTranscriptSHA256", "stdoutBytes", "stdoutSHA256", "stdoutTruncated", "stderrBytes", "stderrSHA256", "stderrTruncated", "execTransactionSHA256"}},
		{CoreCleanupResult{}, []string{"liveValue", "cleanup", "category", "authorityAbsent", "resourcesAbsent"}},
		{CoreInspection{}, []string{"liveValue", "prepared", "state", "generations", "expiresUnixNano", "activeExecutions", "authorityPresent", "resourcesPresent"}},
	}
	for _, contract := range fields {
		typeOf := reflect.TypeOf(contract.value)
		if typeOf.NumField() != len(contract.names) {
			t.Fatalf("%s field count = %d, want %d", typeOf.Name(), typeOf.NumField(), len(contract.names))
		}
		for index, name := range contract.names {
			if typeOf.Field(index).Name != name {
				t.Errorf("%s field %d = %s, want %s", typeOf.Name(), index, typeOf.Field(index).Name, name)
			}
		}
	}
	if CoreExecExitExited != 1 || CoreExecExitSignaled != 2 || CoreExecExitSetupFailed != 3 {
		t.Fatal("core exec exit catalog changed")
	}
	if CoreCleanupComplete != 1 || CoreCleanupRetryRequired != 2 || CoreCleanupStopVMRequired != 3 {
		t.Fatal("core cleanup catalog changed")
	}
	if CoreInspectionPreparing != 1 || CoreInspectionPrepared != 2 || CoreInspectionExecuting != 3 || CoreInspectionRevoking != 4 || CoreInspectionAbsent != 5 {
		t.Fatal("core inspection catalog changed")
	}
}
