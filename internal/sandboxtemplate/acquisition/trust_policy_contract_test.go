package acquisition_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestTrustPolicyContractConstantsAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "strict mode", got: string(acquisition.TrustPolicyModeStrict), want: "strict"},
		{name: "advisory mode", got: string(acquisition.TrustPolicyModeAdvisory), want: "advisory"},
		{name: "trusted decision", got: string(acquisition.TrustPolicyDecisionTrusted), want: "trusted"},
		{name: "rejected decision", got: string(acquisition.TrustPolicyDecisionRejected), want: "rejected"},
		{name: "advisory decision", got: string(acquisition.TrustPolicyDecisionAdvisory), want: "advisory"},
		{name: "unavailable decision", got: string(acquisition.TrustPolicyDecisionUnavailable), want: "unavailable"},
		{name: "mutable reference error", got: string(acquisition.TrustPolicyErrorMutableReference), want: "mutable_reference"},
		{name: "missing digest pin error", got: string(acquisition.TrustPolicyErrorMissingDigestPin), want: "missing_digest_pin"},
		{name: "unresolved lock entry error", got: string(acquisition.TrustPolicyErrorUnresolvedLockEntry), want: "unresolved_lock_entry"},
		{name: "lock provenance mismatch error", got: string(acquisition.TrustPolicyErrorLockProvenanceMismatch), want: "lock_provenance_mismatch"},
		{name: "unsupported source error", got: string(acquisition.TrustPolicyErrorUnsupportedSource), want: "unsupported_source"},
		{name: "resolver unavailable error", got: string(acquisition.TrustPolicyErrorResolverUnavailable), want: "resolver_unavailable"},
		{name: "mutable reference warning", got: string(acquisition.TrustPolicyWarningMutableReference), want: "mutable_reference"},
		{name: "missing digest pin warning", got: string(acquisition.TrustPolicyWarningMissingDigestPin), want: "missing_digest_pin"},
		{name: "unresolved lock entry warning", got: string(acquisition.TrustPolicyWarningUnresolvedLockEntry), want: "unresolved_lock_entry"},
		{name: "lock provenance mismatch warning", got: string(acquisition.TrustPolicyWarningLockProvenanceMismatch), want: "lock_provenance_mismatch"},
		{name: "unsupported source warning", got: string(acquisition.TrustPolicyWarningUnsupportedSource), want: "unsupported_source"},
		{name: "resolver unavailable warning", got: string(acquisition.TrustPolicyWarningResolverUnavailable), want: "resolver_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("constant = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestTrustPolicyContractFieldsAndJSONTags(t *testing.T) {
	requestType := reflect.TypeOf(acquisition.TrustPolicyRequest{})
	assertAcquisitionField(t, requestType, "Mode", reflect.TypeOf(acquisition.TrustPolicyMode("")), `json:"mode,omitempty"`)
	assertAcquisitionField(t, requestType, "Source", reflect.TypeOf((*acquisition.TrustPolicySource)(nil)), `json:"source,omitempty"`)
	assertAcquisitionField(t, requestType, "RequiredReferences", reflect.TypeOf([]acquisition.TrustPolicyReferenceRequirement{}), `json:"requiredReferences,omitempty"`)
	assertAcquisitionField(t, requestType, "Lock", reflect.TypeOf((*acquisition.TemplateLock)(nil)), `json:"lock,omitempty"`)
	assertAcquisitionField(t, requestType, "Provenance", reflect.TypeOf((*acquisition.TemplateLock)(nil)), `json:"provenance,omitempty"`)

	sourceType := reflect.TypeOf(acquisition.TrustPolicySource{})
	assertAcquisitionField(t, sourceType, "Kind", reflect.TypeOf(acquisition.SourceKind("")), `json:"kind,omitempty"`)
	assertAcquisitionField(t, sourceType, "ReferenceKind", reflect.TypeOf(sandboxtemplate.ReferenceKind("")), `json:"referenceKind,omitempty"`)
	assertAcquisitionField(t, sourceType, "Digest", reflect.TypeOf((*sandboxtemplate.DigestMetadata)(nil)), `json:"digest,omitempty"`)

	requirementType := reflect.TypeOf(acquisition.TrustPolicyReferenceRequirement{})
	assertAcquisitionField(t, requirementType, "Field", reflect.TypeOf(""), `json:"field"`)
	assertAcquisitionField(t, requirementType, "Kind", reflect.TypeOf(sandboxtemplate.ReferenceKind("")), `json:"kind,omitempty"`)

	resultType := reflect.TypeOf(acquisition.TrustPolicyResult{})
	assertAcquisitionField(t, resultType, "Mode", reflect.TypeOf(acquisition.TrustPolicyMode("")), `json:"mode,omitempty"`)
	assertAcquisitionField(t, resultType, "Decision", reflect.TypeOf(acquisition.TrustPolicyDecision("")), `json:"decision"`)
	assertAcquisitionField(t, resultType, "Enforcement", reflect.TypeOf((*acquisition.TrustPolicyEnforcementMetadata)(nil)), `json:"enforcement,omitempty"`)
	assertAcquisitionField(t, resultType, "Errors", reflect.TypeOf([]acquisition.TrustPolicyError{}), `json:"errors,omitempty"`)
	assertAcquisitionField(t, resultType, "Warnings", reflect.TypeOf([]acquisition.TrustPolicyWarning{}), `json:"warnings,omitempty"`)

	enforcementType := reflect.TypeOf(acquisition.TrustPolicyEnforcementMetadata{})
	assertAcquisitionField(t, enforcementType, "StrictlyEnforced", reflect.TypeOf(false), `json:"strictlyEnforced"`)

	errorType := reflect.TypeOf(acquisition.TrustPolicyError{})
	assertAcquisitionField(t, errorType, "Code", reflect.TypeOf(acquisition.TrustPolicyErrorCode("")), `json:"code"`)
	assertAcquisitionField(t, errorType, "Field", reflect.TypeOf(""), `json:"field,omitempty"`)
	assertAcquisitionField(t, errorType, "ReferenceField", reflect.TypeOf(""), `json:"referenceField,omitempty"`)
	assertAcquisitionField(t, errorType, "ReferenceIndex", reflect.TypeOf((*int)(nil)), `json:"referenceIndex,omitempty"`)
	assertAcquisitionField(t, errorType, "SourceKind", reflect.TypeOf(acquisition.SourceKind("")), `json:"sourceKind,omitempty"`)
	assertAcquisitionField(t, errorType, "ReasonCode", reflect.TypeOf(acquisition.LockReasonCode("")), `json:"reasonCode,omitempty"`)
	assertAcquisitionField(t, errorType, "Message", reflect.TypeOf(""), `json:"message,omitempty"`)

	warningType := reflect.TypeOf(acquisition.TrustPolicyWarning{})
	assertAcquisitionField(t, warningType, "Code", reflect.TypeOf(acquisition.TrustPolicyWarningCode("")), `json:"code"`)
	assertAcquisitionField(t, warningType, "Field", reflect.TypeOf(""), `json:"field,omitempty"`)
	assertAcquisitionField(t, warningType, "ReferenceField", reflect.TypeOf(""), `json:"referenceField,omitempty"`)
	assertAcquisitionField(t, warningType, "ReferenceIndex", reflect.TypeOf((*int)(nil)), `json:"referenceIndex,omitempty"`)
	assertAcquisitionField(t, warningType, "SourceKind", reflect.TypeOf(acquisition.SourceKind("")), `json:"sourceKind,omitempty"`)
	assertAcquisitionField(t, warningType, "ReasonCode", reflect.TypeOf(acquisition.LockReasonCode("")), `json:"reasonCode,omitempty"`)
	assertAcquisitionField(t, warningType, "Message", reflect.TypeOf(""), `json:"message,omitempty"`)
}

func TestTrustPolicyJSONShapeIncludesOnlySafePolicyMetadata(t *testing.T) {
	index := 1
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     strings.Repeat("a", 64),
	}
	request := acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeStrict,
		Source: &acquisition.TrustPolicySource{
			Kind:          acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Digest:        digest,
		},
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "metadata.reference", Kind: sandboxtemplate.ReferenceKindOCIArtifact},
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock: &acquisition.TemplateLock{
			SourceKind:    acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Status:        acquisition.LockStatusLocked,
			Document: acquisition.DigestLock{
				Status:     acquisition.LockStatusLocked,
				Digest:     digest,
				ReasonCode: acquisition.LockReasonImmutableDigest,
			},
		},
		Provenance: &acquisition.TemplateLock{
			SourceKind:    acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Status:        acquisition.LockStatusLocked,
			Document: acquisition.DigestLock{
				Status:     acquisition.LockStatusLocked,
				Digest:     digest,
				ReasonCode: acquisition.LockReasonImmutableDigest,
			},
		},
	}

	requestRaw := mustAcquisitionObject(t, request)
	assertAcquisitionObjectKeys(t, requestRaw, []string{"mode", "source", "requiredReferences", "lock", "provenance"})
	assertNestedAcquisitionKeys(t, requestRaw, "source", []string{"kind", "referenceKind", "digest"})

	result := acquisition.TrustPolicyResult{
		Mode:        acquisition.TrustPolicyModeStrict,
		Decision:    acquisition.TrustPolicyDecisionRejected,
		Enforcement: &acquisition.TrustPolicyEnforcementMetadata{StrictlyEnforced: true},
		Errors: []acquisition.TrustPolicyError{{
			Code:           acquisition.TrustPolicyErrorMissingDigestPin,
			Field:          "requiredReferences",
			ReferenceField: "runtime.image",
			ReferenceIndex: &index,
			SourceKind:     acquisition.SourceKindOCIArtifact,
			ReasonCode:     acquisition.LockReasonMutableReference,
			Message:        "required reference is not digest pinned",
		}},
		Warnings: []acquisition.TrustPolicyWarning{{
			Code:       acquisition.TrustPolicyWarningResolverUnavailable,
			Field:      "provenance",
			SourceKind: acquisition.SourceKindOCIArtifact,
			Message:    "resolver is unavailable",
		}},
	}

	resultRaw := mustAcquisitionObject(t, result)
	assertAcquisitionObjectKeys(t, resultRaw, []string{"mode", "decision", "enforcement", "errors", "warnings"})
	assertNestedAcquisitionKeys(t, resultRaw, "enforcement", []string{"strictlyEnforced"})
	assertFirstAcquisitionArrayObjectKeys(t, resultRaw, "errors", []string{"code", "field", "referenceField", "referenceIndex", "sourceKind", "reasonCode", "message"})
	assertFirstAcquisitionArrayObjectKeys(t, resultRaw, "warnings", []string{"code", "field", "sourceKind", "message"})

	data, err := json.Marshal(struct {
		Request acquisition.TrustPolicyRequest `json:"request"`
		Result  acquisition.TrustPolicyResult  `json:"result"`
	}{Request: request, Result: result})
	if err != nil {
		t.Fatalf("Marshal(policy metadata) error = %v", err)
	}
	assertAcquisitionTextOmitsFragments(t, string(data),
		"/Users/v/private-template.yaml",
		"token=",
		"password=",
		"registryAuth",
		"authorization",
		"ghp_secret",
		"?secret=sk-live-template",
	)
}

func TestTrustPolicyJSONOmitsOptionalMetadata(t *testing.T) {
	requestRaw := mustAcquisitionObject(t, acquisition.TrustPolicyRequest{
		Source: &acquisition.TrustPolicySource{Kind: acquisition.SourceKindLocalFile},
	})
	assertAcquisitionObjectKeys(t, requestRaw, []string{"source"})
	assertNestedAcquisitionKeys(t, requestRaw, "source", []string{"kind"})

	resultRaw := mustAcquisitionObject(t, acquisition.TrustPolicyResult{
		Decision: acquisition.TrustPolicyDecisionTrusted,
		Errors: []acquisition.TrustPolicyError{{
			Code: acquisition.TrustPolicyErrorMutableReference,
		}},
		Warnings: []acquisition.TrustPolicyWarning{{
			Code: acquisition.TrustPolicyWarningMutableReference,
		}},
	})
	assertAcquisitionObjectKeys(t, resultRaw, []string{"decision", "errors", "warnings"})
	assertFirstAcquisitionArrayObjectKeys(t, resultRaw, "errors", []string{"code"})
	assertFirstAcquisitionArrayObjectKeys(t, resultRaw, "warnings", []string{"code"})
}

func TestTrustPolicyContractsAvoidUnsafeRawMetadataSurface(t *testing.T) {
	unsafeNames := []string{
		"localPath",
		"path",
		"credential",
		"token",
		"query",
		"auth",
		"registryAuth",
		"command",
		"factory",
		"runtimeDriver",
		"driver",
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(acquisition.TrustPolicyRequest{}),
		reflect.TypeOf(acquisition.TrustPolicySource{}),
		reflect.TypeOf(acquisition.TrustPolicyReferenceRequirement{}),
		reflect.TypeOf(acquisition.TrustPolicyResult{}),
		reflect.TypeOf(acquisition.TrustPolicyEnforcementMetadata{}),
		reflect.TypeOf(acquisition.TrustPolicyError{}),
		reflect.TypeOf(acquisition.TrustPolicyWarning{}),
	} {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
				lowerName := strings.ToLower(field.Name + " " + jsonName)
				for _, unsafeName := range unsafeNames {
					if strings.Contains(lowerName, strings.ToLower(unsafeName)) {
						t.Fatalf("%s.%s exposes unsafe policy metadata surface %q", typ.Name(), field.Name, unsafeName)
					}
				}
				if field.Type == reflect.TypeOf(acquisition.TemplateSource{}) || field.Type == reflect.TypeOf((*acquisition.TemplateSource)(nil)) {
					t.Fatalf("%s.%s uses TemplateSource, which can carry raw local paths or refs", typ.Name(), field.Name)
				}
				if field.Type == reflect.TypeOf(sandboxtemplate.RuntimeDriver("")) {
					t.Fatalf("%s.%s uses runtime driver metadata", typ.Name(), field.Name)
				}
			}
		})
	}
}

func assertAcquisitionField(t *testing.T, typ reflect.Type, fieldName string, wantType reflect.Type, wantTag string) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s missing field %s", typ.Name(), fieldName)
	}
	if field.Type != wantType {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), fieldName, field.Type, wantType)
	}
	if got := string(field.Tag); got != wantTag {
		t.Fatalf("%s.%s tag = %q, want %q", typ.Name(), fieldName, got, wantTag)
	}
}

func mustAcquisitionObject(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return raw
}

func assertAcquisitionObjectKeys(t *testing.T, raw any, keys []string) {
	t.Helper()
	object, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("object = %T, want map", raw)
	}
	if len(object) != len(keys) {
		t.Fatalf("keys = %#v, want %#v", sortedAcquisitionKeys(object), keys)
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			t.Fatalf("keys = %#v, missing %q", sortedAcquisitionKeys(object), key)
		}
	}
}

func assertNestedAcquisitionKeys(t *testing.T, raw map[string]any, key string, keys []string) {
	t.Helper()
	nested, ok := raw[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, raw[key])
	}
	assertAcquisitionObjectKeys(t, nested, keys)
}

func assertFirstAcquisitionArrayObjectKeys(t *testing.T, raw map[string]any, key string, keys []string) {
	t.Helper()
	array, ok := raw[key].([]any)
	if !ok || len(array) == 0 {
		t.Fatalf("%s = %#v, want non-empty array", key, raw[key])
	}
	assertAcquisitionObjectKeys(t, array[0], keys)
}

func sortedAcquisitionKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
