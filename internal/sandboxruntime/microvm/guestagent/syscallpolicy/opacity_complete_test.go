package syscallpolicy

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestCompleteOpaqueSurfaceRejectsFormattingAndSerialization(t *testing.T) {
	values := []any{
		WorkloadSnapshot{}, WorkloadRuleView{}, RuntimeProfileView{}, CatalogEntryView{}, MandatoryEvidenceView{},
		RuleView{}, FilterRuleView{}, FilterProfile{}, ScalarClauseView{}, DescriptorRequirementView{},
		PointerRequirementView{}, ObjectRequirementView{}, TransitionView{}, PinnedCallsiteRequirementView{},
		PinnedBinaryBindingView{}, PinnedCallsiteEvidenceView{}, Policy{}, Classification{}, FilterDecision{},
		Decision{}, AdapterDecision{}, AdapterTicket{}, AdapterPermit{}, AdapterBindings{}, AdapterBindingView{},
		BindingQuery{}, BindingObservation{}, StateQuery{}, StateObservation{}, FDQuery{}, FDObservation{},
		PointerQuery{}, PointerObservation{}, ObjectQuery{}, ObjectObservation{},
	}
	for _, value := range values {
		name := reflect.TypeOf(value).Name()
		t.Run(name, func(t *testing.T) {
			if got := fmt.Sprintf("%+v", value); got != opaqueFormat {
				t.Fatalf("format = %q", got)
			}
			if _, ok := value.(fmt.Stringer); !ok {
				t.Fatal("missing fmt.Stringer")
			}
			if _, ok := value.(fmt.GoStringer); !ok {
				t.Fatal("missing fmt.GoStringer")
			}
			if _, ok := value.(json.Marshaler); !ok {
				t.Fatal("missing json.Marshaler")
			}
			if _, ok := value.(encoding.TextMarshaler); !ok {
				t.Fatal("missing encoding.TextMarshaler")
			}
			if _, ok := value.(encoding.BinaryMarshaler); !ok {
				t.Fatal("missing encoding.BinaryMarshaler")
			}
			if encoded, err := json.Marshal(value); err == nil || encoded != nil {
				t.Fatal("JSON marshal did not fail closed")
			}

			pointer := reflect.New(reflect.TypeOf(value)).Interface()
			if _, ok := pointer.(json.Unmarshaler); !ok {
				t.Fatal("missing json.Unmarshaler")
			}
			if _, ok := pointer.(encoding.TextUnmarshaler); !ok {
				t.Fatal("missing encoding.TextUnmarshaler")
			}
			if _, ok := pointer.(encoding.BinaryUnmarshaler); !ok {
				t.Fatal("missing encoding.BinaryUnmarshaler")
			}
			before := reflect.ValueOf(pointer).Elem().Interface()
			if err := pointer.(json.Unmarshaler).UnmarshalJSON([]byte(`{"forged":true}`)); err == nil {
				t.Fatal("JSON unmarshal did not fail closed")
			}
			if !reflect.DeepEqual(before, reflect.ValueOf(pointer).Elem().Interface()) {
				t.Fatal("unmarshal mutated receiver")
			}
		})
	}
}
