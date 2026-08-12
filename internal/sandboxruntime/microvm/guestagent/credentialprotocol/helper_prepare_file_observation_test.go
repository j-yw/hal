package credentialprotocol

import (
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestHelperPrepareFileObservationIsOnePointerSafeMetadataOnlyAndOpaque(t *testing.T) {
	typeOf := reflect.TypeOf(HelperPrepareFileObservation{})
	if typeOf.NumField() != 1 || typeOf.Field(0).Name != "owner" || typeOf.Field(0).IsExported() || typeOf.Field(0).Type.Kind() != reflect.Pointer || typeOf.Field(0).Tag != "" {
		t.Fatalf("observation layout = %#v", typeOf)
	}
	owner := typeOf.Field(0).Type.Elem()
	for index := 0; index < owner.NumField(); index++ {
		field := owner.Field(index)
		if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.String || field.Type.Kind() == reflect.Interface || field.Type.Kind() == reflect.Map {
			t.Errorf("owner field %s retains forbidden type %v", field.Name, field.Type)
		}
	}
	digest := sha256.Sum256([]byte("private"))
	value, err := NewHelperPrepareFileObservation(1, 0, 7, digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, opaque := range []any{value, &value} {
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", opaque, opaque, opaque, opaque, opaque); got != strings.Repeat("HelperPrepareFileObservation|", 4)+"HelperPrepareFileObservation" {
			t.Errorf("format = %q", got)
		}
		if _, err := json.Marshal(opaque); !errors.Is(err, ErrHelperPrepareObservationSerialize) {
			t.Errorf("JSON = %v", err)
		}
		if _, err := opaque.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrHelperPrepareObservationSerialize) {
			t.Errorf("text = %v", err)
		}
	}
}

func TestHelperPrepareFileObservationRejectsUnboundMetadata(t *testing.T) {
	digest := sha256.Sum256([]byte("private"))
	for name, makeObservation := range map[string]func() (HelperPrepareFileObservation, error){
		"revision": func() (HelperPrepareFileObservation, error) {
			return NewHelperPrepareFileObservation(2, 0, 7, digest, digest)
		},
		"index": func() (HelperPrepareFileObservation, error) {
			return NewHelperPrepareFileObservation(1, MaxHelperBindings, 7, digest, digest)
		},
		"length zero": func() (HelperPrepareFileObservation, error) {
			return NewHelperPrepareFileObservation(1, 0, 0, digest, digest)
		},
		"length high": func() (HelperPrepareFileObservation, error) {
			return NewHelperPrepareFileObservation(1, 0, MaxHelperFileBytes+1, digest, digest)
		},
		"zero digest": func() (HelperPrepareFileObservation, error) {
			return NewHelperPrepareFileObservation(1, 0, 7, [32]byte{}, [32]byte{})
		},
		"digest mismatch": func() (HelperPrepareFileObservation, error) {
			changed := digest
			changed[0]++
			return NewHelperPrepareFileObservation(1, 0, 7, digest, changed)
		},
	} {
		if _, err := makeObservation(); !errors.Is(err, ErrHelperPrepareFileObservation) {
			t.Errorf("%s = %v", name, err)
		}
	}
}
