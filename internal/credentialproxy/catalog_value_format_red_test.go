package credentialproxy

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestL8CredentialProxyCatalogValueFormsDenyLiveInspection(t *testing.T) {
	forms := []struct {
		name string
		make func(*StaticServiceCatalog) any
	}{
		{name: "pointer", make: func(catalog *StaticServiceCatalog) any { return catalog }},
		{name: "value", make: func(catalog *StaticServiceCatalog) any { return *catalog }},
		{name: "pointer interface", make: func(catalog *StaticServiceCatalog) any { var value any = catalog; return value }},
		{name: "value interface", make: func(catalog *StaticServiceCatalog) any { var value any = *catalog; return value }},
	}
	for _, tt := range forms {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := NewStaticServiceCatalog(
				"catalog-generation-01",
				CatalogOwnerHostAdmin,
				l8FixtureAzureDefinition(t),
			)
			if err != nil {
				t.Fatalf("NewStaticServiceCatalog() error = %v", err)
			}
			assertCredentialProxyCatalogFormDenied(t, tt.make(catalog))
		})
	}
}

func assertCredentialProxyCatalogFormDenied(t *testing.T, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if len(payload) != 0 || !errors.Is(err, ErrLiveCatalogStateNotSerializable) {
		t.Errorf("json.Marshal(%T) = %q, %v, want stable live-state denial", value, payload, err)
	}
	if marshaler, ok := value.(json.Marshaler); !ok {
		t.Errorf("%T does not implement json.Marshaler", value)
	} else if payload, marshalErr := marshaler.MarshalJSON(); len(payload) != 0 || marshalErr != ErrLiveCatalogStateNotSerializable {
		t.Errorf("MarshalJSON(%T) = %q, %v, want stable live-state denial", value, payload, marshalErr)
	}
	if marshaler, ok := value.(encoding.TextMarshaler); !ok {
		t.Errorf("%T does not implement encoding.TextMarshaler", value)
	} else if payload, marshalErr := marshaler.MarshalText(); len(payload) != 0 || marshalErr != ErrLiveCatalogStateNotSerializable {
		t.Errorf("MarshalText(%T) = %q, %v, want stable live-state denial", value, payload, marshalErr)
	}
	if errorValue, ok := value.(error); !ok {
		t.Errorf("%T does not implement safe error rendering", value)
	} else {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, errorValue.Error())
	}
	if stringer, ok := value.(fmt.Stringer); !ok {
		t.Errorf("%T does not implement fmt.Stringer", value)
	} else {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, stringer.String())
	}
	if stringer, ok := value.(fmt.GoStringer); !ok {
		t.Errorf("%T does not implement fmt.GoStringer", value)
	} else {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, stringer.GoString())
	}
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v"} {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, fmt.Sprintf(format, value))
	}
}
