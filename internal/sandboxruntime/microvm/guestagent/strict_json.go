package guestagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const maxStrictJSONDepth = 64

func strictUnmarshalObject(encoded []byte, destination any) error {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return fmt.Errorf("response must be one UTF-8 JSON object")
	}
	if err := validateStrictJSONObject(encoded, maxStrictJSONDepth); err != nil {
		return err
	}
	if err := validateCanonicalJSONFields(encoded, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func validateCanonicalJSONFields(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return validateCanonicalJSONValue(value, reflect.TypeOf(destination))
}

func validateCanonicalJSONValue(value any, destinationType reflect.Type) error {
	for destinationType != nil && destinationType.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		destinationType = destinationType.Elem()
	}
	if destinationType == nil {
		return nil
	}
	if value == nil {
		switch destinationType.Kind() {
		case reflect.Interface, reflect.Map, reflect.Slice:
			return nil
		default:
			return fmt.Errorf("JSON value has noncanonical null type")
		}
	}

	switch destinationType.Kind() {
	case reflect.Interface:
		return nil
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("JSON value must be an object")
		}
		fields := canonicalJSONStructFields(destinationType)
		for name, nested := range object {
			fieldType, known := fields[name]
			if !known {
				return fmt.Errorf("JSON object contains noncanonical or unknown field")
			}
			if err := validateCanonicalJSONValue(nested, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return fmt.Errorf("JSON value must be an array")
		}
		if destinationType.Kind() == reflect.Array && len(values) != destinationType.Len() {
			return fmt.Errorf("JSON array length is noncanonical")
		}
		for _, nested := range values {
			if err := validateCanonicalJSONValue(nested, destinationType.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("JSON value must be an object")
		}
		for _, nested := range object {
			if err := validateCanonicalJSONValue(nested, destinationType.Elem()); err != nil {
				return err
			}
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("JSON value must be a boolean")
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("JSON value must be a string")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Uintptr, reflect.Float32, reflect.Float64:
		if _, ok := value.(json.Number); !ok {
			return fmt.Errorf("JSON value must be a number")
		}
	}
	return nil
}

func canonicalJSONStructFields(structType reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, structType.NumField())
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func validateStrictJSONObject(encoded []byte, maximumDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	root, ok := token.(json.Delim)
	if !ok || root != '{' {
		return fmt.Errorf("JSON root must be an object")
	}
	if err := validateStrictObjectTokens(decoder, 1, maximumDepth); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateStrictObjectTokens(decoder *json.Decoder, depth, maximumDepth int) error {
	if depth > maximumDepth {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("JSON object key is malformed")
		}
		if _, duplicate := keys[key]; duplicate {
			return fmt.Errorf("JSON object contains duplicate key")
		}
		keys[key] = struct{}{}
		if err := validateStrictValueTokens(decoder, depth+1, maximumDepth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return fmt.Errorf("JSON object is not terminated")
	}
	return nil
}

func validateStrictArrayTokens(decoder *json.Decoder, depth, maximumDepth int) error {
	if depth > maximumDepth {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	for decoder.More() {
		if err := validateStrictValueTokens(decoder, depth+1, maximumDepth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return fmt.Errorf("JSON array is not terminated")
	}
	return nil
}

func validateStrictValueTokens(decoder *json.Decoder, depth, maximumDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return validateStrictObjectTokens(decoder, depth, maximumDepth)
	case '[':
		return validateStrictArrayTokens(decoder, depth, maximumDepth)
	default:
		return fmt.Errorf("JSON value delimiter is malformed")
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("JSON contains trailing data")
}
