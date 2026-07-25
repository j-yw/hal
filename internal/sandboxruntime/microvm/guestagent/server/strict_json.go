package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

func strictRequestObject(encoded []byte) error {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return fmt.Errorf("request must be one UTF-8 JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	root, ok := token.(json.Delim)
	if !ok || root != '{' {
		return fmt.Errorf("request root must be an object")
	}
	if err := strictObjectTokens(decoder, 1); err != nil {
		return err
	}
	return strictJSONEOF(decoder)
}

func strictDecodeRequest(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return strictJSONEOF(decoder)
}

func strictObjectTokens(decoder *json.Decoder, depth int) error {
	if depth > MaximumJSONNestingDepth {
		return fmt.Errorf("request JSON nesting exceeds limit")
	}
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("request JSON object key is malformed")
		}
		if _, duplicate := keys[key]; duplicate {
			return fmt.Errorf("request JSON contains duplicate key")
		}
		keys[key] = struct{}{}
		if err := strictValueTokens(decoder, depth+1); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return fmt.Errorf("request JSON object is not terminated")
	}
	return nil
}

func strictArrayTokens(decoder *json.Decoder, depth int) error {
	if depth > MaximumJSONNestingDepth {
		return fmt.Errorf("request JSON nesting exceeds limit")
	}
	for decoder.More() {
		if err := strictValueTokens(decoder, depth+1); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return fmt.Errorf("request JSON array is not terminated")
	}
	return nil
}

func strictValueTokens(decoder *json.Decoder, depth int) error {
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
		return strictObjectTokens(decoder, depth)
	case '[':
		return strictArrayTokens(decoder, depth)
	default:
		return fmt.Errorf("request JSON delimiter is malformed")
	}
}

func strictJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("request JSON contains trailing data")
}
