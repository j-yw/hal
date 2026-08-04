package sandboxworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("worker JSON limit is invalid")
	}
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 {
			return nil, errors.New("worker JSON exceeds limit")
		}
		if n == 0 && probeErr == io.EOF {
			return raw, nil
		}
		if probeErr != nil {
			return nil, probeErr
		}
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}

func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeStoredJobStateV2Into(reader io.Reader, maxBytes int64, output *storedJobStateV2) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output); err != nil {
		return Response{}, err
	}
	return output, nil
}

func encodeWorkerResponse(writer io.Writer, response Response) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(response)
}

func validateWorkerJSONPreflightV2(raw string) error {
	if !utf8.ValidString(raw) {
		return errors.New("worker JSON text is invalid")
	}
	parser := workerJSONPreflightV2{raw: raw}
	if err := parser.parseValue(workerJSONPreflightRootV2); err != nil {
		return err
	}
	parser.skipSpace()
	if parser.offset != len(parser.raw) {
		return errors.New("worker JSON has trailing data")
	}
	return nil
}

const workerJSONPreflightMaxDepthV2 = 10_000

type workerJSONPreflightContextV2 uint8

const (
	workerJSONPreflightGenericV2 workerJSONPreflightContextV2 = iota
	workerJSONPreflightRootV2
	workerJSONPreflightJobV2
	workerJSONPreflightProductionFlagV2
)

type workerJSONPreflightV2 struct {
	raw    string
	offset int
	depth  int
}

func (parser *workerJSONPreflightV2) parseValue(context workerJSONPreflightContextV2) error {
	parser.skipSpace()
	if parser.offset >= len(parser.raw) {
		return errors.New("worker JSON is incomplete")
	}
	requiredProductionFlag := context == workerJSONPreflightProductionFlagV2
	if requiredProductionFlag && parser.raw[parser.offset] != '{' {
		return errors.New("worker JSON credential intent must be an object")
	}
	switch parser.raw[parser.offset] {
	case '{':
		return parser.parseObject(context)
	case '[':
		return parser.parseArray()
	case '"':
		_, err := parser.parseString()
		return err
	case 't':
		return parser.parseLiteral("true")
	case 'f':
		return parser.parseLiteral("false")
	case 'n':
		return parser.parseLiteral("null")
	default:
		return parser.parseNumber()
	}
}

func (parser *workerJSONPreflightV2) parseObject(context workerJSONPreflightContextV2) error {
	if err := parser.enterContainer(); err != nil {
		return err
	}
	defer parser.leaveContainer()
	requiredProductionFlag := context == workerJSONPreflightProductionFlagV2
	parser.offset++
	parser.skipSpace()
	seen := make(map[string]bool)
	productionFlagSeen := false
	if parser.consume('}') {
		if requiredProductionFlag {
			return errors.New("worker JSON productionCredentialsRequested is required")
		}
		return nil
	}
	for {
		key, err := parser.parseString()
		if err != nil {
			return err
		}
		if seen[key] {
			return errors.New("worker JSON contains duplicate object key")
		}
		seen[key] = true
		parser.skipSpace()
		if !parser.consume(':') {
			return errors.New("worker JSON object separator is invalid")
		}
		parser.skipSpace()
		if requiredProductionFlag && strings.EqualFold(key, "productionCredentialsRequested") {
			if productionFlagSeen {
				return errors.New("worker JSON contains duplicate object key")
			}
			if !strings.HasPrefix(parser.raw[parser.offset:], "true") && !strings.HasPrefix(parser.raw[parser.offset:], "false") {
				return errors.New("worker JSON productionCredentialsRequested must be boolean")
			}
			productionFlagSeen = true
		}
		if err := parser.parseValue(workerJSONPreflightChildContextV2(context, key)); err != nil {
			return err
		}
		parser.skipSpace()
		if parser.consume('}') {
			if requiredProductionFlag && !productionFlagSeen {
				return errors.New("worker JSON productionCredentialsRequested is required")
			}
			return nil
		}
		if !parser.consume(',') {
			return errors.New("worker JSON object separator is invalid")
		}
		parser.skipSpace()
	}
}

func (parser *workerJSONPreflightV2) parseArray() error {
	if err := parser.enterContainer(); err != nil {
		return err
	}
	defer parser.leaveContainer()
	parser.offset++
	parser.skipSpace()
	if parser.consume(']') {
		return nil
	}
	for {
		if err := parser.parseValue(workerJSONPreflightGenericV2); err != nil {
			return err
		}
		parser.skipSpace()
		if parser.consume(']') {
			return nil
		}
		if !parser.consume(',') {
			return errors.New("worker JSON array separator is invalid")
		}
		parser.skipSpace()
	}
}

func (parser *workerJSONPreflightV2) enterContainer() error {
	if parser.depth >= workerJSONPreflightMaxDepthV2 {
		return errors.New("worker JSON nesting exceeds limit")
	}
	parser.depth++
	return nil
}

func (parser *workerJSONPreflightV2) leaveContainer() {
	parser.depth--
}

func workerJSONPreflightChildContextV2(context workerJSONPreflightContextV2, key string) workerJSONPreflightContextV2 {
	switch {
	case context == workerJSONPreflightRootV2 && strings.EqualFold(key, "jobStartV2"):
		return workerJSONPreflightProductionFlagV2
	case context == workerJSONPreflightRootV2 && strings.EqualFold(key, "jobV2"):
		return workerJSONPreflightJobV2
	case context == workerJSONPreflightJobV2 && strings.EqualFold(key, "credentialIntent"):
		return workerJSONPreflightProductionFlagV2
	default:
		return workerJSONPreflightGenericV2
	}
}

func (parser *workerJSONPreflightV2) parseString() (string, error) {
	parser.skipSpace()
	if !parser.consume('"') {
		return "", errors.New("worker JSON object key is invalid")
	}
	start := parser.offset - 1
	escaped := false
	for parser.offset < len(parser.raw) {
		current := parser.raw[parser.offset]
		parser.offset++
		if current < 0x20 {
			return "", errors.New("worker JSON string is invalid")
		}
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if current == '"' {
			quoted := strings.ReplaceAll(parser.raw[start:parser.offset], `\/`, `/`)
			value, err := strconv.Unquote(quoted)
			if err != nil {
				return "", errors.New("worker JSON string is invalid")
			}
			return value, nil
		}
	}
	return "", errors.New("worker JSON string is incomplete")
}

func (parser *workerJSONPreflightV2) parseLiteral(literal string) error {
	if !strings.HasPrefix(parser.raw[parser.offset:], literal) {
		return errors.New("worker JSON literal is invalid")
	}
	parser.offset += len(literal)
	return nil
}

func (parser *workerJSONPreflightV2) parseNumber() error {
	start := parser.offset
	if parser.consume('-') && parser.offset >= len(parser.raw) {
		return errors.New("worker JSON number is invalid")
	}
	if parser.consume('0') {
		if parser.offset < len(parser.raw) && parser.raw[parser.offset] >= '0' && parser.raw[parser.offset] <= '9' {
			return errors.New("worker JSON number is noncanonical")
		}
	} else {
		if parser.offset >= len(parser.raw) || parser.raw[parser.offset] < '1' || parser.raw[parser.offset] > '9' {
			return errors.New("worker JSON number is invalid")
		}
		for parser.offset < len(parser.raw) && parser.raw[parser.offset] >= '0' && parser.raw[parser.offset] <= '9' {
			parser.offset++
		}
	}
	if parser.offset < len(parser.raw) && (parser.raw[parser.offset] == '.' || parser.raw[parser.offset] == 'e' || parser.raw[parser.offset] == 'E') {
		return errors.New("worker JSON number is noncanonical")
	}
	if parser.raw[start:parser.offset] == "-0" {
		return errors.New("worker JSON number is noncanonical")
	}
	return nil
}

func (parser *workerJSONPreflightV2) skipSpace() {
	for parser.offset < len(parser.raw) {
		switch parser.raw[parser.offset] {
		case ' ', '\t', '\r', '\n':
			parser.offset++
		default:
			return
		}
	}
}

func (parser *workerJSONPreflightV2) consume(value byte) bool {
	if parser.offset >= len(parser.raw) || parser.raw[parser.offset] != value {
		return false
	}
	parser.offset++
	return true
}
