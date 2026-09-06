//go:build linux

package minimalprofile

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// ReadPublishRequest authenticates a bounded immutable copy before decoding.
// expectedSHA256 must come from the trusted build receipt channel, not from a
// checksum adjacent to an untrusted staged archive or candidate bundle.
func ReadPublishRequest(name, expectedSHA256 string) (PublishRequest, error) {
	dir, err := os.MkdirTemp("", "hal-minimal-request-")
	if err != nil {
		return PublishRequest{}, errImage
	}
	defer os.RemoveAll(dir)
	snapshot := filepath.Join(dir, "request.json")
	if _, err := copyPinned(name, snapshot, expectedSHA256, 4<<20); err != nil {
		return PublishRequest{}, errImage
	}
	data, err := os.ReadFile(snapshot)
	if err != nil || digestBytes(data) != expectedSHA256 {
		return PublishRequest{}, errImage
	}
	var request PublishRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return PublishRequest{}, errImage
	}
	return request, nil
}
