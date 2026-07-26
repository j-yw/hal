package registry

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
)

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func decodeManifest(data []byte, responseContentType string, maxLayerBytes int) (descriptor, error) {
	mediaType, _, err := mime.ParseMediaType(responseContentType)
	if err != nil || mediaType != MediaTypeOCIManifest {
		return descriptor{}, coded(ErrorCodeManifestMediaTypeUnsupported, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded manifest
	if err := decoder.Decode(&decoded); err != nil {
		return descriptor{}, coded(ErrorCodeManifestInvalid, nil)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return descriptor{}, coded(ErrorCodeManifestInvalid, nil)
	}
	if decoded.SchemaVersion != 2 {
		return descriptor{}, coded(ErrorCodeManifestInvalid, nil)
	}
	if decoded.MediaType != MediaTypeOCIManifest {
		return descriptor{}, coded(ErrorCodeManifestMediaTypeUnsupported, nil)
	}
	if decoded.MediaType != mediaType {
		return descriptor{}, coded(ErrorCodeManifestMediaTypeUnsupported, nil)
	}
	if decoded.ArtifactType != MediaTypeTemplateArtifact {
		return descriptor{}, coded(ErrorCodeArtifactTypeUnsupported, nil)
	}
	if decoded.Config.MediaType != MediaTypeOCIEmptyConfig ||
		!validDigest(decoded.Config.Digest) ||
		decoded.Config.Size < 0 ||
		decoded.Config.Size > 2 {
		return descriptor{}, coded(ErrorCodeManifestInvalid, nil)
	}
	if len(decoded.Layers) != 1 {
		return descriptor{}, coded(ErrorCodeLayerCountInvalid, nil)
	}
	layer := decoded.Layers[0]
	if layer.MediaType != MediaTypeTemplateYAML && layer.MediaType != MediaTypeTemplateJSON {
		return descriptor{}, coded(ErrorCodeLayerMediaTypeUnsupported, nil)
	}
	if !validDigest(layer.Digest) || layer.Size < 0 {
		return descriptor{}, coded(ErrorCodeManifestInvalid, nil)
	}
	if layer.Size > int64(maxLayerBytes) {
		return descriptor{}, coded(ErrorCodeLayerOversize, nil)
	}
	return layer, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return io.ErrUnexpectedEOF
	}
	return err
}

func validDigest(value string) bool {
	return len(value) == len("sha256:")+64 &&
		value[:len("sha256:")] == "sha256:" &&
		sha256Pattern.MatchString(value[len("sha256:"):])
}
