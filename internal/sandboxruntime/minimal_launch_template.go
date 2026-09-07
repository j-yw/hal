package sandboxruntime

import "strings"

// TemplateIdentity returns original intent even after revocation or expiry.
// It grants no image trust, launch, credential or cleanup authority.
func (reservation *MinimalLaunchReservation) TemplateIdentity() (MinimalLaunchTemplateIdentity, error) {
	if reservation == nil || reservation.self != reservation || !ValidMinimalLaunchTemplateIdentity(reservation.templateIdentity) {
		return MinimalLaunchTemplateIdentity{}, ErrMinimalLaunchUnavailable
	}
	return reservation.templateIdentity, nil
}

// ValidMinimalLaunchTemplateIdentity checks only the bounded selected syntax.
// The three digest roles are distinct; none establishes a measured rootfs pin.
func ValidMinimalLaunchTemplateIdentity(value MinimalLaunchTemplateIdentity) bool {
	for _, digest := range []string{value.TemplateDocumentSHA256, value.TemplateManifestSHA256, value.RuntimeImageSHA256} {
		if len(digest) != 64 {
			return false
		}
		for index := range len(digest) {
			if c := digest[index]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	image := value.RuntimeImage
	if len(image) > 4096 || !strings.HasSuffix(image, "@sha256:"+value.RuntimeImageSHA256) {
		return false
	}
	prefix := image[:len(image)-len("@sha256:")-64]
	if len(prefix) == 0 || strings.Contains(prefix, "://") {
		return false
	}
	for index := range len(prefix) {
		c := prefix[index]
		alphanumeric := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alphanumeric && (index == 0 || c != '.' && c != '_' && c != ':' && c != '/' && c != '-') {
			return false
		}
	}
	return true
}
