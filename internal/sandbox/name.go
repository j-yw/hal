package sandbox

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	maxSandboxNameLength   = 59
	tailscalePrefixSandbox = "hal-"
	defaultSandboxName     = "sandbox"
)

// ValidateName validates sandbox names used across files, providers, and Tailscale.
func ValidateName(name string) error {
	if len(name) < 1 || len(name) > maxSandboxNameLength {
		return errors.New("must be 1-59 chars")
	}

	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return errors.New("must not start or end with hyphen")
	}

	for i := 0; i < len(name); i++ {
		c := name[i]
		isLowerAlpha := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isHyphen := c == '-'
		if !isLowerAlpha && !isDigit && !isHyphen {
			return errors.New("must be lowercase alphanumeric and hyphens")
		}

		if isHyphen && i > 0 && name[i-1] == '-' {
			return errors.New("must not contain consecutive hyphens")
		}
	}

	return nil
}

// TailscaleHostname returns the hostname used for Tailscale DNS.
func TailscaleHostname(name string) string {
	return tailscalePrefixSandbox + name
}

// SandboxNameFromBranch derives a valid sandbox name from a git branch name.
func SandboxNameFromBranch(branch string) string {
	sanitized := sanitizeName(branch)
	if len(sanitized) > maxSandboxNameLength {
		sanitized = strings.Trim(sanitized[:maxSandboxNameLength], "-")
	}
	if sanitized == "" {
		return defaultSandboxName
	}
	return sanitized
}

// BatchNames returns count names as {base}-NN style values.
func BatchNames(base string, count int) ([]string, error) {
	if count < 1 {
		return nil, errors.New("count must be at least 1")
	}

	width := len(strconv.Itoa(count))
	if width < 2 {
		width = 2
	}

	suffixLen := 1 + width // "-" + padded number
	if len(base)+suffixLen > maxSandboxNameLength {
		return nil, fmt.Errorf("base name %q with suffix width %d exceeds %d chars", base, width, maxSandboxNameLength)
	}

	names := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		name := fmt.Sprintf("%s-%0*d", base, width, i)
		if err := ValidateName(name); err != nil {
			return nil, fmt.Errorf("invalid generated name %q: %w", name, err)
		}
		names = append(names, name)
	}

	return names, nil
}

func sanitizeName(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(input))

	lastWasHyphen := false
	for i := 0; i < len(input); i++ {
		c := input[i]
		isLowerAlpha := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'

		if isLowerAlpha || isDigit {
			builder.WriteByte(c)
			lastWasHyphen = false
			continue
		}

		if !lastWasHyphen {
			builder.WriteByte('-')
			lastWasHyphen = true
		}
	}

	return strings.Trim(builder.String(), "-")
}
