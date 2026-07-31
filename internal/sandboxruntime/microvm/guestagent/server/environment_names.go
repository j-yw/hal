package server

func validLinuxEnvironmentName(name string) bool {
	if name == "http_proxy" || name == "https_proxy" {
		return true
	}
	if name == "" {
		return false
	}
	for index, char := range name {
		switch {
		case char >= 'A' && char <= 'Z':
		case char == '_':
		case index > 0 && char >= '0' && char <= '9':
		default:
			return false
		}
	}
	return true
}
