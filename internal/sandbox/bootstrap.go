package sandbox

import "strings"

const defaultSetupScriptURL = "https://raw.githubusercontent.com/ReScienceLab/hal/main/sandbox/setup.sh"

func appendSetupScriptRunner(b *strings.Builder, indent string) {
	b.WriteString(indent)
	b.WriteString("setup_url=\"${HAL_SETUP_URL:-")
	b.WriteString(defaultSetupScriptURL)
	b.WriteString("}\"\n")
	b.WriteString(indent)
	b.WriteString("if [ -n \"${GITHUB_TOKEN:-}\" ]; then\n")
	b.WriteString(indent)
	b.WriteString("  header_file=$(mktemp)\n")
	b.WriteString(indent)
	b.WriteString("  trap 'rm -f \"$header_file\"' EXIT\n")
	b.WriteString(indent)
	b.WriteString("  printf 'Authorization: Bearer %s\\n' \"$GITHUB_TOKEN\" > \"$header_file\"\n")
	b.WriteString(indent)
	b.WriteString("  curl -fsSL -H @\"$header_file\" \"$setup_url\" | bash\n")
	b.WriteString(indent)
	b.WriteString("else\n")
	b.WriteString(indent)
	b.WriteString("  curl -fsSL \"$setup_url\" | bash\n")
	b.WriteString(indent)
	b.WriteString("fi\n")
}
