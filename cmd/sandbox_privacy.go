package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	ui "github.com/jywlabs/hal/internal/ui"
)

var sandboxShowAddresses bool

func sandboxRedactor(showAddresses bool, env map[string]string, instances ...*sandbox.SandboxState) ui.Redactor {
	redactor := ui.Redactor{ShowAddresses: showAddresses}
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		redactor.KnownAddresses = append(redactor.KnownAddresses,
			inst.IP,
			inst.TailscaleIP,
			inst.TailscaleHostname,
			sandbox.PreferredIP(inst),
		)
	}
	for key, value := range env {
		if isSensitiveEnvKey(key) {
			redactor.KnownSecrets = append(redactor.KnownSecrets, value)
		}
	}
	return redactor
}

func sandboxRedactingWriter(out io.Writer, redactor ui.Redactor) *ui.RedactingWriter {
	if out == nil {
		return nil
	}
	return ui.NewRedactingWriter(out, redactor)
}

func sandboxFlushRedactor(w *ui.RedactingWriter) {
	if w != nil {
		_ = w.Flush()
	}
}

func sandboxSanitizeError(err error, redactor ui.Redactor) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", redactor.Redact(err.Error()))
}

func isSensitiveEnvKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	return strings.Contains(key, "KEY") ||
		strings.Contains(key, "TOKEN") ||
		strings.Contains(key, "SECRET") ||
		strings.Contains(key, "PASSWORD")
}

func sandboxAccessLabel(inst *sandbox.SandboxState) string {
	if inst == nil {
		return "unknown"
	}
	if strings.TrimSpace(inst.Status) == sandbox.StatusStopped {
		return "unavailable"
	}
	if strings.TrimSpace(inst.TailscaleIP) != "" {
		return "tailscale"
	}
	if strings.TrimSpace(inst.TailscaleHostname) != "" {
		return "tailscale pending"
	}
	if strings.TrimSpace(inst.IP) != "" {
		if inst.TailscaleLockdown {
			return "public blocked"
		}
		return "public fallback"
	}
	if inst.TailscaleLockdown {
		return "tailscale pending"
	}
	return "unknown"
}

func sandboxSSHCommand(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "hal sandbox ssh"
	}
	return "hal sandbox ssh " + name
}
