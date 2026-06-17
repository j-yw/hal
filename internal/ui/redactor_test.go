package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactor_RedactsSecretsAndAddresses(t *testing.T) {
	r := Redactor{
		KnownAddresses: []string{"203.0.113.10", "hal-dev"},
		KnownSecrets:   []string{"sk-test-secret"},
	}

	got := r.Redact("token=sk-test-secret public=203.0.113.10 host=hal-dev tailscale=100.64.0.7 v6=2001:db8::1")

	for _, unwanted := range []string{"sk-test-secret", "203.0.113.10", "hal-dev", "100.64.0.7", "2001:db8::1"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("Redact() leaked %q in %q", unwanted, got)
		}
	}
	if strings.Count(got, secretPlaceholder) != 1 {
		t.Fatalf("Redact() secret placeholders = %d, want 1 in %q", strings.Count(got, secretPlaceholder), got)
	}
	if strings.Count(got, addressPlaceholder) != 4 {
		t.Fatalf("Redact() address placeholders = %d, want 4 in %q", strings.Count(got, addressPlaceholder), got)
	}
}

func TestRedactor_ShowAddressesStillRedactsSecrets(t *testing.T) {
	r := Redactor{
		ShowAddresses:  true,
		KnownAddresses: []string{"203.0.113.10"},
		KnownSecrets:   []string{"sk-test-secret"},
	}

	got := r.Redact("token=sk-test-secret public=203.0.113.10")

	if strings.Contains(got, "sk-test-secret") {
		t.Fatalf("Redact() leaked secret in %q", got)
	}
	if !strings.Contains(got, "203.0.113.10") {
		t.Fatalf("Redact() hid address despite ShowAddresses=true: %q", got)
	}
}

func TestRedactingWriter_RedactsAcrossSplitWrites(t *testing.T) {
	var buf bytes.Buffer
	w := NewRedactingWriter(&buf, Redactor{})

	if _, err := w.Write([]byte("provider says 203.0.")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if _, err := w.Write([]byte("113.10")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	got := buf.String()
	if strings.Contains(got, "203.0.113.10") {
		t.Fatalf("RedactingWriter leaked split address: %q", got)
	}
	if !strings.Contains(got, addressPlaceholder) {
		t.Fatalf("RedactingWriter output missing redaction placeholder: %q", got)
	}
}
