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

func TestRedactor_PreservesCSSPseudoSelectors(t *testing.T) {
	r := Redactor{}
	input := `.collection-ripple::before { content: ""; }
.collection-ripple::after { content: ""; }
li::marker { color: red; }
main::-webkit-scrollbar { width: 8px; }`

	got := r.Redact(input)
	if got != input {
		t.Fatalf("Redact() changed CSS pseudo selectors:\n got: %q\nwant: %q", got, input)
	}
	if strings.Contains(got, addressPlaceholder) {
		t.Fatalf("Redact() inserted address placeholder into CSS selectors: %q", got)
	}
}

func TestRedactor_StillRedactsIPv6Addresses(t *testing.T) {
	r := Redactor{}
	got := r.Redact("v6=2001:db8::1 bracket=[2001:db8::2]")

	for _, unwanted := range []string{"2001:db8::1", "2001:db8::2"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("Redact() leaked IPv6 address %q in %q", unwanted, got)
		}
	}
	if strings.Count(got, addressPlaceholder) != 2 {
		t.Fatalf("Redact() address placeholders = %d, want 2 in %q", strings.Count(got, addressPlaceholder), got)
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

func TestRedactingWriter_PreservesCSSPseudoSelectorAcrossSplitWrites(t *testing.T) {
	var buf bytes.Buffer
	w := NewRedactingWriter(&buf, Redactor{})

	if _, err := w.Write([]byte(".collection-ripple:")); err != nil {
		t.Fatalf("Write() first chunk error: %v", err)
	}
	if _, err := w.Write([]byte(":before { content: \"\"; }")); err != nil {
		t.Fatalf("Write() second chunk error: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	got := buf.String()
	want := `.collection-ripple::before { content: ""; }`
	if got != want {
		t.Fatalf("RedactingWriter changed CSS selector: got %q, want %q", got, want)
	}
}

func TestRedactingWriter_RedactsAcrossLongLineFlushBoundary(t *testing.T) {
	tests := []struct {
		name        string
		redactor    Redactor
		sensitive   string
		placeholder string
	}{
		{
			name:        "secret",
			redactor:    Redactor{KnownSecrets: []string{"sk-long-boundary-secret"}},
			sensitive:   "sk-long-boundary-secret",
			placeholder: secretPlaceholder,
		},
		{
			name:        "address",
			redactor:    Redactor{},
			sensitive:   "203.0.113.10",
			placeholder: addressPlaceholder,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewRedactingWriter(&buf, tt.redactor)
			line := tt.sensitive + " " + strings.Repeat("x", redactionTailBytes-len(tt.sensitive))

			if _, err := w.Write([]byte(line)); err != nil {
				t.Fatalf("Write() error: %v", err)
			}
			if err := w.Flush(); err != nil {
				t.Fatalf("Flush() error: %v", err)
			}

			got := buf.String()
			if strings.Contains(got, tt.sensitive) {
				t.Fatalf("RedactingWriter leaked value across long-line flush boundary: %q", got)
			}
			if !strings.Contains(got, tt.placeholder) {
				t.Fatalf("RedactingWriter output missing redaction placeholder: %q", got)
			}
		})
	}
}

func TestRedactingWriter_RedactsLongKnownSecretAcrossTailBoundary(t *testing.T) {
	var buf bytes.Buffer
	secret := "sk-" + strings.Repeat("s", redactionTailBytes+128)
	w := NewRedactingWriter(&buf, Redactor{KnownSecrets: []string{secret}})

	firstChunkLen := redactionTailBytes + 1
	if _, err := w.Write([]byte(secret[:firstChunkLen])); err != nil {
		t.Fatalf("Write() first chunk error: %v", err)
	}
	if _, err := w.Write([]byte(secret[firstChunkLen:] + " suffix")); err != nil {
		t.Fatalf("Write() second chunk error: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	got := buf.String()
	if strings.Contains(got, secret) {
		t.Fatalf("RedactingWriter leaked long known secret across tail boundary: %q", got)
	}
	if !strings.Contains(got, secretPlaceholder) {
		t.Fatalf("RedactingWriter output missing redaction placeholder: %q", got)
	}
}
