package rootlesspodman

import (
	"strings"
	"testing"
)

func TestL7RawPacketProcStatusRequiresEveryZeroCapabilitySetAndNoNewPrivs(t *testing.T) {
	valid := validRawPacketProcStatusFixture()
	if err := validateRawPacketProcStatus([]byte(valid), int64(len(valid))); err != nil {
		t.Fatalf("validateRawPacketProcStatus(valid) unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		status string
	}{
		{name: "missing inheritable", status: strings.Replace(valid, "CapInh:\t0000000000000000\n", "", 1)},
		{name: "duplicate permitted", status: valid + "CapPrm:\t0000000000000000\n"},
		{name: "malformed effective", status: strings.Replace(valid, "CapEff:\t0000000000000000", "CapEff:\tzero", 1)},
		{name: "truncated bounding", status: strings.Replace(valid, "CapBnd:\t0000000000000000", "CapBnd:\t000000000000000", 1)},
		{name: "nonzero inheritable", status: strings.Replace(valid, "CapInh:\t0000000000000000", "CapInh:\t0000000000000001", 1)},
		{name: "nonzero permitted", status: strings.Replace(valid, "CapPrm:\t0000000000000000", "CapPrm:\t0000000000002000", 1)},
		{name: "nonzero effective", status: strings.Replace(valid, "CapEff:\t0000000000000000", "CapEff:\t0000000000001000", 1)},
		{name: "nonzero bounding", status: strings.Replace(valid, "CapBnd:\t0000000000000000", "CapBnd:\t0000000000200000", 1)},
		{name: "nonzero ambient", status: strings.Replace(valid, "CapAmb:\t0000000000000000", "CapAmb:\t0000000000002000", 1)},
		{name: "missing no new privs", status: strings.Replace(valid, "NoNewPrivs:\t1\n", "", 1)},
		{name: "no new privs disabled", status: strings.Replace(valid, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)},
		{name: "truncated file", status: strings.TrimSuffix(valid, "\n")},
		{name: "NUL substitution", status: strings.Replace(valid, "CapEff:", "CapEff:\x00", 1)},
		{name: "oversized", status: valid + strings.Repeat("x", 1024)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := int64(len(tt.status))
			if tt.name == "oversized" {
				limit = int64(len(valid))
			}
			if err := validateRawPacketProcStatus([]byte(tt.status), limit); err == nil {
				t.Fatal("validateRawPacketProcStatus() error = nil, want fail-closed rejection")
			}
		})
	}
}

func TestL7RawPacketProcStatRequiresExactPIDAndStableStartIdentity(t *testing.T) {
	const stat = "4242 (sleep) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99999 20\n"
	start, err := parseRawPacketProcStartTime([]byte(stat), 4242)
	if err != nil || start != "99999" {
		t.Fatalf("parseRawPacketProcStartTime() = %q, %v, want 99999", start, err)
	}
	for _, invalid := range []string{
		"4243 (sleep) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99999 20\n",
		"4242 (truncated) S 1 2 3\n",
		"4242 malformed\n",
		"4242 (sleep) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 zero 20\n",
	} {
		if _, err := parseRawPacketProcStartTime([]byte(invalid), 4242); err == nil {
			t.Fatalf("parseRawPacketProcStartTime(%q) error = nil, want rejection", invalid)
		}
	}
}

func validRawPacketProcStatusFixture() string {
	return "Name:\tsleep\n" +
		"CapInh:\t0000000000000000\n" +
		"CapPrm:\t0000000000000000\n" +
		"CapEff:\t0000000000000000\n" +
		"CapBnd:\t0000000000000000\n" +
		"CapAmb:\t0000000000000000\n" +
		"NoNewPrivs:\t1\n"
}
