package cmd

import "testing"

// Job log records are chunks that may span many lines. A sensitive line must
// not take the rest of the chunk with it, or the run summary disappears.
func TestSandboxWorkerJobLogDataRedactsOnlySensitiveLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{
			name: "absolute path line among summary lines",
			data: "✓ All stories complete after 1 iteration(s).\nwrote /root/workspace/private/report.md\nDuration: 2m 47s\n",
			want: "✓ All stories complete after 1 iteration(s).\n[redacted]\nDuration: 2m 47s\n",
		},
		{
			name: "secret assignment line keeps neighbours",
			data: "PRD: Progress: 1/1 stories complete (100%)\nGITHUB_TOKEN=ghp_examplevalue\n",
			want: "PRD: Progress: 1/1 stories complete (100%)\n[redacted]\n",
		},
		{
			name: "single sensitive line without newline",
			data: "API_KEY=abcdef",
			want: "[redacted]",
		},
		{
			name: "carriage returns are preserved",
			data: "step one\r\nstep two\r\n",
			want: "step one\r\nstep two\r\n",
		},
		{
			name: "clean chunk unchanged",
			data: "Last story: US-001 — Add greet helper\n",
			want: "Last story: US-001 — Add greet helper\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeSandboxWorkerJobLogData(tc.data); got != tc.want {
				t.Fatalf("sanitizeSandboxWorkerJobLogData() =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}
