package sandbox

import (
	"math"
	"testing"
	"time"
)

func TestEstimatedCost(t *testing.T) {
	baseTime := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		instance *SandboxState
		now      func() time.Time
		want     float64
	}{
		{
			name: "digitalocean s-1vcpu-2gb 10 hours",
			instance: &SandboxState{
				Provider:  "digitalocean",
				Size:      "s-1vcpu-2gb",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(10 * time.Hour) },
			want: 10 * 0.018,
		},
		{
			name: "digitalocean s-2vcpu-4gb 24 hours",
			instance: &SandboxState{
				Provider:  "digitalocean",
				Size:      "s-2vcpu-4gb",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(24 * time.Hour) },
			want: 24 * 0.036,
		},
		{
			name: "digitalocean s-4vcpu-8gb 48 hours",
			instance: &SandboxState{
				Provider:  "digitalocean",
				Size:      "s-4vcpu-8gb",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(48 * time.Hour) },
			want: 48 * 0.071,
		},
		{
			name: "hetzner cx22 100 hours",
			instance: &SandboxState{
				Provider:  "hetzner",
				Size:      "cx22",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(100 * time.Hour) },
			want: 100 * 0.007,
		},
		{
			name: "hetzner cx32 72 hours",
			instance: &SandboxState{
				Provider:  "hetzner",
				Size:      "cx32",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(72 * time.Hour) },
			want: 72 * 0.013,
		},
		{
			name: "hetzner cx42 1 hour",
			instance: &SandboxState{
				Provider:  "hetzner",
				Size:      "cx42",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(1 * time.Hour) },
			want: 1 * 0.025,
		},
		{
			name: "lightsail small_3_0 200 hours",
			instance: &SandboxState{
				Provider:  "lightsail",
				Size:      "small_3_0",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(200 * time.Hour) },
			want: 200 * 0.012,
		},
		{
			name: "lightsail medium_3_0 12 hours",
			instance: &SandboxState{
				Provider:  "lightsail",
				Size:      "medium_3_0",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(12 * time.Hour) },
			want: 12 * 0.024,
		},
		{
			name: "lightsail large_3_0 6 hours",
			instance: &SandboxState{
				Provider:  "lightsail",
				Size:      "large_3_0",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(6 * time.Hour) },
			want: 6 * 0.047,
		},
		{
			name: "unknown provider returns -1",
			instance: &SandboxState{
				Provider:  "aws",
				Size:      "t2.micro",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(10 * time.Hour) },
			want: -1,
		},
		{
			name: "unknown size returns -1",
			instance: &SandboxState{
				Provider:  "digitalocean",
				Size:      "s-unknown",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(10 * time.Hour) },
			want: -1,
		},
		{
			name: "daytona provider returns -1",
			instance: &SandboxState{
				Provider:  "daytona",
				Size:      "",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(10 * time.Hour) },
			want: -1,
		},
		{
			name: "empty size returns -1",
			instance: &SandboxState{
				Provider:  "hetzner",
				Size:      "",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(10 * time.Hour) },
			want: -1,
		},
		{
			name: "stopped sandbox still accrues cost",
			instance: &SandboxState{
				Provider:  "hetzner",
				Size:      "cx22",
				Status:    StatusStopped,
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime.Add(50 * time.Hour) },
			want: 50 * 0.007,
		},
		{
			name: "zero hours returns zero cost",
			instance: &SandboxState{
				Provider:  "digitalocean",
				Size:      "s-2vcpu-4gb",
				CreatedAt: baseTime,
			},
			now:  func() time.Time { return baseTime },
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EstimatedCost(tt.instance, tt.now)
			if tt.want == -1 {
				if got != -1 {
					t.Errorf("EstimatedCost() = %v, want -1", got)
				}
				return
			}
			if math.Abs(got-tt.want) > 0.0001 {
				t.Errorf("EstimatedCost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEstimatedCost_AllProvidersAndSizes(t *testing.T) {
	// Verify all expected provider/size combinations are present in hourlyRates.
	expected := map[string][]string{
		"digitalocean": {"s-1vcpu-2gb", "s-2vcpu-4gb", "s-4vcpu-8gb"},
		"hetzner":      {"cx22", "cx32", "cx42"},
		"lightsail":    {"small_3_0", "medium_3_0", "large_3_0"},
	}

	for provider, sizes := range expected {
		providerRates, ok := hourlyRates[provider]
		if !ok {
			t.Errorf("missing provider %q in hourlyRates", provider)
			continue
		}
		if len(providerRates) != len(sizes) {
			t.Errorf("provider %q has %d sizes, want %d", provider, len(providerRates), len(sizes))
		}
		for _, size := range sizes {
			rate, ok := providerRates[size]
			if !ok {
				t.Errorf("missing size %q for provider %q", size, provider)
				continue
			}
			if rate <= 0 {
				t.Errorf("rate for %s/%s must be positive, got %v", provider, size, rate)
			}
		}
	}

	if len(hourlyRates) != len(expected) {
		t.Errorf("hourlyRates has %d providers, want %d", len(hourlyRates), len(expected))
	}
}

func TestEstimatedCost_RatesArePositive(t *testing.T) {
	for provider, sizes := range hourlyRates {
		for size, rate := range sizes {
			if rate <= 0 {
				t.Errorf("rate for %s/%s must be positive, got %v", provider, size, rate)
			}
		}
	}
}
