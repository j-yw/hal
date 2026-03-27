package sandbox

import "time"

// hourlyRates maps provider → size → hourly cost in USD.
var hourlyRates = map[string]map[string]float64{
	"digitalocean": {
		"s-1vcpu-2gb": 0.018,
		"s-2vcpu-4gb": 0.036,
		"s-4vcpu-8gb": 0.071,
	},
	"hetzner": {
		"cx22": 0.007,
		"cx32": 0.013,
		"cx42": 0.025,
	},
	"lightsail": {
		"small_3_0":  0.012,
		"medium_3_0": 0.024,
		"large_3_0":  0.047,
	},
}

// EstimatedCost returns the estimated cost in USD for a sandbox instance
// based on hours since creation multiplied by the hourly rate.
// Returns -1 if the provider or size is unknown.
// Cost always accrues from CreatedAt (stopped sandboxes still charge).
func EstimatedCost(instance *SandboxState, now func() time.Time) float64 {
	if instance == nil || instance.CreatedAt.IsZero() {
		return -1
	}
	providerRates, ok := hourlyRates[instance.Provider]
	if !ok {
		return -1
	}
	rate, ok := providerRates[instance.Size]
	if !ok {
		return -1
	}
	hours := now().Sub(instance.CreatedAt).Hours()
	if hours < 0 {
		return 0
	}
	return hours * rate
}
