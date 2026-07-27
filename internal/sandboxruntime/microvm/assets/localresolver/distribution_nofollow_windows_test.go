//go:build windows

package localresolver

import "testing"

func TestL5WindowsDistributionResolutionFailsClosedWithoutSecurityProof(t *testing.T) {
	for name, operation := range map[string]func() error{
		"resolve": func() error {
			_, err := ResolveDistribution(DistributionRequest{RootDir: `C:\l5-distribution`})
			return err
		},
		"verify": func() error {
			_, err := VerifyDistributionBundle(DistributionRequest{RootDir: `C:\l5-distribution`})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("distribution operation succeeded without Windows owner and DACL proof")
			}
		})
	}
}
