//go:build !linux

package firecracker

func renderProductionLiveBootFiles(PathPlan, []byte) error {
	return newLiveBootRenderConfigError("stateDir", "production live boot rendering requires Linux")
}
