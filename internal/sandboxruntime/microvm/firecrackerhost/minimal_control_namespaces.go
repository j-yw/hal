package firecrackerhost

// Only actual eight-role admission captures this scalar snapshot. It binds
// received handles to sealed producer input, not to a current L7 owner.
type minimalControlNamespaceProjection struct {
	configCorrelation string
	namespaces        minimalControlNamespaces
}

func (projection minimalControlNamespaceProjection) valid() bool {
	ns := projection.namespaces
	return validJailerStagingDigest(projection.configCorrelation) &&
		ns.UserDevice != 0 && ns.UserInode != 0 && ns.NetworkDevice != 0 && ns.NetworkInode != 0 &&
		(ns.UserDevice != ns.NetworkDevice || ns.UserInode != ns.NetworkInode)
}
