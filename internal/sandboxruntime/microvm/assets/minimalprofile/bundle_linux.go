//go:build linux

package minimalprofile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"golang.org/x/sys/unix"
)

const BuilderImageDigest = "sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6"

// PublishRequest is a TRUSTED producer input, not candidate bundle metadata.
// Its staged tar, process pins, installed tree pin and source inventory must
// come from an independently authenticated offline build. This half does not
// generate that source build or infer its provenance from a tar's contents.
type PublishRequest struct {
	ParentDir, SourceDir, OutputDir string
	SourceRevision, SourceTree      string
	Epoch                           int64
	BuildImageDigest                string
	Archive, ArchiveSHA256          string
	Pins                            Pins
	Sources                         []assetbuild.L8LockedSource
}

// Receipt remains outside the exact seven-file bundle. The caller must retain
// it independently; deriving expected pins from candidate JSON defeats B1.
type Receipt struct {
	Expected                             localresolver.L8MinimalExpectedIdentity
	ArchiveSHA256, InstalledPiTreeSHA256 string
}

// Publish builds and inspects ext4, then uses the genuine L7 and B1 verifiers
// before atomic no-replace seven-file publication. No launch descriptor or
// strict readiness authority is issued to the caller.
func Publish(ctx context.Context, req PublishRequest) (receipt Receipt, retErr error) {
	phase := "request"
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("minimal bundle: %s rejected", phase)
		}
	}()
	if req.BuildImageDigest != BuilderImageDigest || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(req.SourceRevision) || !regexp.MustCompile(`^tree-[a-f0-9]{40}$`).MatchString(req.SourceTree) || !validPins(req.Pins) || req.Epoch <= 0 || req.Epoch > 2147483647 {
		return receipt, errImage
	}
	phase = "parent verification"
	parent, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{RootDir: req.ParentDir})
	if err != nil {
		return receipt, errImage
	}
	lease, err := parent.AcquireL7AssetLease()
	if err != nil {
		return receipt, errImage
	}
	defer func() {
		if err := lease.Close(); err != nil {
			retErr = errImage
		}
	}()
	parentFacts, err := measureParent(req.ParentDir)
	if err != nil {
		return receipt, errImage
	}
	runtime := assetbuild.L8RuntimeFacts{NodeVersion: "22.22.0", NodeSHA256: req.Pins.NodeSHA256, PiPackage: "@earendil-works/pi-coding-agent", PiVersion: "0.82.1", PiLauncherSHA256: req.Pins.PiLauncherSHA256, PiDependencyTreeSHA256: assetbuild.L8MinimalDependencyTreeSHA256(req.Sources)}
	sources := assetbuild.L8MinimalSourceLock{SchemaVersion: assetbuild.L8MinimalSourceLockSchemaV1, ImageProfile: assetbuild.ImageProfileL8MinimalCredentials, SourceRevision: req.SourceRevision, ParentL7: parentFacts, Runtime: runtime, Sources: append([]assetbuild.L8LockedSource(nil), req.Sources...)}
	phase = "source inventory"
	if err := assetbuild.ValidateL8SourceLock(assetbuild.L8SourceLock{SchemaVersion: assetbuild.L8SourceLockSchemaVersionV1, CatalogVersion: assetbuild.L8SourceLockCatalogVersionV1, ImageProfile: assetbuild.ImageProfileL8ProductionCredentials, ParentL7: parentFacts, Runtime: runtime, Sources: sources.Sources}); err != nil {
		return receipt, errImage
	}
	work, err := os.MkdirTemp("", "hal-minimal-sources-")
	if err != nil {
		return receipt, errImage
	}
	defer os.RemoveAll(work)
	for _, source := range sources.Sources {
		if err := ctx.Err(); err != nil {
			return receipt, errImage
		}
		snapshot := filepath.Join(work, "source")
		size, err := copyPinned(filepath.Join(req.SourceDir, source.Filename), snapshot, source.SHA256, source.SizeBytes)
		if err != nil || size != source.SizeBytes {
			return receipt, errImage
		}
		if os.Remove(snapshot) != nil {
			return receipt, errImage
		}
	}
	phase = "output directory"
	outputParent, err := openDirectory(filepath.Dir(req.OutputDir), true)
	if err != nil {
		return receipt, errImage
	}
	defer outputParent.Close()
	if !safeLeaf(filepath.Base(req.OutputDir)) {
		return receipt, errImage
	}
	if _, err := os.Lstat(req.OutputDir); !os.IsNotExist(err) {
		return receipt, errImage
	}
	stage, err := os.MkdirTemp(filepath.Dir(req.OutputDir), ".minimal-bundle-")
	if err != nil {
		return receipt, errImage
	}
	defer os.RemoveAll(stage)
	phase = "image production"
	measurement, err := BuildImage(ctx, ImageRequest{Archive: req.Archive, ArchiveSHA256: req.ArchiveSHA256, Output: filepath.Join(stage, "rootfs.ext4"), Epoch: req.Epoch, Pins: req.Pins})
	if err != nil {
		return receipt, errImage
	}
	if lease.ConfirmCurrent(&parent.Descriptor) != nil {
		return receipt, errImage
	}
	if _, err := copyPinned(filepath.Join(req.ParentDir, "vmlinux"), filepath.Join(stage, "vmlinux"), parentFacts.KernelSHA256, parentFacts.KernelSizeBytes); err != nil {
		return receipt, errImage
	}
	phase = "document construction"
	sourceDigest, err := writeDocument(stage, "sources.lock.json", sources)
	if err != nil {
		return receipt, errImage
	}
	inspection := assetbuild.L8MinimalFinalInspection{SchemaVersion: assetbuild.L8MinimalInspectionSchemaV1, ImageProfile: sources.ImageProfile, SourceRevision: req.SourceRevision, RootfsSHA256: measurement.RootfsSHA256, SourceLockSHA256: sourceDigest, ParentL7: parentFacts, Runtime: runtime, Executables: measurement.Executables, Inventory: measurement.Inventory, AgentUID: 1000, WorkloadUID: 1000, WorkspaceUID: 1000, WorkspaceMode: 0700}
	inspectionDigest, err := writeDocument(stage, "final-inspection.json", inspection)
	if err != nil {
		return receipt, errImage
	}
	facts := assetbuild.L8MinimalProfileFacts{ContractVersion: assetbuild.L8MinimalProfileContractV1, ParentL7: parentFacts, Runtime: runtime, GuestInitSHA256: req.Pins.GuestInitSHA256, GuestAgentSHA256: req.Pins.GuestAgentSHA256, SourceLockSHA256: sourceDigest, FinalInspectionSHA256: inspectionDigest}
	m := assetbuild.L8MinimalDistributionManifest{SchemaVersion: assetbuild.SchemaVersionV1, ImageProfile: sources.ImageProfile, Architecture: parent.Manifest.Architecture, Versions: parent.Manifest.Versions, GuestAgent: parent.Manifest.GuestAgent, GuestNetwork: parent.Manifest.GuestNetwork, MinimalProfile: facts, Assets: []assetbuild.DistributionAsset{{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: parentFacts.KernelSizeBytes, SHA256: parentFacts.KernelSHA256}, {Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: measurement.SizeBytes, SHA256: measurement.RootfsSHA256}}}
	p := assetbuild.L8MinimalProvenance{SchemaVersion: m.SchemaVersion, ImageProfile: m.ImageProfile, SourceRevision: req.SourceRevision, SourceTree: req.SourceTree, SourceDateEpoch: req.Epoch, BuildImageDigest: req.BuildImageDigest, Architecture: m.Architecture, Versions: m.Versions, GuestAgent: m.GuestAgent, GuestNetwork: m.GuestNetwork, MinimalProfile: facts}
	for _, a := range m.Assets {
		p.Outputs = append(p.Outputs, assetbuild.Output{Key: a.Key, ID: a.ID, Kind: a.Kind, SizeBytes: a.SizeBytes, SHA256: a.SHA256})
	}
	if assetbuild.ValidateL8MinimalDocuments(m, p, sources, inspection) != nil {
		return receipt, errImage
	}
	manifestDigest, err := writeDocument(stage, "distribution-manifest.json", m)
	if err != nil {
		return receipt, errImage
	}
	provenanceDigest, err := writeDocument(stage, "provenance.json", p)
	if err != nil {
		return receipt, errImage
	}
	digests := map[string]string{"distribution-manifest.json": manifestDigest, "final-inspection.json": inspectionDigest, "provenance.json": provenanceDigest, "rootfs.ext4": measurement.RootfsSHA256, "sources.lock.json": sourceDigest, "vmlinux": parentFacts.KernelSHA256}
	var checksums strings.Builder
	for _, name := range sortedKeys(digests) {
		fmt.Fprintf(&checksums, "%s  %s\n", digests[name], name)
	}
	if err := writeNewFile(filepath.Join(stage, "SHA256SUMS"), []byte(checksums.String())); err != nil {
		return receipt, errImage
	}
	receipt = Receipt{Expected: localresolver.L8MinimalExpectedIdentity{SourceRevision: req.SourceRevision, RootfsSHA256: measurement.RootfsSHA256, GuestInitSHA256: req.Pins.GuestInitSHA256, GuestAgentSHA256: req.Pins.GuestAgentSHA256, Runtime: runtime, SourceLockSHA256: sourceDigest, FinalInspectionSHA256: inspectionDigest, ProvenanceSHA256: provenanceDigest}, ArchiveSHA256: req.ArchiveSHA256, InstalledPiTreeSHA256: measurement.InstalledPiTreeSHA256}
	phase = "B1 verification"
	verified, err := localresolver.VerifyL8MinimalDistributionBundle(localresolver.L8MinimalDistributionRequest{DistributionRequest: localresolver.DistributionRequest{RootDir: stage}, ParentL7: parent, Expected: receipt.Expected})
	if err != nil {
		return Receipt{}, errImage
	}
	if err := verified.Close(); err != nil {
		return Receipt{}, errImage
	}
	if lease.ConfirmCurrent(&parent.Descriptor) != nil {
		return Receipt{}, errImage
	}
	stageFD, err := openDirectory(stage, true)
	if err != nil {
		return Receipt{}, errImage
	}
	defer stageFD.Close()
	if stageFD.Sync() != nil {
		return Receipt{}, errImage
	}
	phase = "publication"
	// Verify the named stage still denotes the retained directory at the
	// output parent before moving it; no overwrite or fallback rename exists.
	var named, retained unix.Stat_t
	if unix.Fstat(int(stageFD.Fd()), &retained) != nil || unix.Fstatat(int(outputParent.Fd()), filepath.Base(stage), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || retained.Ino != named.Ino || retained.Dev != named.Dev {
		return Receipt{}, errImage
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, errImage
	}
	if unix.Renameat2(int(outputParent.Fd()), filepath.Base(stage), int(outputParent.Fd()), filepath.Base(req.OutputDir), unix.RENAME_NOREPLACE) != nil {
		return Receipt{}, errImage
	}
	if outputParent.Sync() != nil {
		return Receipt{}, errImage
	}
	return receipt, nil
}

func writeDocument(root, name string, value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", errImage
	}
	data = append(data, '\n')
	if len(data) > 4<<20 {
		return "", errImage
	}
	if err := writeNewFile(filepath.Join(root, name), data); err != nil {
		return "", errImage
	}
	return digestBytes(data), nil
}
func writeNewFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errImage
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errImage
	}
	return nil
}

func measureParent(root string) (assetbuild.L8ParentL7Evidence, error) {
	parent := assetbuild.L8ParentL7Evidence{ImageProfile: assetbuild.ImageProfileL7Network}
	for _, entry := range []struct {
		name   string
		digest *string
		size   *int64
	}{{"distribution-manifest.json", &parent.ManifestSHA256, nil}, {"provenance.json", &parent.ProvenanceSHA256, nil}, {"SHA256SUMS", &parent.ChecksumsSHA256, nil}, {"vmlinux", &parent.KernelSHA256, &parent.KernelSizeBytes}, {"rootfs.ext4", &parent.RootfsSHA256, &parent.RootfsSizeBytes}} {
		dir, err := openDirectory(root, false)
		if err != nil {
			return parent, errImage
		}
		fd, err := unix.Openat(int(dir.Fd()), entry.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		dir.Close()
		if err != nil {
			return parent, errImage
		}
		f := os.NewFile(uintptr(fd), entry.name)
		limit := int64(4 << 20)
		if entry.size != nil {
			limit = 1 << 30
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
			f.Close()
			return parent, errImage
		}
		h := sha256.New()
		n, readErr := io.Copy(h, io.LimitReader(f, limit+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || n != info.Size() {
			return parent, errImage
		}
		*entry.digest = hex.EncodeToString(h.Sum(nil))
		if entry.size != nil {
			*entry.size = n
		}
	}
	h := sha256.New()
	for _, token := range []string{"hal/l8/image-profile/parent-l7-evidence/v1", assetbuild.ImageProfileL7Network} {
		_ = binary.Write(h, binary.BigEndian, uint16(len(token)))
		_, _ = h.Write([]byte(token))
	}
	for _, d := range []string{parent.ManifestSHA256, parent.ProvenanceSHA256, parent.ChecksumsSHA256} {
		raw, _ := hex.DecodeString(d)
		_, _ = h.Write(raw)
	}
	_ = binary.Write(h, binary.BigEndian, uint64(parent.KernelSizeBytes))
	raw, _ := hex.DecodeString(parent.KernelSHA256)
	_, _ = h.Write(raw)
	_ = binary.Write(h, binary.BigEndian, uint64(parent.RootfsSizeBytes))
	raw, _ = hex.DecodeString(parent.RootfsSHA256)
	_, _ = h.Write(raw)
	parent.EvidenceSHA256 = hex.EncodeToString(h.Sum(nil))
	return parent, nil
}
