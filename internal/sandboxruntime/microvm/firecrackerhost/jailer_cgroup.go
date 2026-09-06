package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errJailerCgroup = errors.New("strict Jailer cgroup authority unavailable")

// Preserve the stager's explicit terminal-close warning without turning an
// unclassified root-removal failure into absence. This only examines private
// staging errors; unknown wrappers or excessive nesting remain quarantined.
func jailerCgroupOnlyTerminalStagingClose(err error, depth int) bool {
	if depth > 16 {
		return false
	}
	if !errors.Is(err, errJailerStagingCleanupIncomplete) {
		return true
	}
	if staged, ok := err.(*jailerStagingError); ok {
		return staged.code == "root_close"
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !jailerCgroupOnlyTerminalStagingClose(child, depth+1) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return jailerCgroupOnlyTerminalStagingClose(wrapped.Unwrap(), depth+1)
	}
	return false
}

type strictJailerCgroupResources struct {
	anchor                      string
	cpuQuota, cpuPeriod         uint64
	memoryMax, swapMax, pidsMax uint64
}

type strictJailerCgroupRequest struct {
	resources               strictJailerCgroupResources
	runtimeID, configSHA256 string
	guestMemoryMiB          uint64
}

// The filesystem owns its partial creation even when create fails. No method
// may select a replacement by pathname or enable an ancestor controller.
type strictJailerCgroupFilesystem interface {
	create(string) error
	created() bool
	verify() error
	read(string) (string, error)
	write(string, string) error
	duplicate() (*os.File, error)
	remove() error
	close() error
}

type strictJailerCgroupLease struct {
	mu                                     sync.Mutex
	request                                strictJailerCgroupRequest
	fs                                     strictJailerCgroupFilesystem
	prepared, launched, quiesced, released bool
}

func strictJailerCoordinatorCgroupRequest(request strictJailerCoordinatorRequest) (strictJailerCgroupRequest, error) {
	if request.cgroup == nil {
		return strictJailerCgroupRequest{}, errJailerCgroup
	}
	config, err := readStrictJailerConfig(request.config)
	if err != nil || config.MachineConfig.MemSizeMiB <= 0 {
		return strictJailerCgroupRequest{}, errJailerCgroup
	}
	result := strictJailerCgroupRequest{resources: *request.cgroup, runtimeID: request.runtimeID, configSHA256: request.config.SHA256, guestMemoryMiB: uint64(config.MachineConfig.MemSizeMiB)}
	return result, validateJailerCgroupRequest(result, uint64(os.Getpagesize()))
}

func validateJailerCgroupRequest(request strictJailerCgroupRequest, pageSize uint64) error {
	r := request.resources
	if !filepath.IsAbs(r.anchor) || filepath.Clean(r.anchor) != r.anchor || r.anchor == "/" || strings.TrimSpace(r.anchor) != r.anchor ||
		!validStrictJailerRuntimeID(request.runtimeID) || !validJailerStagingDigest(request.configSHA256) ||
		r.cpuPeriod < 1000 || r.cpuPeriod > 1000000 || r.cpuQuota < 1000 || r.cpuQuota > 1024*r.cpuPeriod ||
		r.memoryMax < 1<<20 || r.memoryMax > 1<<40 || r.swapMax > 1<<40 || r.pidsMax == 0 || r.pidsMax > 1<<20 ||
		pageSize == 0 || r.memoryMax%pageSize != 0 || r.swapMax%pageSize != 0 ||
		request.guestMemoryMiB == 0 || request.guestMemoryMiB > 1<<20 || r.memoryMax < request.guestMemoryMiB<<20 {
		return errJailerCgroup
	}
	return nil
}

func (request strictJailerCgroupRequest) limits() [][2]string {
	r := request.resources
	return [][2]string{
		{"cpu.max", strconv.FormatUint(r.cpuQuota, 10) + " " + strconv.FormatUint(r.cpuPeriod, 10) + "\n"},
		{"memory.max", strconv.FormatUint(r.memoryMax, 10) + "\n"},
		{"memory.swap.max", strconv.FormatUint(r.swapMax, 10) + "\n"},
		{"pids.max", strconv.FormatUint(r.pidsMax, 10) + "\n"},
	}
}

func prepareStrictJailerCgroup(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
	return prepareStrictJailerCgroupWithFilesystem(ctx, request, uint64(os.Getpagesize()), newLinuxJailerCgroupFilesystem)
}

func prepareStrictJailerCgroupWithFilesystem(ctx context.Context, request strictJailerCgroupRequest, pageSize uint64, open func(string) (strictJailerCgroupFilesystem, error)) (*strictJailerCgroupLease, error) {
	ctx = nonNilContext(ctx)
	if ctx.Err() != nil || validateJailerCgroupRequest(request, pageSize) != nil || open == nil {
		return nil, errJailerCgroup
	}
	fs, err := open(request.resources.anchor)
	if interfaceValueIsNil(fs) {
		return nil, errJailerCgroup
	}
	lease := &strictJailerCgroupLease{request: request, fs: fs}
	if err != nil || ctx.Err() != nil {
		return lease, errJailerCgroup
	}
	if err := fs.create(request.runtimeID); err != nil {
		return lease, errJailerCgroup
	}
	for _, limit := range request.limits() {
		if ctx.Err() != nil || fs.verify() != nil || ctx.Err() != nil || fs.write(limit[0], limit[1]) != nil {
			return lease, errJailerCgroup
		}
	}
	if lease.verifyLimitsLocked() != nil || ctx.Err() != nil {
		return lease, errJailerCgroup
	}
	lease.prepared = true
	return lease, nil
}

func (lease *strictJailerCgroupLease) verifyLimitsLocked() error {
	if lease.fs.verify() != nil {
		return errJailerCgroup
	}
	for _, limit := range lease.request.limits() {
		value, err := lease.fs.read(limit[0])
		if err != nil || value != limit[1] {
			return errJailerCgroup
		}
	}
	return nil
}

func (lease *strictJailerCgroupLease) matches(runtimeID, digest string) bool {
	if lease == nil {
		return false
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.prepared && !lease.quiesced && !lease.released && lease.request.runtimeID == runtimeID && lease.request.configSHA256 == digest
}

func (lease *strictJailerCgroupLease) verifyForLaunch() error {
	if lease == nil {
		return errJailerCgroup
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.prepared || lease.launched || lease.quiesced || lease.released {
		return errJailerCgroup
	}
	return lease.verifyLimitsLocked()
}

// The callback receives one CLOEXEC duplicate for clone3, not an inherited
// file. Cleanup waits for the callback and every duplicate is closed locally.
func (lease *strictJailerCgroupLease) withLaunchFD(ctx context.Context, runtimeID string, use func(*os.File) error) (resultErr error) {
	if lease == nil || use == nil {
		return errJailerCgroup
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	ctx = nonNilContext(ctx)
	if ctx.Err() != nil || !lease.prepared || lease.launched || lease.quiesced || lease.released || lease.request.runtimeID != runtimeID || lease.verifyLimitsLocked() != nil {
		return errJailerCgroup
	}
	fd, err := lease.fs.duplicate()
	if err != nil || fd == nil {
		if fd != nil {
			_ = fd.Close()
		}
		return errJailerCgroup
	}
	defer func() {
		if fd.Close() != nil {
			resultErr = errors.Join(resultErr, errJailerCgroup)
		}
	}()
	if ctx.Err() != nil || lease.fs.verify() != nil {
		return errJailerCgroup
	}
	lease.launched = true
	err = use(fd)
	if ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	return err
}

func jailerCgroupEmpty(payload string) (bool, error) {
	if len(payload) > 4096 || !strings.HasSuffix(payload, "\n") {
		return false, errJailerCgroup
	}
	seen := map[string]bool{}
	empty := false
	for _, line := range strings.Split(strings.TrimSuffix(payload, "\n"), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || seen[parts[0]] || (parts[1] != "0" && parts[1] != "1") || (parts[0] != "populated" && parts[0] != "frozen") {
			return false, errJailerCgroup
		}
		seen[parts[0]] = true
		if parts[0] == "populated" {
			empty = parts[1] == "0"
		}
	}
	if !seen["populated"] {
		return false, errJailerCgroup
	}
	return empty, nil
}

func jailerCgroupControllersEnabled(payload string) bool {
	if len(payload) > 4096 || !strings.HasSuffix(payload, "\n") {
		return false
	}
	enabled := map[string]bool{}
	for _, name := range strings.Fields(payload) {
		if enabled[name] {
			return false
		}
		enabled[name] = true
	}
	return enabled["cpu"] && enabled["memory"] && enabled["pids"]
}

func (lease *strictJailerCgroupLease) quiesce(ctx context.Context) error {
	if lease == nil {
		return errJailerCgroup
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return nil
	}
	if !lease.fs.created() {
		lease.quiesced = true
		return nil
	}
	ctx, cancel := context.WithTimeout(nonNilContext(ctx), 2*time.Second)
	defer cancel()
	if ctx.Err() != nil || lease.fs.verify() != nil || lease.fs.write("cgroup.kill", "1\n") != nil {
		return errJailerCgroup
	}
	for {
		if ctx.Err() != nil || lease.fs.verify() != nil {
			return errJailerCgroup
		}
		value, err := lease.fs.read("cgroup.events")
		empty, parseErr := jailerCgroupEmpty(value)
		if err != nil || parseErr != nil {
			return errJailerCgroup
		}
		if empty {
			lease.quiesced = true
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errJailerCgroup
		case <-timer.C:
		}
	}
}

func (lease *strictJailerCgroupLease) release() error {
	if lease == nil {
		return errJailerCgroup
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return nil
	}
	if !lease.quiesced {
		return errJailerCgroup
	}
	if lease.fs.created() {
		if lease.fs.verify() != nil {
			return errJailerCgroup
		}
		value, err := lease.fs.read("cgroup.events")
		empty, parseErr := jailerCgroupEmpty(value)
		if err != nil || parseErr != nil || !empty || lease.fs.remove() != nil {
			return errJailerCgroup
		}
	}
	if lease.fs.close() != nil {
		return errJailerCgroup
	}
	lease.released = true
	return nil
}
