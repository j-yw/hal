//go:build linux

package l7network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"golang.org/x/sys/unix"
)

const defaultNamespaceOutputLimit int64 = 256 << 10

type ProductionNamespaceResolverOptions struct {
	LifecycleRunner rootlesspodman.LifecycleCommandRunner
	PodmanPath      string
	NSenterPath     string
	IPPath          string
	InterfaceName   string
	MaxOutputBytes  int64
}

type ProductionNamespaceResolver struct {
	options ProductionNamespaceResolverOptions
}

func NewProductionNamespaceResolver(options ProductionNamespaceResolverOptions) (*ProductionNamespaceResolver, error) {
	if options.PodmanPath == "" {
		options.PodmanPath = rootlesspodman.DefaultPodmanExecutable
	}
	if options.MaxOutputBytes == 0 {
		options.MaxOutputBytes = defaultNamespaceOutputLimit
	}
	if options.LifecycleRunner == nil || !absoluteTool(options.PodmanPath) && options.PodmanPath != rootlesspodman.DefaultPodmanExecutable ||
		!absoluteTool(options.NSenterPath) || !absoluteTool(options.IPPath) || (options.InterfaceName != "" && !safeInterface(options.InterfaceName)) ||
		options.MaxOutputBytes <= 0 || options.MaxOutputBytes > defaultNamespaceOutputLimit {
		return nil, ErrInvalidConfiguration
	}
	return &ProductionNamespaceResolver{options: options}, nil
}

func (r *ProductionNamespaceResolver) Resolve(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) (NamespaceResolution, error) {
	if r == nil || r.options.LifecycleRunner == nil || request.Target.ID == "" || request.Target.ID != request.Target.Runtime.RuntimeID ||
		request.Target.Runtime.Driver != rootlesspodman.DriverID || !safeID(request.Target.ID) || !safeID(request.Target.Name) {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	before, err := r.inspect(ctx, request)
	if err != nil {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	user, network, err := openExactNamespace(before.pid)
	if err != nil {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = user.Close()
			_ = network.Close()
		}
	}()
	routeArgs := []string{"--json", "-6", "route", "show", "default"}
	if r.options.InterfaceName != "" {
		routeArgs = append(routeArgs, "dev", r.options.InterfaceName)
	}
	routePayload, err := r.runIP(ctx, user, network, routeArgs...)
	if err != nil {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	interfaceName, err := exactDefaultInterface(routePayload, r.options.InterfaceName)
	if err != nil {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	addressPayload, err := r.runIP(ctx, user, network, "--json", "address", "show", "dev", interfaceName)
	if err != nil {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	workload, gateway, prefix, err := parseExactIPv6Link(addressPayload, routePayload, interfaceName)
	if err != nil {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	after, err := r.inspect(ctx, request)
	if err != nil || !reflect.DeepEqual(before, after) || !namespaceStillExact(before.pid, user, network) {
		return NamespaceResolution{}, ErrNamespaceUnverified
	}
	closeOnError = false
	return NamespaceResolution{Namespace: linuxrules.NewNamespaceHandle(int(user.Fd()), int(network.Fd())),
		InterfaceName: interfaceName, WorkloadIPv6Address: workload, GatewayIPv6Address: gateway,
		IPv6PrefixBits: prefix, Close: &namespaceFiles{user: user, network: network}}, nil
}

type podmanNamespaceInspection struct {
	id, name  string
	pid       int
	startedAt string
	labels    map[string]string
}
type podmanInspectPayload struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Running   *bool  `json:"Running"`
		Status    string `json:"Status"`
		PID       *int   `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (r *ProductionNamespaceResolver) inspect(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) (podmanNamespaceInspection, error) {
	result, err := r.options.LifecycleRunner.RunLifecycleCommand(ctx, rootlesspodman.CommandRequest{Operation: rootlesspodman.OperationInspect,
		Args:           []string{r.options.PodmanPath, "inspect", "--type", "container", request.Target.Runtime.RuntimeID},
		MaxStdoutBytes: r.options.MaxOutputBytes, MaxStderrBytes: r.options.MaxOutputBytes})
	if err != nil || result.ExitCode != 0 || len(result.Stdout) == 0 || int64(len(result.Stdout)) > r.options.MaxOutputBytes {
		return podmanNamespaceInspection{}, ErrNamespaceUnverified
	}
	decoder := json.NewDecoder(strings.NewReader(result.Stdout))
	var payloads []podmanInspectPayload
	if decoder.Decode(&payloads) != nil || len(payloads) != 1 || decoder.Decode(new(any)) != io.EOF {
		return podmanNamespaceInspection{}, ErrNamespaceUnverified
	}
	p := payloads[0]
	if p.ID != request.Target.ID || p.Name != request.Target.Name || p.State.Running == nil || !*p.State.Running || p.State.Status != "running" ||
		p.State.PID == nil || *p.State.PID <= 1 || p.State.StartedAt == "" || !labelsMatch(p.Config.Labels, request) {
		return podmanNamespaceInspection{}, ErrNamespaceUnverified
	}
	return podmanNamespaceInspection{id: p.ID, name: p.Name, pid: *p.State.PID, startedAt: p.State.StartedAt, labels: cloneMap(p.Config.Labels)}, nil
}

func labelsMatch(labels map[string]string, request rootlesspodman.NetworkTopologyTargetRequest) bool {
	i := request.Identity
	expected := map[string]string{"dev.jywlabs.hal.runtime": rootlesspodman.DriverID, "dev.jywlabs.hal.sandbox.name": request.Target.Name,
		"dev.jywlabs.hal.topology.generation": i.TopologyGenerationID, "dev.jywlabs.hal.runtime.generation": i.RuntimeGenerationID,
		"dev.jywlabs.hal.network-rules.generation": i.RuleGenerationID}
	for k, v := range expected {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func openExactNamespace(pid int) (*os.File, *os.File, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid), "ns")
	user, err := os.Open(filepath.Join(base, "user"))
	if err != nil {
		return nil, nil, err
	}
	network, err := os.Open(filepath.Join(base, "net"))
	if err != nil {
		_ = user.Close()
		return nil, nil, err
	}
	return user, network, nil
}

func namespaceStillExact(pid int, user, network *os.File) bool {
	currentUser, currentNetwork, err := openExactNamespace(pid)
	if err != nil {
		return false
	}
	defer currentUser.Close()
	defer currentNetwork.Close()
	u1, e1 := user.Stat()
	u2, e2 := currentUser.Stat()
	n1, e3 := network.Stat()
	n2, e4 := currentNetwork.Stat()
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && os.SameFile(u1, u2) && os.SameFile(n1, n2)
}

func (r *ProductionNamespaceResolver) runIP(ctx context.Context, user, network *os.File, args ...string) ([]byte, error) {
	userCopy, err := dupFile(user, "l7-user")
	if err != nil {
		return nil, ErrNamespaceUnverified
	}
	defer userCopy.Close()
	networkCopy, err := dupFile(network, "l7-net")
	if err != nil {
		return nil, ErrNamespaceUnverified
	}
	defer networkCopy.Close()
	commandArgs := []string{"--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--preserve-credentials", "--", r.options.IPPath}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, r.options.NSenterPath, commandArgs...)
	command.ExtraFiles = []*os.File{userCopy, networkCopy}
	command.Env = []string{}
	stdout := &boundedBuffer{max: r.options.MaxOutputBytes}
	stderr := &boundedBuffer{max: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil || stdout.exceeded {
		return nil, ErrNamespaceUnverified
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

type ipAddressRecord struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen uint8  `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}
type ipRouteRecord struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

func exactDefaultInterface(routePayload []byte, configured string) (string, error) {
	var routes []ipRouteRecord
	if json.Unmarshal(routePayload, &routes) != nil || len(routes) != 1 || !safeInterface(routes[0].Dev) || (configured != "" && routes[0].Dev != configured) {
		return "", ErrNamespaceUnverified
	}
	return routes[0].Dev, nil
}

func parseExactIPv6Link(addressPayload, routePayload []byte, iface string) (string, string, uint8, error) {
	var addresses []ipAddressRecord
	var routes []ipRouteRecord
	if json.Unmarshal(addressPayload, &addresses) != nil || len(addresses) != 1 || addresses[0].IfName != iface || json.Unmarshal(routePayload, &routes) != nil || len(routes) != 1 || routes[0].Dev != iface || (routes[0].Dst != "default" && routes[0].Dst != "::/0") {
		return "", "", 0, ErrNamespaceUnverified
	}
	var workload netip.Addr
	var prefix uint8
	for _, info := range addresses[0].AddrInfo {
		if info.Family != "inet6" || info.Scope != "global" {
			continue
		}
		addr, err := netip.ParseAddr(info.Local)
		if err != nil || !addr.Is6() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || workload.IsValid() {
			return "", "", 0, ErrNamespaceUnverified
		}
		workload = addr
		prefix = info.PrefixLen
	}
	gateway, err := netip.ParseAddr(routes[0].Gateway)
	if err != nil || !workload.IsValid() || !gateway.Is6() || !gateway.IsLinkLocalUnicast() || prefix == 0 || prefix > 128 {
		return "", "", 0, ErrNamespaceUnverified
	}
	return workload.String(), gateway.String(), prefix, nil
}

type namespaceFiles struct {
	user, network *os.File
	once          sync.Once
	err           error
}

func (f *namespaceFiles) Close() error {
	if f == nil {
		return nil
	}
	f.once.Do(func() { f.err = errors.Join(f.user.Close(), f.network.Close()) })
	return f.err
}
func dupFile(file *os.File, name string) (*os.File, error) {
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	out := os.NewFile(uintptr(fd), name)
	if out == nil {
		_ = unix.Close(fd)
		return nil, ErrNamespaceUnverified
	}
	return out, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	max      int64
	exceeded bool
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if int64(w.buffer.Len()+len(p)) > w.max {
		w.exceeded = true
		remain := int(w.max) - w.buffer.Len()
		if remain > 0 {
			_, _ = w.buffer.Write(p[:remain])
		}
		return len(p), nil
	}
	return w.buffer.Write(p)
}
func absoluteTool(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func safeInterface(value string) bool {
	if value == "" || value == "lo" || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func cloneMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
